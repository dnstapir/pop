/*
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package main

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/viper"

	"github.com/dnstapir/tapir"
)

type RpzRefresh struct {
	Name     string
	Upstream string
	//	RRKeepFunc  func(uint16) bool
	RRParseFunc func(*dns.RR, *tapir.ZoneData) bool
	ZoneType    tapir.ZoneType // 1=xfr, 2=map, 3=slice
	Resp        chan RpzRefreshResult
}

type RpzRefreshResult struct {
	Msg      string
	Error    bool
	ErrorMsg string
}

type RefreshCounter struct {
	Name           string
	SOARefresh     uint32
	CurRefresh     uint32
	IncomingSerial uint32
	//	RRKeepFunc     func(uint16) bool
	RRParseFunc func(*dns.RR, *tapir.ZoneData) bool
	Upstream    string
	Downstreams []string
}

func (td *TemData) RefreshEngine(conf *Config, stopch chan struct{}) {

	var TapirIntelCh = td.TapirMqttSubCh

	var zonerefch = td.RpzRefreshCh
	var rpzcmdch = td.RpzCommandCh

	var refreshCounters = make(map[string]*RefreshCounter, 5)
	refreshTicker := time.NewTicker(1 * time.Second)

	reaperStart := time.Now().Truncate(td.ReaperInterval).Add(td.ReaperInterval)
	reaperTicker := time.NewTicker(td.ReaperInterval)

	go func() {
		time.Sleep(reaperStart.Sub(time.Now()))
		reaperTicker.Reset(td.ReaperInterval)
	}()

	if !viper.GetBool("service.refresh.active") {
		log.Printf("Refresh Engine is NOT active. Zones will only be updated on receipt on Notifies.")
		for {
			select {
			case <-zonerefch: // ensure that we keep reading to keep the
				continue // channel open
			}
		}
	} else {
		log.Printf("RefreshEngine: Starting")
	}

	var upstream, zone string
	var downstreams []string
	var refresh uint32
	//	var keepfunc func(uint16) bool
	var parsefunc func(*dns.RR, *tapir.ZoneData) bool
	var rc *RefreshCounter
	var updated bool
	var err error
	var cmd RpzCmdData
	var tpkg tapir.MqttPkg
	var zr RpzRefresh

	resetSoaSerial := viper.GetBool("service.reset_soa_serial")

	for {
		select {
		case tpkg = <-TapirIntelCh:
			switch tpkg.Data.MsgType {
			case "intel-update", "observation":
				log.Printf("RefreshEngine: Tapir Observation update: (src: %s) %d additions and %d removals\n",
					tpkg.Data.SrcName, len(tpkg.Data.Added), len(tpkg.Data.Removed))
				td.ProcessTapirUpdate(tpkg)
				log.Printf("RefreshEngine: Tapir Observation update evaluated.")

			case "global-config":
				td.ProcessTapirGlobalConfig(tpkg.Data)
				log.Printf("RefreshEngine: Tapir Global Config evaluated.")

			default:
				log.Printf("RefreshEngine: Tapir IntelUpdate: unknown msg type: %s", tpkg.Data.MsgType)
			}

		case zr = <-zonerefch:
			zone = zr.Name
			log.Printf("RefreshEngine: Requested to refresh zone \"%s\"", zone)
			if zone != "" {
				if zonedata, exist := td.RpzSources[zone]; exist {
					log.Printf("RefreshEngine: scheduling immediate refresh for known zone '%s'",
						zone)
					if _, known := refreshCounters[zone]; !known {
						refresh = zonedata.SOA.Refresh

						upstream = zr.Upstream
						if upstream == "" && zr.Resp != nil {
							log.Printf("RefreshEngine: %s: Upstream unspecified", zone)
							zr.Resp <- RpzRefreshResult{Error: true, ErrorMsg: "Upstream unspecified"}
						}

						parsefunc = zr.RRParseFunc
						if parsefunc == nil && zr.Resp != nil {
							log.Printf("RefreshEngine: %s: ParseFunc unspecified", zone)
							zr.Resp <- RpzRefreshResult{Error: true, ErrorMsg: "ParseFunc unspecified"}
						}

						refreshCounters[zone] = &RefreshCounter{
							Name:       zone,
							SOARefresh: refresh,
							CurRefresh: 1, // force immediate refresh
							//							RRKeepFunc:  keepfunc,
							RRParseFunc: parsefunc,
							Upstream:    upstream,
							Downstreams: downstreams,
						}
					} else {
						rc = refreshCounters[zone]
					}
					updated, err = td.RpzSources[zone].Refresh(rc.Upstream)
					if err != nil {
						log.Printf("RefreshEngine: Error from zone refresh(%s): %v", zone, err)
					}

					if updated {
						if resetSoaSerial {
							td.RpzSources[zone].SOA.Serial = uint32(time.Now().Unix())
							log.Printf("RefreshEngine: %s updated from upstream. Resetting serial to unixtime: %d",
								zone, td.RpzSources[zone].SOA.Serial)
						}
						td.NotifyDownstreams()
					}
					// showing some apex details:
					log.Printf("Showing some details for zone %s: ", zone)
					log.Printf("%s SOA: %s", zone, td.RpzSources[zone].SOA.String())
					zr.Resp <- RpzRefreshResult{Msg: "all ok"}
				} else {
					log.Printf("RefreshEngine: adding the new zone '%s'", zone)

					upstream = zr.Upstream
					if upstream == "" {
						log.Printf("RefreshEngine: %s: Upstream unspecified", zone)
						zr.Resp <- RpzRefreshResult{Error: true, ErrorMsg: "Upstream unspecified"}
						continue
					}

					parsefunc = zr.RRParseFunc
					if parsefunc == nil {
						log.Printf("RefreshEngine: %s: RRParseFunc unspecified", zone)
						zr.Resp <- RpzRefreshResult{Error: true, ErrorMsg: "RRParseFunc unspecified"}
						continue
					}

					zonedata = &tapir.ZoneData{
						ZoneName: zone,
						ZoneType: zr.ZoneType,
						//						RRKeepFunc:  keepfunc,
						RRParseFunc: parsefunc,
						//						RpzData:     map[string]string{}, // must be initialized
						Logger: log.Default(),
					}
					// log.Printf("RefEng: New zone %s, keepfunc: %v", zone, keepfunc)
					updated, err := zonedata.Refresh(upstream)
					if err != nil {
						log.Printf("RefreshEngine: Error from zone refresh(%s): %v", zone, err)
						zr.Resp <- RpzRefreshResult{Error: true, ErrorMsg: err.Error()}
						continue
					}

					refresh = zonedata.SOA.Refresh
					// Is there a max refresh counter configured, then use it.
					maxrefresh := uint32(viper.GetInt("service.maxrefresh"))
					if maxrefresh != 0 && maxrefresh < refresh {
						refresh = maxrefresh
					}
					refreshCounters[zone] = &RefreshCounter{
						Name:       zone,
						SOARefresh: refresh,
						CurRefresh: refresh,
						//						RRKeepFunc:  keepfunc,
						RRParseFunc: parsefunc,
						Upstream:    upstream,
						Downstreams: downstreams,
					}

					if updated {
						if resetSoaSerial {
							zonedata.SOA.Serial = uint32(time.Now().Unix())
							log.Printf("RefreshEngine: %s updated from upstream. Resetting serial to unixtime: %d",
								zone, zonedata.SOA.Serial)
						}
						// NotifyDownstreams(zonedata, downstreams)

					}
					td.mu.Lock()
					td.RpzSources[zone] = zonedata
					td.mu.Unlock()
					// XXX: as parsing is done inline to the zone xfr, we don't need to inform
					// the caller (I hope). I think we do.
					zr.Resp <- RpzRefreshResult{Msg: "all ok"}
				}
			}

		case <-refreshTicker.C:
			TapirIntelCh = td.TapirMqttSubCh // stupid kludge
			// log.Printf("RefEng: ticker. refCounters: %v", refreshCounters)
			for zone, rc := range refreshCounters {
				// log.Printf("RefEng: ticker for %s: curref: %d", zone, v.CurRefresh)
				rc.CurRefresh--
				if rc.CurRefresh <= 0 {
					upstream = rc.Upstream
					//					if rc.RRKeepFunc == nil {
					//						panic("RefreshEngine: keepfunc=nil")
					//					}
					if rc.RRParseFunc == nil {
						panic("RefreshEngine: parsefunc=nil")
					}

					log.Printf("RefreshEngine: will refresh zone %s due to refresh counter", zone)
					// log.Printf("Len(RpzZones) = %d", len(RpzZones))
					updated, err := td.RpzSources[zone].Refresh(upstream)
					rc.CurRefresh = rc.SOARefresh
					if err != nil {
						log.Printf("RefreshEngine: Error from zd.Refresh(%s): %v", zone, err)
					}
					if updated {
						if resetSoaSerial {
							td.RpzSources[zone].SOA.Serial = uint32(time.Now().Unix())
							log.Printf("RefreshEngine: %s updated from upstream. Resetting serial to unixtime: %d",
								zone, td.RpzSources[zone].SOA.Serial)

						}
					}
					if updated {
						td.NotifyDownstreams()
					}
				}
			}

		case <-reaperTicker.C:
			err := td.Reaper(false)
			if err != nil {
				log.Printf("Reaper: error: %v", err)
			}

		case cmd = <-rpzcmdch:
			command := cmd.Command
			log.Printf("RefreshEngine: recieved an %s command on the RpzCmd channel", command)
			resp := RpzCmdResponse{
				Zone: zone,
			}
			switch command {
			case "BUMP":
				zone = cmd.Zone
				if zone != "" {
					if zd, exist := td.RpzSources[zone]; exist {
						log.Printf("RefreshEngine: bumping SOA serial for known zone '%s'",
							zone)
						resp.OldSerial = zd.SOA.Serial
						zd.SOA.Serial = uint32(time.Now().Unix())
						resp.NewSerial = zd.SOA.Serial
						rc = refreshCounters[zone]
						td.NotifyDownstreams()
						resp.Msg = fmt.Sprintf("Zone %s: bumped serial from %d to %d. Notified downstreams: %v",
							zone, resp.OldSerial, resp.NewSerial, rc.Downstreams)
						log.Printf(resp.Msg)
						resp.Status = true
					} else {
						resp.Error = true
						resp.ErrorMsg = fmt.Sprintf("Request to bump serial for unknown zone '%s'", zone)
						log.Printf(resp.ErrorMsg)
					}
				}
				cmd.Result <- resp

			case "RPZ-ADD":
				log.Printf("RefreshEngine: recieved an RPZ ADD command: %s (policy %s)", cmd.Domain, cmd.Policy)
				if td.Whitelisted(cmd.Domain) {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("Domain name \"%s\" is whitelisted. No change.",
						cmd.Domain)
					cmd.Result <- resp
					continue
				}

				if td.Blacklisted(cmd.Domain) {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("Domain name \"%s\" is already blacklisted. No change.",
						cmd.Domain)

					cmd.Result <- resp
					continue
				}

				// if the name isn't either whitelisted or blacklisted
				if cmd.ListType == "greylist" {
					td.GreylistAdd(cmd.Domain, cmd.Policy, cmd.RpzSource)
					resp.Msg = fmt.Sprintf("Domain name \"%s\" (policy %s) added to greylisting DB.",
						cmd.Domain, cmd.Policy)
					cmd.Result <- resp
					continue
				}
				log.Printf("rf: RPZ-ADD 3")

			case "RPZ-REMOVE":
				log.Printf("RefreshEngine: recieved an RPZ REMOVE command: %s", cmd.Domain)
				resp.Msg = "RPZ-REMOVE NYI"
				cmd.Result <- resp

			case "RPZ-LOOKUP":
				log.Printf("RefreshEngine: recieved an RPZ LOOKUP command: %s", cmd.Domain)
				var msg string
				if td.Whitelisted(cmd.Domain) {
					resp.Msg = fmt.Sprintf("Domain name \"%s\" is whitelisted.", cmd.Domain)
					cmd.Result <- resp
					continue
				}
				msg += fmt.Sprintf("Domain name \"%s\" is not whitelisted.\n", cmd.Domain)

				if td.Blacklisted(cmd.Domain) {
					resp.Msg = fmt.Sprintf("Domain name \"%s\" is blacklisted.", cmd.Domain)
					cmd.Result <- resp
					continue
				}
				msg += fmt.Sprintf("Domain name \"%s\" is not blacklisted.\n", cmd.Domain)

				// if the name isn't either whitelisted or blacklisted: go though all greylists
				_, greymsg := td.GreylistingReport(cmd.Domain)
				resp.Msg = msg + greymsg
				cmd.Result <- resp
				continue

			case "RPZ-LIST-SOURCES":
				log.Printf("RefreshEngine: recieved an RPZ LIST-SOURCES command")
				list := []string{}
				//				for _, wl := range td.Whitelists {
				for _, wl := range td.Lists["whitelist"] {
					list = append(list, wl.Name)
				}
				resp.Msg += fmt.Sprintf("Whitelist srcs: %s\n", strings.Join(list, ", "))

				list = []string{}
				//				for _, bl := range td.Blacklists {
				for _, bl := range td.Lists["blacklist"] {
					list = append(list, bl.Name)
				}
				resp.Msg += fmt.Sprintf("Blacklist srcs: %s\n", strings.Join(list, ", "))

				list = []string{}
				//				for _, gl := range td.Greylists {
				for _, gl := range td.Lists["greylist"] {
					list = append(list, gl.Name)
				}
				resp.Msg += fmt.Sprintf("Greylist srcs: %s\n", strings.Join(list, ", "))
				cmd.Result <- resp

			default:
				td.Logger.Printf("RefreshEngine: unknown command: \"%s\". Ignored.", command)
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("RefreshEngine: unknown command: \"%s\". Ignored.",
					command)
				cmd.Result <- resp
			}
		}
	}
}

func (td *TemData) NotifyDownstreams() error {
	td.Logger.Printf("RefreshEngine: Notifying %d downstreams for RPZ zone %s", len(td.Downstreams), td.Rpz.ZoneName)
	for _, d := range td.Downstreams {
		m := new(dns.Msg)
		m.SetNotify(td.Rpz.ZoneName)
		td.Rpz.Axfr.SOA.Serial = td.Rpz.CurrentSerial
		m.Ns = append(m.Ns, dns.RR(&td.Rpz.Axfr.SOA))
		dest := net.JoinHostPort(d.Address, strconv.Itoa(d.Port))
		td.Logger.Printf("RefreshEngine: Notifying downstream %s about new SOA serial (%d) for RPZ zone %s", dest, td.Rpz.Axfr.SOA.Serial, td.Rpz.ZoneName)
		r, err := dns.Exchange(m, dest)
		if err != nil {
			// well, we tried
			td.Logger.Printf("Error from downstream %s on Notify(%s): %v", dest, td.Rpz.ZoneName, err)
			continue
		}
		if r.Opcode != dns.OpcodeNotify {
			// well, we tried
			td.Logger.Printf("Error: not a NOTIFY QR from downstream %s on Notify(%s): %s",
				dest, td.Rpz.ZoneName, dns.OpcodeToString[r.Opcode])
		} else {
			td.Logger.Printf("RefreshEngine: Downstream %s responded correctly to Notify(%s) about new SOA serial (%d)", dest, td.Rpz.ZoneName, td.Rpz.Axfr.SOA.Serial)
		}
	}
	return nil
}
