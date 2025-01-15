/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package main

import (
	"encoding/json"
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

func (pd *PopData) RefreshEngine(conf *Config, stopch chan struct{}) {

	var ObservationsCh = pd.TapirObservations

	var zonerefch = pd.RpzRefreshCh
	var rpzcmdch = pd.RpzCommandCh

	var refreshCounters = make(map[string]*RefreshCounter, 5)
	refreshTicker := time.NewTicker(1 * time.Second)

	reaperStart := time.Now().Truncate(pd.ReaperInterval).Add(pd.ReaperInterval)
	reaperTicker := time.NewTicker(pd.ReaperInterval)

	go func() {
		time.Sleep(time.Until(reaperStart))
		reaperTicker.Reset(pd.ReaperInterval)
	}()

	if !viper.GetBool("services.refreshengine.active") {
		log.Printf("Refresh Engine is NOT active. Zones will only be updated on receipt on Notifies.")
		for range zonerefch {
			// ensure that we keep reading to keep the channel open
			continue
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
	var tpkg tapir.MqttPkgIn
	var zr RpzRefresh

	resetSoaSerial := viper.GetBool("service.reset_soa_serial")

	for {
		select {
		case tpkg = <-ObservationsCh:
			tm := tapir.TapirMsg{}
			err := json.Unmarshal(tpkg.Payload, &tm)
			if err != nil {
				log.Printf("RefreshEngine: Error unmarshalling TapirMsg: %v", err)
				continue
			}
			switch tm.MsgType {
			case "observation", "intel-update":
				log.Printf("RefreshEngine: Tapir Observation update: (src: %s) %d additions and %d removals\n",
					tm.SrcName, len(tm.Added), len(tm.Removed))
				_, err := pd.ProcessTapirUpdate(tm)
				if err != nil {
					Gconfig.Internal.ComponentStatusCh <- tapir.ComponentStatusUpdate{
						Status:    tapir.StatusFail,
						Component: "tapir-observation",
						Msg:       fmt.Sprintf("ProcessTapirUpdate error: %v", err),
					}
					log.Printf("RefreshEngine: Error from ProcessTapirUpdate(): %v", err)
				}
				Gconfig.Internal.ComponentStatusCh <- tapir.ComponentStatusUpdate{
					Status:    tapir.StatusOK,
					Component: "tapir-observation",
					Msg:       fmt.Sprintf("ProcessTapirUpdate: MQTT observation message received"),
				}
				log.Printf("RefreshEngine: Tapir Observation update evaluated.")

				//			case "global-config":
				//				if !strings.HasSuffix(tpkg.Topic, "config") {
				//					log.Printf("RefreshEngine: received global-config message on wrong topic: %s. Ignored", tpkg.Topic)
				//					Gconfig.Internal.ComponentStatusCh <- tapir.ComponentStatusUpdate{
				//						Status:    "fail",
				//						Component: "mqtt-config",
				//						Msg:       fmt.Sprintf("RefreshEngine: received global-config message on wrong topic: %s. Ignored", tpkg.Topic),
				//					}
				//					continue
				//				}
				//				pd.ProcessTapirGlobalConfig(tm)
				//				log.Printf("RefreshEngine: Tapir Global Config evaluated.")
				//				Gconfig.Internal.ComponentStatusCh <- tapir.ComponentStatusUpdate{
				//					Status:    "ok",
				//					Component: "mqtt-config",
				//					Msg:       fmt.Sprintf("RefreshEngine: Tapir Global Config evaluated."),
				//				}

			default:
				log.Printf("RefreshEngine: Tapir Message: unknown msg type: %s", tm.MsgType)
				Gconfig.Internal.ComponentStatusCh <- tapir.ComponentStatusUpdate{
					Status:    tapir.StatusFail,
					Component: "mqtt-unknown",
					Msg:       fmt.Sprintf("RefreshEngine: Tapir Message: unknown msg type: %s", tm.MsgType),
				}
			}
			// log.Printf("RefreshEngine: Tapir IntelUpdate: %v", tpkg.Data)

		case zr = <-zonerefch:
			zone = zr.Name
			log.Printf("RefreshEngine: Requested to refresh zone \"%s\"", zone)
			if zone != "" {
				if zonedata, exist := pd.RpzSources[zone]; exist {
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
					updated, err = pd.RpzSources[zone].Refresh(rc.Upstream)
					if err != nil {
						log.Printf("RefreshEngine: Error from zone refresh(%s): %v", zone, err)
					}

					if updated {
						if resetSoaSerial {
							pd.RpzSources[zone].SOA.Serial = uint32(time.Now().Unix())
							log.Printf("RefreshEngine: %s updated from upstream. Resetting serial to unixtime: %d",
								zone, pd.RpzSources[zone].SOA.Serial)
						}
						err := pd.NotifyDownstreams()
						if err != nil {
							log.Printf("RefreshEngine: Error notifying downstreams: %v", err)
						}
					}
					// showing some apex details:
					log.Printf("Showing some details for zone %s: ", zone)
					log.Printf("%s SOA: %s", zone, pd.RpzSources[zone].SOA.String())
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
					pd.mu.Lock()
					pd.RpzSources[zone] = zonedata
					pd.mu.Unlock()
					// XXX: as parsing is done inline to the zone xfr, we don't need to inform
					// the caller (I hope). I think we do.
					zr.Resp <- RpzRefreshResult{Msg: "all ok"}
				}
			}

		case <-refreshTicker.C:
			ObservationsCh = pd.TapirObservations // stupid kludge
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
					updated, err := pd.RpzSources[zone].Refresh(upstream)
					rc.CurRefresh = rc.SOARefresh
					if err != nil {
						log.Printf("RefreshEngine: Error from zd.Refresh(%s): %v", zone, err)
					}
					if updated {
						if resetSoaSerial {
							pd.RpzSources[zone].SOA.Serial = uint32(time.Now().Unix())
							log.Printf("RefreshEngine: %s updated from upstream. Resetting serial to unixtime: %d",
								zone, pd.RpzSources[zone].SOA.Serial)

						}
					}
					if updated {
						err := pd.NotifyDownstreams()
						if err != nil {
							log.Printf("RefreshEngine: Error notifying downstreams: %v", err)
						}
					}
				}
			}

		case <-reaperTicker.C:
			err := pd.Reaper(false)
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
					if zd, exist := pd.RpzSources[zone]; exist {
						log.Printf("RefreshEngine: bumping SOA serial for known zone '%s'",
							zone)
						resp.OldSerial = zd.SOA.Serial
						zd.SOA.Serial = uint32(time.Now().Unix())
						resp.NewSerial = zd.SOA.Serial
						rc = refreshCounters[zone]
						err := pd.NotifyDownstreams()
						if err != nil {
							resp.Error = true
							resp.ErrorMsg = fmt.Sprintf("Error notifying downstreams: %v", err)
						}
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
				if pd.Allowlisted(cmd.Domain) {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("Domain name \"%s\" is allowlisted. No change.",
						cmd.Domain)
					cmd.Result <- resp
					continue
				}

				if pd.Denylisted(cmd.Domain) {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("Domain name \"%s\" is already denylisted. No change.",
						cmd.Domain)

					cmd.Result <- resp
					continue
				}

				// if the name isn't either allowlisted or denylisted
				if cmd.ListType == "doubtlist" {
					_, err := pd.DoubtlistAdd(cmd.Domain, cmd.Policy, cmd.RpzSource)
					if err != nil {
						resp.Error = true
						resp.ErrorMsg = fmt.Sprintf("Error adding domain name \"%s\" to doubtlisting DB: %v", cmd.Domain, err)
					} else {
						resp.Msg = fmt.Sprintf("Domain name \"%s\" (policy %s) added to doubtlisting DB.",
							cmd.Domain, cmd.Policy)
					}
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
				if pd.Allowlisted(cmd.Domain) {
					resp.Msg = fmt.Sprintf("Domain name \"%s\" is allowlisted.", cmd.Domain)
					cmd.Result <- resp
					continue
				}
				msg += fmt.Sprintf("Domain name \"%s\" is not allowlisted.\n", cmd.Domain)

				if pd.Denylisted(cmd.Domain) {
					resp.Msg = fmt.Sprintf("Domain name \"%s\" is denylisted.", cmd.Domain)
					cmd.Result <- resp
					continue
				}
				msg += fmt.Sprintf("Domain name \"%s\" is not denylisted.\n", cmd.Domain)

				// if the name isn't either allowlisted or denylisted: go though all doubtlists
				_, doubtmsg := pd.DoubtlistingReport(cmd.Domain)
				resp.Msg = msg + doubtmsg
				cmd.Result <- resp
				continue

			case "RPZ-LIST-SOURCES":
				log.Printf("RefreshEngine: recieved an RPZ LIST-SOURCES command")
				list := []string{}
				//				for _, wl := range pd.Allowlists {
				for _, wl := range pd.Lists["allowlist"] {
					list = append(list, wl.Name)
				}
				resp.Msg += fmt.Sprintf("Allowlist srcs: %s\n", strings.Join(list, ", "))

				list = []string{}
				//				for _, bl := range pd.Denylists {
				for _, bl := range pd.Lists["denylist"] {
					list = append(list, bl.Name)
				}
				resp.Msg += fmt.Sprintf("denylist srcs: %s\n", strings.Join(list, ", "))

				list = []string{}
				//				for _, gl := range pd.Doubtlists {
				for _, gl := range pd.Lists["doubtlist"] {
					list = append(list, gl.Name)
				}
				resp.Msg += fmt.Sprintf("Doubtlist srcs: %s\n", strings.Join(list, ", "))
				cmd.Result <- resp

			default:
				pd.Logger.Printf("RefreshEngine: unknown command: \"%s\". Ignored.", command)
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("RefreshEngine: unknown command: \"%s\". Ignored.",
					command)
				cmd.Result <- resp
			}
		}
	}
}

func (pd *PopData) NotifyDownstreams() error {
	pd.Logger.Printf("RefreshEngine: Notifying %d downstreams for RPZ zone %s", len(pd.Downstreams), pd.Rpz.ZoneName)
	for _, d := range pd.Downstreams {
		dest := net.JoinHostPort(d.Address, strconv.Itoa(d.Port))
		csu := tapir.ComponentStatusUpdate{
			Component: "downstream-notify",
			Status:    tapir.StatusFail,
			Msg:       fmt.Sprintf("Notifying downstream %s about new SOA serial (%d) for RPZ zone %s", dest, pd.Rpz.Axfr.SOA.Serial, pd.Rpz.ZoneName),
			TimeStamp: time.Now(),
		}

		m := new(dns.Msg)
		m.SetNotify(pd.Rpz.ZoneName)
		pd.Rpz.Axfr.SOA.Serial = pd.Rpz.CurrentSerial
		// m.Ns = append(m.Ns, dns.RR(&pd.Rpz.Axfr.SOA))
		pd.Logger.Printf("RefreshEngine: Notifying downstream %s about new SOA serial (%d) for RPZ zone %s", dest, pd.Rpz.Axfr.SOA.Serial, pd.Rpz.ZoneName)
		r, err := dns.Exchange(m, dest)
		if err != nil {
			// well, we tried
			csu.Msg = fmt.Sprintf("Error from downstream %s on NOTIFY(%s): %v", dest, pd.Rpz.ZoneName, err)
			Gconfig.Internal.ComponentStatusCh <- csu
			pd.Logger.Println(csu.Msg)
			continue
		}
		if r.Opcode != dns.OpcodeNotify {
			// well, we tried
			csu.Msg = fmt.Sprintf("Error: not a NOTIFY response from downstream %s on NOTIFY(%s): %s", dest, pd.Rpz.ZoneName, dns.OpcodeToString[r.Opcode])
			Gconfig.Internal.ComponentStatusCh <- csu
			pd.Logger.Println(csu.Msg)
			continue

		} else {
			if r.Rcode != dns.RcodeSuccess {
				csu.Msg = fmt.Sprintf("Downstream %s responded with rcode %s to NOTIFY(%s) about new SOA serial (%d)", dest, dns.RcodeToString[r.Rcode], pd.Rpz.ZoneName, pd.Rpz.Axfr.SOA.Serial)
				Gconfig.Internal.ComponentStatusCh <- csu
				pd.Logger.Println(csu.Msg)
				continue
			}
			csu.Status = tapir.StatusOK
			csu.Msg = fmt.Sprintf("Downstream %s responded correctly to NOTIFY(%s) about new SOA serial (%d)", dest, pd.Rpz.ZoneName, pd.Rpz.Axfr.SOA.Serial)
			Gconfig.Internal.ComponentStatusCh <- csu
			pd.Logger.Println(csu.Msg)
		}
	}
	return nil
}
