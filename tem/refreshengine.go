/*
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package main

import (
	"fmt"
	"log"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/viper"

	"github.com/dnstapir/tapir-em/tapir"
)

type RefreshCounter struct {
	Name           string
	SOARefresh     uint32
	CurRefresh     uint32
	IncomingSerial uint32
	KeepFunc       func(uint16) bool
	Upstream       string
	Downstreams    []string
}

func (td *TemData) RefreshEngine(conf *Config, stopch chan struct{}) {

	var zonerefch = conf.Internal.RefreshZoneCh
	var rpzcmdch = conf.Internal.RpzCmdCh

	var refreshCounters = make(map[string]*RefreshCounter, 5)
	ticker := time.NewTicker(1 * time.Second)

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
	var keepfunc func(uint16) bool
	var rc *RefreshCounter
	var updated bool
	var err error
	var cmd RpzCmdData
	var zr ZoneRefresher

	resetSoaSerial := viper.GetBool("service.reset_soa_serial")

	for {
		select {
		case zr = <-zonerefch:
			zone = zr.Name
			log.Printf("RefreshEngine: Requested to refresh zone \"%s\"", zone)
			if zone != "" {
				if zonedata, exist := Zones[zone]; exist {
					log.Printf("RefreshEngine: scheduling immediate refresh for known zone '%s'",
						zone)
					if _, known := refreshCounters[zone]; !known {
						refresh = zonedata.SOA.Refresh
						upstream = GetUpstream(zone)
						downstreams = GetDownstreams(zone)
						_, keepfunc = GetKeepFunc(zone)
						refreshCounters[zone] = &RefreshCounter{
							Name:        zone,
							SOARefresh:  refresh,
							CurRefresh:  1, // force immediate refresh
							KeepFunc:    keepfunc,
							Upstream:    upstream,
							Downstreams: downstreams,
						}
					} else {
						rc = refreshCounters[zone]
					}
					updated, err = Zones[zone].Refresh(rc.Upstream, rc.KeepFunc)
					if err != nil {
						log.Printf("RefreshEngine: Error from zone refresh(%s): %v", zone, err)
					}

					if updated {
						if resetSoaSerial {
							Zones[zone].SOA.Serial = uint32(time.Now().Unix())
							log.Printf("RefreshEngine: %s updated from upstream. Resetting serial to unixtime: %d",
								zone, Zones[zone].SOA.Serial)
						}
						NotifyDownstreams(Zones[zone], rc.Downstreams)
					}
					// showing some apex details:
					log.Printf("Showing some details for zone %s: zoneid=%s", zone, Zones[zone].ZoneID)
					log.Printf("%s SOA: %s", zone, Zones[zone].SOA.String())
					for _, rr := range Zones[zone].TXTrrs {
						log.Printf("%s TXT: %s", zone, rr.String())
					}
					//					for _, rr := range Zones[zone].ZONEMDrrs {
					//						log.Printf("%s ZONEMD: %s", zone, rr.String())
					//					}
				} else {
					log.Printf("RefreshEngine: adding the new zone '%s'", zone)
					upstream = GetUpstream(zone)
					downstreams = GetDownstreams(zone)
					_, keepfunc = GetKeepFunc(zone)
					zonedata = &tapir.ZoneData{
						ZoneName: zone,
						ZoneType: zr.ZoneType,
						KeepFunc: keepfunc,
						Logger:   log.Default(),
					}
					// log.Printf("RefEng: New zone %s, keepfunc: %v", zone, keepfunc)
					updated, err := zonedata.Refresh(upstream, keepfunc)
					if err != nil {
						log.Printf("RefreshEngine: Error from zone refresh(%s): %v",
							zone, err)
					}

					refresh = zonedata.SOA.Refresh
					// Is there a max refresh counter configured, then use it.
					maxrefresh := uint32(viper.GetInt("service.maxrefresh"))
					if maxrefresh != 0 && maxrefresh < refresh {
						refresh = maxrefresh
					}
					refreshCounters[zone] = &RefreshCounter{
						Name:        zone,
						SOARefresh:  refresh,
						CurRefresh:  refresh,
						KeepFunc:    keepfunc,
						Upstream:    upstream,
						Downstreams: downstreams,
					}

					if updated {
						if resetSoaSerial {
							zonedata.SOA.Serial = uint32(time.Now().Unix())
							log.Printf("RefreshEngine: %s updated from upstream. Resetting serial to unixtime: %d",
								zone, zonedata.SOA.Serial)
						}
						NotifyDownstreams(zonedata, downstreams)
					}
					Zones[zone] = zonedata
				}
			}

		case <-ticker.C:
			// log.Printf("RefEng: ticker. refCounters: %v", refreshCounters)
			for zone, rc := range refreshCounters {
				// log.Printf("RefEng: ticker for %s: curref: %d", zone, v.CurRefresh)
				rc.CurRefresh--
				if rc.CurRefresh <= 0 {
					upstream = GetUpstream(zone)
					if rc.KeepFunc == nil {
						panic("keepfunc=nil in refeng")
					}

					log.Printf("RefreshEngine: will refresh zone %s due to refresh counter", zone)
					// log.Printf("Len(Zones) = %d", len(Zones))
					updated, err := Zones[zone].Refresh(upstream, rc.KeepFunc)
					rc.CurRefresh = rc.SOARefresh
					if err != nil {
						log.Printf("RefreshEngine: Error from zd.Refresh(%s): %v", zone, err)
					}
					if updated {
						if resetSoaSerial {
							Zones[zone].SOA.Serial = uint32(time.Now().Unix())
							log.Printf("RefreshEngine: %s updated from upstream. Resetting serial to unixtime: %d",
								zone, Zones[zone].SOA.Serial)

						}
					}
					if updated {
						NotifyDownstreams(Zones[zone], rc.Downstreams)
					}
				}
			}

		case cmd = <-rpzcmdch:
			command := cmd.Command
			resp := RpzCmdResponse{
					Zone: zone,
			}
			switch command {
			case "BUMP":
				zone = cmd.Zone
				if zone != "" {
					if zd, exist := Zones[zone]; exist {
						log.Printf("RefreshEngine: bumping SOA serial for known zone '%s'",
							zone)
						resp.OldSerial = zd.SOA.Serial
						zd.SOA.Serial = uint32(time.Now().Unix())
						resp.NewSerial = zd.SOA.Serial
						rc = refreshCounters[zone]
						NotifyDownstreams(zd, rc.Downstreams)
						resp.Msg = fmt.Sprintf("Zone %s: bumped serial from %d to %d. Notified downstreams: %v",
							zone, resp.OldSerial, resp.NewSerial, rc.Downstreams)
						log.Printf(resp.Msg)
						resp.Status = true
					} else {
						resp.Error = true
						resp.ErrorMsg = fmt.Sprintf("Request to bump serial and epoch for unknown zone '%s'", zone)
						log.Printf(resp.ErrorMsg)
					}
				}
				cmd.Result <- resp

			case "RPZ-ADD":
				log.Printf("RefreshEngine: recieved an RPZ ADD command: %s (policy %s)", cmd.Domain, cmd.Policy)
				if td.Whitelisted(cmd.Domain) {
				   resp.Error = true
				   resp.ErrorMsg = fmt.Sprintf("No rule added for \"%s\" as this domain is whitelisted.",
				   		   		   cmd.Domain)
				} else {
				   resp.Msg = fmt.Sprintf("New rule added for \"%s\" (policy %s).",
				   	      		       cmd.Domain, cmd.Policy)
				  
				}
				cmd.Result <- resp

			case "RPZ-REMOVE":
				log.Printf("RefreshEngine: recieved an RPZ REMOVE command: %s", cmd.Domain)
				resp.Msg = "RPZ-REMOVE NYI"
				cmd.Result <- resp
			}
		}
	}
}

func NotifyDownstreams(zd *tapir.ZoneData, downstreams []string) error {
	for _, d := range downstreams {
		log.Printf("RefreshEngine: %s: Notifying downstream %s about new SOA serial", zd.ZoneName, d)
		m := new(dns.Msg)
		m.SetNotify(zd.ZoneName)
		r, err := dns.Exchange(m, d)
		if err != nil {
			// well, we tried
			log.Printf("Error from downstream %s on Notify(%s): %v", d, zd.ZoneName, err)
			continue
		}
		if r.Opcode != dns.OpcodeNotify {
			// well, we tried
			log.Printf("Error: not a NOTIFY QR from downstream %s on Notify(%s): %s",
				d, zd.ZoneName, dns.OpcodeToString[r.Opcode])
		}
	}
	return nil
}
