/*
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package main

import (
	"fmt"
	"log"
	"strings"

	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
	"github.com/spf13/viper"

	"github.com/dnstapir/tapir-em/tapir"
)

var RpzZones = make(map[string]*tapir.ZoneData, 5)

// func DnsEngine(scannerq chan ScanRequest, updateq chan UpdateRequest) error {
func DnsEngine(conf *Config) error {
	addresses := viper.GetStringSlice("dnsengine.addresses")

	//      verbose := viper.GetBool("dnsengine.verbose")
	//      debug := viper.GetBool("dnsengine.debug")
	dns.HandleFunc(".", createHandler(conf))

	log.Printf("DnsEngine: addresses: %v", addresses)
	for _, addr := range addresses {
		for _, net := range []string{"udp", "tcp"} {
			go func(addr, net string) {
				log.Printf("DnsEngine: serving on %s (%s)\n", addr, net)
				server := &dns.Server{Addr: addr, Net: net}

				// Must bump the buffer size of incoming UDP msgs, as updates
				// may be much larger then queries
				server.UDPSize = dns.DefaultMsgSize // 4096
				if err := server.ListenAndServe(); err != nil {
					log.Printf("Failed to setup the %s server: %s\n", net, err.Error())
				} else {
					log.Printf("DnsEngine: listening on %s/%s\n", addr, net)
				}
			}(addr, net)
		}
	}
	return nil
}

func xxxServe(conf *Config, net, address, port string, soreuseport bool) {
	service := address + ":" + port
	fmt.Printf("%s: serving on %s (%s)\n", conf.Service.Name, service, net)

	server := &dns.Server{Addr: service, Net: net, ReusePort: soreuseport}
	if err := server.ListenAndServe(); err != nil {
		fmt.Printf("Failed to setup the "+net+" server: %s\n", err.Error())
	} else {
		fmt.Printf("TEM: listening on %s/%s\n", service, net)
	}
}

func GetKeepFunc(zone string) (string, func(uint16) bool) {
	switch viper.GetString("service.filter") {
	case "dnssec":
		return "dnssec", tapir.DropDNSSECp
	case "dnssec+zonemd":
		return "dnssec+zonemd", tapir.DropDNSSECZONEMDp
	}
	return "none", func(t uint16) bool { return true }
}

func createHandler(conf *Config) func(w dns.ResponseWriter, r *dns.Msg) {

	zonech := conf.TemData.RpzRefreshCh

	//	var rrtypes []string

	return func(w dns.ResponseWriter, r *dns.Msg) {
		qname := r.Question[0].Name
		var dnssec_ok bool
		opt := r.IsEdns0()
		if opt != nil {
			dnssec_ok = opt.Do()
		}
		log.Printf("DNSSEC OK: %v", dnssec_ok)

		switch r.Opcode {
		case dns.OpcodeNotify:
			ntype := r.Question[0].Qtype
			log.Printf("Received NOTIFY(%s) for zone '%s'", dns.TypeToString[ntype], qname)
			// send NOERROR response
			m := new(dns.Msg)
			m.SetReply(r)
			w.WriteMsg(m)

			if _, ok := RpzZones[qname]; ok {
				log.Printf("Received Notify for known zone %s. Fetching from upstream", qname)
				zonech <- RpzRefresher{
					Name:     qname, // send zone name into RefreshEngine
					ZoneType: RpzZones[qname].ZoneType,
				}
			} else {
				log.Printf("Received Notify for unknown zone %s. Fetching from upstream", qname)
				zonech <- RpzRefresher{
					Name:     qname,
					ZoneType: 1, // unknown zones are stored as the simplest type, i.e. as xfr zones
				}
			}
			fmt.Printf("Notify message: %v\n", m.String())

			return

		case dns.OpcodeQuery:
			qtype := r.Question[0].Qtype
			log.Printf("Zone %s %s request from %s", qname, dns.TypeToString[qtype], w.RemoteAddr())
			if zd, ok := RpzZones[qname]; ok {
				// The qname is equal to the name of a zone we have
				ApexResponder(w, r, zd, qname, qtype, dnssec_ok)
			} else {
				log.Printf("DnsHandler: Qname is '%s', which is not a known zone.", qname)
				known_zones := []string{}
				for z, _ := range RpzZones {
					known_zones = append(known_zones, z)
				}
				log.Printf("DnsHandler: Known zones are: %v", known_zones)

				// Let's see if we can find the zone
				zd := FindZone(qname)
				if zd == nil {
					log.Printf("After FindZone: zd==nil")
					m := new(dns.Msg)
					m.SetRcode(r, dns.RcodeRefused)
					w.WriteMsg(m)
					return // didn't find any zone for that qname or found zone, but it is an XFR zone only
				}
				log.Printf("After FindZone: zd: zd.ZoneType: %v", zd.ZoneType)
				if zd.ZoneType == 1 {
					m := new(dns.Msg)
					m.SetRcode(r, dns.RcodeRefused)
					w.WriteMsg(m)
					return // didn't find any zone for that qname or found zone, but it is an XFR zone only
				}
				log.Printf("Found matching full zone for qname %s: %s", qname, zd.ZoneName)
				QueryResponder(w, r, zd, qname, qtype, dnssec_ok)
				return
			}
			return

		default:
			log.Printf("Error: unable to handle msgs of type %s",
				dns.OpcodeToString[r.Opcode])
		}
	}
}

func ApexResponder(w dns.ResponseWriter, r *dns.Msg, zd *tapir.ZoneData, qname string, qtype uint16, dnssec_ok bool) error {
	m := new(dns.Msg)
	m.SetReply(r)
	m.MsgHdr.Authoritative = true

	apex := zd.Owners[zd.OwnerIndex[zd.ZoneName]]
	// zd.Logger.Printf("*** Ownerindex(%s)=%d apex: %v", zd.ZoneName, zd.OwnerIndex[zd.ZoneName], apex)
	var glue tapir.RRset

	switch qtype {
	case dns.TypeAXFR, dns.TypeIXFR:
		log.Printf("We have the zone %s, so let's try to serve it", qname)
		log.Printf("SOA: %s", zd.SOA.String())
		log.Printf("FilteredRRs: %d (+ %d apex RRs)", len(zd.FilteredRRs), zd.ApexLen)

		zd.ZoneTransferOut(w, r)
		return nil
	case dns.TypeSOA:
		// zd.Logger.Printf("There are %d SOA RRs in %s. rrset: %v", len(apex.RRtypes[dns.TypeSOA].RRs),
		// 			   zd.ZoneName, apex.RRtypes[dns.TypeSOA])
		m.Answer = append(m.Answer, dns.RR(&zd.SOA))
		m.Ns = append(m.Ns, apex.RRtypes[dns.TypeNS].RRs...)
		glue = *zd.FindGlue(apex.RRtypes[dns.TypeNS], dnssec_ok)
		m.Extra = append(m.Extra, glue.RRs...)
// 	case dns.TypeMX, dns.TypeTLSA, dns.TypeSRV, dns.TypeA, dns.TypeAAAA,
// 				dns.TypeNS, dns.TypeTXT, dns.TypeZONEMD,
// 				dns.TypeNSEC, dns.TypeNSEC3, dns.TypeNSEC3PARAM, dns.TypeRRSIG, 
// 				dns.TypeDNSKEY, dns.TypeCSYNC, dns.TypeCDS, dns.TypeCDNSKEY:
// 				if rrset, ok := apex.RRtypes[qtype]; ok {
// 					if len(rrset.RRs) > 0 {
// 						m.Answer = append(m.Answer, rrset.RRs...)
// 						m.Ns = append(m.Ns, apex.RRtypes[dns.TypeNS].RRs...)
// 						glue = *zd.FindGlue(apex.RRtypes[dns.TypeNS], dnssec_ok)
// 						m.Extra = append(m.Extra, glue.RRs...)
// 					} else {
// 						m.Ns = append(m.Ns, apex.RRtypes[dns.TypeSOA].RRs...)
// 					}
// 				} else {
// 					m.Ns = append(m.Ns, apex.RRtypes[dns.TypeSOA].RRs...)
// 				}

	default:
		// every apex query we don't want to deal with
		m.MsgHdr.Rcode = dns.RcodeRefused
		m.Ns = append(m.Ns, zd.NSrrs...)
	}
	w.WriteMsg(m)
	return nil
}

// 0. Check for *any* existence of qname
// 1. [OK] For a qname below zone, first check if there is a delegation. If so--> send referral
// 2. If no delegation, check for exact match
// 3. [OK] If no exact match, check for CNAME match
// 4. If no CNAME match, check for wild card match
// 5. Give up.

func QueryResponder(w dns.ResponseWriter, r *dns.Msg, zd *tapir.ZoneData, qname string, qtype uint16, dnssec_ok bool) error {

	m := new(dns.Msg)
	m.SetReply(r)
	m.MsgHdr.Authoritative = true

	var apex tapir.OwnerData

	switch zd.ZoneType {
	case 2:
		apex = zd.Data[zd.ZoneName]
	case 3:
		apex = zd.Owners[zd.OwnerIndex[zd.ZoneName]]
	}

	returnNXDOMAIN := func() {
		// return NXDOMAIN
		m.MsgHdr.Rcode = dns.RcodeNameError
		m.Ns = append(m.Ns, apex.RRtypes[dns.TypeSOA].RRs...)
//		if dnssec_ok {
//			m.Ns = append(m.Ns, apex.RRtypes[dns.TypeSOA].RRSIGs...)
			// XXX: Here we need to also add the proof of non-existence via NSEC+RRSIG(NSEC)
			// or NSEC3+RRSIG(NSEC3)... at some point
			// covering NSEC+RRSIG(that NSEC) + // apex NSEC + RRSIG(apex NSEC)
//		}
		w.WriteMsg(m)
		return
	}

	// log.Printf("Zone %s Data: %v", zd.ZoneName, zd.Data)

	var owner tapir.OwnerData
	switch zd.ZoneType {
	case 2:
		if tmp, exist := zd.Data[qname]; exist {
			owner = tmp
		} else {
			returnNXDOMAIN()
			return nil
		}

	case 3:
		if _, ok := zd.OwnerIndex[qname]; !ok {
			// return NXDOMAIN
			m.MsgHdr.Rcode = dns.RcodeNameError
			m.Ns = append(m.Ns, apex.RRtypes[dns.TypeSOA].RRs...)
//			if dnssec_ok {
//				m.Ns = append(m.Ns, apex.RRtypes[dns.TypeSOA].RRSIGs...)
				// XXX: Here we need to also add the proof of non-existence via NSEC+RRSIG(NSEC) or NSEC3+RRSIG(NSEC3)... at some point
				// covering NSEC+RRSIG(that NSEC) + // apex NSEC + RRSIG(apex NSEC)
//			}
			w.WriteMsg(m)
			return nil
		}

		owner = zd.Owners[zd.OwnerIndex[qname]]
	default:
		log.Fatalf("Error: QueryResponder: unknown zone type: %d", zd.ZoneType)
	}

	var glue *tapir.RRset

	// 0. Check for *any existence of qname in zone
	if len(owner.RRtypes) == 0 {
		m.MsgHdr.Rcode = dns.RcodeNameError
		m.Ns = append(m.Ns, apex.RRtypes[dns.TypeSOA].RRs...)
//		if dnssec_ok {
//			m.Ns = append(m.Ns, apex.RRtypes[dns.TypeSOA].RRSIGs...)
			// XXX: Here we need to also add the proof of non-existence via NSEC+RRSIG(NSEC) or NSEC3+RRSIG(NSEC3)... at some point
			// covering NSEC+RRSIG(that NSEC) + // apex NSEC + RRSIG(apex NSEC)
//		}
		w.WriteMsg(m)
		return nil
	}

	// 2. Check for qname + CNAME
	// if len(zd.Data[qname].RRtypes) == 1 {
	if len(owner.RRtypes) == 1 {
		for k, v := range owner.RRtypes {
			if k == dns.TypeCNAME {
				if len(v.RRs) > 1 {
					// XXX: NSD will not even load a zone with multiple CNAMEs. Better to check during load...
					log.Printf("QueryResponder: Zone %s: Illegal content: multiple CNAME RRs: %v", zd.ZoneName, v)
				}
				// m.Answer = append(m.Answer, FilterRRSIG(v, dnssec_ok)...)
				m.Answer = append(m.Answer, v.RRs...)
//				if dnssec_ok {
//					m.Answer = append(m.Answer, v.RRSIGs...)
//				}
				tgt := v.RRs[0].(*dns.CNAME).Target
				if strings.HasSuffix(tgt, zd.ZoneName) {
					if tgtrrset, ok := zd.Owners[zd.OwnerIndex[tgt]].RRtypes[qtype]; ok {
						m.Answer = append(m.Answer, tgtrrset.RRs...)
						m.Ns = append(m.Ns, apex.RRtypes[dns.TypeNS].RRs...)
						glue = zd.FindGlue(apex.RRtypes[dns.TypeNS], dnssec_ok)
						m.Extra = append(m.Extra, glue.RRs...)
//						if dnssec_ok {
//							m.Answer = append(m.Answer, tgtrrset.RRSIGs...)
//							m.Ns = append(m.Ns, apex.RRtypes[dns.TypeNS].RRSIGs...)
//							m.Extra = append(m.Extra, glue.RRSIGs...)
//						}
					}
					w.WriteMsg(m)
					return nil
				}
			}
		}
	}

	// 1. Check for child delegation
	//	childns, glue := zd.FindDelegation(qname, dnssec_ok)
	//	log.Printf("Checking for child delegation for %s", qname)
	//	if childns != nil {
	//		m.MsgHdr.Authoritative = false
	//		m.Ns = append(m.Ns, childns.RRs...)
	//		m.Extra = append(m.Extra, glue.RRs...)
	//		w.WriteMsg(m)
	//		return nil
	//	}

	// 2. Check for exact match qname+qtype
	switch qtype {
	case dns.TypeTXT, dns.TypeMX, dns.TypeA, dns.TypeAAAA:
		//		dns.TypeDS, dns.TypeNSEC, dns.TypeNSEC3, dns.TypeRRSIG:
		log.Printf("Apex data[%s]:\n", zd.ZoneName)
		for rrt, d := range apex.RRtypes {
			log.Printf("%s: %v", dns.TypeToString[rrt], d)
		}

		log.Printf("Qname data[%s]:\n", qname)
		for rrt, d := range owner.RRtypes {
			log.Printf("%s: %v", dns.TypeToString[rrt], d)
		}

		if _, ok := owner.RRtypes[qtype]; ok && len(owner.RRtypes[qtype].RRs) > 0 {
			m.Answer = append(m.Answer, owner.RRtypes[qtype].RRs...)
			m.Ns = append(m.Ns, apex.RRtypes[dns.TypeNS].RRs...)
			glue = zd.FindGlue(apex.RRtypes[dns.TypeNS], dnssec_ok)
			m.Extra = append(m.Extra, glue.RRs...)
//			if dnssec_ok {
//				m.Answer = append(m.Answer, owner.RRtypes[qtype].RRSIGs...)
//				m.Ns = append(m.Ns, apex.RRtypes[dns.TypeNS].RRSIGs...)
//				m.Extra = append(m.Extra, glue.RRSIGs...)
//			}
		} else {
			m.Ns = append(m.Ns, apex.RRtypes[dns.TypeSOA].RRs...)
//			if dnssec_ok {
//				m.Ns = append(m.Ns, apex.RRtypes[dns.TypeSOA].RRSIGs...)
//			}
		}
		w.WriteMsg(m)
		return nil

	default:
		// everything we don't want to deal with
		m.MsgHdr.Rcode = dns.RcodeRefused
		m.Ns = append(m.Ns, apex.RRtypes[dns.TypeNS].RRs...)
		glue = zd.FindGlue(apex.RRtypes[dns.TypeNS], dnssec_ok)
		m.Extra = append(m.Extra, glue.RRs...)
//		if dnssec_ok {
//			m.Extra = append(m.Extra, glue.RRSIGs...)
//		}
		w.WriteMsg(m)
	}
	return nil
}

func FindZone(qname string) *tapir.ZoneData {
	var tzone string
	labels := strings.Split(qname, ".")
	for i := 1; i < len(labels)-1; i++ {
		tzone = strings.Join(labels[i:], ".")
		log.Printf("FindZone for qname='%s': testing '%s'", qname, tzone)
		if z, ok := RpzZones[tzone]; ok {
			log.Printf("Yes, zone=%s for qname=%s", tzone, qname)
			return z
		}
	}
	log.Printf("FindZone: no zone for qname=%s found", qname)
	return nil
}

func FindZoneNG(qname string) *tapir.ZoneData {
	i := strings.Index(qname, ".")
	for {
		if i == -1 {
			break // done
		}
		log.Printf("FindZone for qname='%s': testing '%s'", qname, qname[i:])
		if z, ok := RpzZones[qname[i:]]; ok {
			log.Printf("Yes, zone=%s for qname=%s", qname[i:], qname)
			return z
		}
		i = strings.Index(qname[i:], ".")
	}
	log.Printf("FindZone: no zone for qname=%s found", qname)
	return nil
}
