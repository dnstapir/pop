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

	"github.com/dnstapir/tapir"
)

// var RpzZones = make(map[string]*tapir.ZoneData, 5)

// func DnsEngine(scannerq chan ScanRequest, updateq chan UpdateRequest) error {
func DnsEngine(conf *Config) error {
	addresses := viper.GetStringSlice("dnsengine.addresses")

	//      verbose := viper.GetBool("dnsengine.verbose")
	//      debug := viper.GetBool("dnsengine.debug")
	dns.HandleFunc(".", createHandler(conf))

	conf.Loggers.Dnsengine.Printf("DnsEngine: addresses: %v", addresses)
	for _, addr := range addresses {
		for _, net := range []string{"udp", "tcp"} {
			go func(addr, net string) {
				conf.Loggers.Dnsengine.Printf("DnsEngine: serving on %s (%s)\n", addr, net)
				server := &dns.Server{Addr: addr, Net: net}

				// Must bump the buffer size of incoming UDP msgs, as updates
				// may be much larger then queries
				server.UDPSize = dns.DefaultMsgSize // 4096
				if err := server.ListenAndServe(); err != nil {
					conf.Loggers.Dnsengine.Printf("Failed to setup the %s server: %s\n", net, err.Error())
				} else {
					conf.Loggers.Dnsengine.Printf("DnsEngine: listening on %s/%s\n", addr, net)
				}
			}(addr, net)
		}
	}
	return nil
}

func createHandler(conf *Config) func(w dns.ResponseWriter, r *dns.Msg) {

	td := conf.TemData
	lg := conf.Loggers.Dnsengine
	zonech := conf.TemData.RpzRefreshCh

	//	var rrtypes []string

	return func(w dns.ResponseWriter, r *dns.Msg) {
		qname := r.Question[0].Name

		switch r.Opcode {
		case dns.OpcodeNotify:
			ntype := r.Question[0].Qtype
			lg.Printf("Received NOTIFY(%s) for zone '%s'", dns.TypeToString[ntype], qname)
			// send NOERROR response
			m := new(dns.Msg)
			m.SetReply(r)
			err := w.WriteMsg(m)
			if err != nil {
				lg.Printf("createHandler: unable to call WriteMsg() for OpcodeNotify: %s", err)
			}

			if _, ok := td.RpzSources[qname]; ok {
				lg.Printf("Received Notify for known zone %s. Fetching from upstream", qname)
				zonech <- RpzRefresh{
					Name:     qname, // send zone name into RefreshEngine
					ZoneType: td.RpzSources[qname].ZoneType,
				}
			}
			lg.Printf("Notify message: %v\n", m.String())

			return

		case dns.OpcodeQuery:
			qtype := r.Question[0].Qtype
			lg.Printf("Zone %s %s request from %s", qname, dns.TypeToString[qtype], w.RemoteAddr())
			if qname == td.Rpz.ZoneName {
				err := td.RpzResponder(w, r, qtype, lg)
				if err != nil {
					lg.Printf("createHandler: unable to call RpzResponder(): %s", err)
				}
			} else if zd, ok := td.RpzSources[qname]; ok {
				// The qname is equal to the name of a zone we have
				err := ApexResponder(w, r, zd, qname, qtype, lg)
				if err != nil {
					lg.Printf("createHandler: unable to call ApexResponder(): %s", err)
				}
			} else {
				lg.Printf("DnsHandler: Qname is '%s', which is not a known zone.", qname)
				known_zones := []string{td.Rpz.ZoneName}
				for z := range td.RpzSources {
					known_zones = append(known_zones, z)
				}
				lg.Printf("DnsHandler: Known zones are: %v", known_zones)

				// Let's see if we can find the zone
				if strings.HasSuffix(qname, td.Rpz.ZoneName) {
					lg.Printf("Query for qname %s belongs in our own RPZ \"%s\"",
						qname, td.Rpz.ZoneName)
					err := td.QueryResponder(w, r, qname, qtype, lg)
					if err != nil {
						lg.Printf("createHandler: unable to call QueryResponder(): %s", err)
					}
					return
				}
				zd := td.FindZone(qname)
				if zd == nil {
					lg.Printf("After FindZone: zd==nil")
					m := new(dns.Msg)
					m.SetRcode(r, dns.RcodeRefused)
					err := w.WriteMsg(m)
					if err != nil {
						lg.Printf("createHandler: unable to call WriteMsg() for OpcodeQuery: %s", err)
					}
					return // didn't find any zone for that qname or found zone, but it is an XFR zone only
				}
				lg.Printf("After FindZone: zd: zd.ZoneType: %v", zd.ZoneType)
				if zd.ZoneType == tapir.XfrZone {
					m := new(dns.Msg)
					m.SetRcode(r, dns.RcodeRefused)
					err := w.WriteMsg(m)
					if err != nil {
						lg.Printf("createHandler: unable to WriteMsg() for XfrZone: %s", err)
					}
					return // didn't find any zone for that qname or found zone, but it is an XFR zone only
				}
				lg.Printf("Found matching full zone for qname %s: %s", qname, zd.ZoneName)
				err := QueryResponder(w, r, zd, qname, qtype, lg)
				if err != nil {
					lg.Printf("createHandler: unable to call QueryResponder(): %s", err)
				}
				return
			}
			return

		default:
			lg.Printf("Error: unable to handle msgs of type %s",
				dns.OpcodeToString[r.Opcode])
		}
	}
}

func (td *TemData) RpzResponder(w dns.ResponseWriter, r *dns.Msg, qtype uint16, lg *log.Logger) error {
	m := new(dns.Msg)
	m.SetReply(r)
	m.MsgHdr.Authoritative = true

	//	apex := zd.Owners[zd.OwnerIndex[zd.ZoneName]]
	// zd.Logger.Printf("*** Ownerindex(%s)=%d apex: %v", zd.ZoneName, zd.OwnerIndex[zd.ZoneName], apex)
	zd := td.Rpz.Axfr.ZoneData
	// XXX: we need this, but later var glue tapir.RRset

	switch qtype {
	case dns.TypeAXFR:
		lg.Printf("We have the zone %s, so let's try to serve it", td.Rpz.ZoneName)
		//		log.Printf("SOA: %s", zd.SOA.String())
		//		log.Printf("BodyRRs: %d (+ %d apex RRs)", len(zd.BodyRRs), zd.ApexLen)

		//		td.Logger.Printf("RpzResponder: sending zone %s with %d body RRs to XfrOut",
		//			zd.ZoneName, len(zd.RRs))

		serial, _, err := td.RpzAxfrOut(w, r)
		if err != nil {
			lg.Printf("RpzResponder: error from RpzAxfrOut() serving zone %s: %v", zd.ZoneName, err)
		}
		td.mu.Lock()
		td.Downstreams.Serial = serial
		td.mu.Unlock()
		return nil
	case dns.TypeIXFR:
		lg.Printf("RpzResponder: %s is our RPZ output", td.Rpz.ZoneName)

		serial, _, err := td.RpzIxfrOut(w, r)
		if err != nil {
			lg.Printf("RpzResponder: error from RpzIxfrOut() serving zone %s: %v", zd.ZoneName, err)
		}
		td.mu.Lock()
		td.Downstreams.Serial = serial
		td.mu.Unlock()
		return nil
	case dns.TypeSOA:
		// zd.Logger.Printf("There are %d SOA RRs in %s. rrset: %v", len(apex.RRtypes[dns.TypeSOA].RRs),
		// 			   zd.ZoneName, apex.RRtypes[dns.TypeSOA])
		//		m.Answer = append(m.Answer, dns.RR(&zd.SOA))
		td.Rpz.Axfr.SOA.Serial = td.Rpz.CurrentSerial
		m.Answer = append(m.Answer, dns.RR(&td.Rpz.Axfr.SOA))
		//		m.Ns = append(m.Ns, apex.RRtypes[dns.TypeNS].RRs...)
		m.Ns = append(m.Ns, td.Rpz.Axfr.ZoneData.NSrrs...)
		//		glue = *zd.FindGlue(apex.RRtypes[dns.TypeNS])
		//		m.Extra = append(m.Extra, glue.RRs...)

	default:
		// every apex query we don't want to deal with
		m.MsgHdr.Rcode = dns.RcodeRefused
		m.Ns = append(m.Ns, zd.NSrrs...)
	}
	err := w.WriteMsg(m)
	if err != nil {
		return fmt.Errorf("RpzResponder: unable to WriteMsg(): %w", err)
	}
	return nil
}

func ApexResponder(w dns.ResponseWriter, r *dns.Msg, zd *tapir.ZoneData,
	qname string, qtype uint16, lg *log.Logger) error {
	m := new(dns.Msg)
	m.SetReply(r)
	m.MsgHdr.Authoritative = true

	apex := zd.Owners[zd.OwnerIndex[zd.ZoneName]]
	// zd.Logger.Printf("*** Ownerindex(%s)=%d apex: %v", zd.ZoneName, zd.OwnerIndex[zd.ZoneName], apex)
	var glue tapir.RRset

	switch qtype {
	//	case dns.TypeAXFR, dns.TypeIXFR:
	//	log.Printf("We have the zone %s, so let's try to serve it", qname)
	//	log.Printf("SOA: %s", zd.SOA.String())
	//	log.Printf("BodyRRs: %d (+ %d apex RRs)", len(zd.BodyRRs), zd.ApexLen)

	//		zd.Logger.Printf("ApexResponder: sending zone %s with %d body RRs to XfrOut",
	//			zd.ZoneName, len(zd.RRs))

	//		_, err := zd.ZoneTransferOut(w, r)
	//		if err != nil {
	//			zd.Logger.Printf("ApexResponder: error serving zone %s: %v", zd.ZoneName, err)
	//		}
	//		return nil
	case dns.TypeSOA:
		// zd.Logger.Printf("There are %d SOA RRs in %s. rrset: %v", len(apex.RRtypes[dns.TypeSOA].RRs),
		// 			   zd.ZoneName, apex.RRtypes[dns.TypeSOA])
		m.Answer = append(m.Answer, dns.RR(&zd.SOA))
		m.Ns = append(m.Ns, apex.RRtypes[dns.TypeNS].RRs...)
		glue = *zd.FindGlue(apex.RRtypes[dns.TypeNS])
		m.Extra = append(m.Extra, glue.RRs...)

	default:
		// every apex query we don't want to deal with
		m.MsgHdr.Rcode = dns.RcodeRefused
		m.Ns = append(m.Ns, zd.NSrrs...)
	}
	err := w.WriteMsg(m)
	if err != nil {
		return fmt.Errorf("ApexResponder: unable to WriteMsg(): %w", err)
	}
	return nil
}

// 0. Check for *any* existence of qname
// 1. [OK] For a qname below zone, first check if there is a delegation. If so--> send referral
// 2. If no delegation, check for exact match
// 3. [OK] If no exact match, check for CNAME match
// 4. If no CNAME match, check for wild card match
// 5. Give up.

func QueryResponder(w dns.ResponseWriter, r *dns.Msg, zd *tapir.ZoneData, qname string, qtype uint16, lg *log.Logger) error {

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
		err := w.WriteMsg(m)
		if err != nil {
			lg.Printf("QueryResponder: unable to WriteMsg() in returnNXDOMAIN: %s", err)
		}
	}

	// log.Printf("Zone %s Data: %v", zd.ZoneName, zd.Data)

	var owner tapir.OwnerData
	switch zd.ZoneType {
	case tapir.MapZone, tapir.RpzZone:
		if tmp, exist := zd.Data[qname]; exist {
			owner = tmp
		} else {
			returnNXDOMAIN()
			return nil
		}

	case tapir.SliceZone:
		if _, ok := zd.OwnerIndex[qname]; !ok {
			// return NXDOMAIN
			m.MsgHdr.Rcode = dns.RcodeNameError
			m.Ns = append(m.Ns, apex.RRtypes[dns.TypeSOA].RRs...)
			err := w.WriteMsg(m)
			if err != nil {
				return fmt.Errorf("QueryResponder: unable to WriteMsg() NXDOMAIN for tapir.SliceZone: %w", err)
			}
			return nil
		}

		owner = zd.Owners[zd.OwnerIndex[qname]]
	default:
		TEMExiter("Error: QueryResponder: unknown zone type: %d", zd.ZoneType)
	}

	var glue *tapir.RRset

	// 0. Check for *any existence of qname in zone
	if len(owner.RRtypes) == 0 {
		m.MsgHdr.Rcode = dns.RcodeNameError
		m.Ns = append(m.Ns, apex.RRtypes[dns.TypeSOA].RRs...)
		err := w.WriteMsg(m)
		if err != nil {
			return fmt.Errorf("QueryResponder: unable to WriteMsg() when checking for qname existance in zone: %w", err)
		}
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
				m.Answer = append(m.Answer, v.RRs...)
				tgt := v.RRs[0].(*dns.CNAME).Target
				if strings.HasSuffix(tgt, zd.ZoneName) {
					if tgtrrset, ok := zd.Owners[zd.OwnerIndex[tgt]].RRtypes[qtype]; ok {
						m.Answer = append(m.Answer, tgtrrset.RRs...)
						m.Ns = append(m.Ns, apex.RRtypes[dns.TypeNS].RRs...)
						glue = zd.FindGlue(apex.RRtypes[dns.TypeNS])
						m.Extra = append(m.Extra, glue.RRs...)
					}
					err := w.WriteMsg(m)
					if err != nil {
						return fmt.Errorf("QueryResponder: unable to WriteMsg() when itrating over owner.RRtypes: %w", err)
					}
					return nil
				}
			}
		}
	}

	// 2. Check for exact match qname+qtype
	switch qtype {
	case dns.TypeTXT, dns.TypeMX, dns.TypeA, dns.TypeAAAA:
		lg.Printf("Apex data[%s]:\n", zd.ZoneName)
		for rrt, d := range apex.RRtypes {
			lg.Printf("%s: %v", dns.TypeToString[rrt], d)
		}

		lg.Printf("Qname data[%s]:\n", qname)
		for rrt, d := range owner.RRtypes {
			lg.Printf("%s: %v", dns.TypeToString[rrt], d)
		}

		if _, ok := owner.RRtypes[qtype]; ok && len(owner.RRtypes[qtype].RRs) > 0 {
			m.Answer = append(m.Answer, owner.RRtypes[qtype].RRs...)
			m.Ns = append(m.Ns, apex.RRtypes[dns.TypeNS].RRs...)
			glue = zd.FindGlue(apex.RRtypes[dns.TypeNS])
			m.Extra = append(m.Extra, glue.RRs...)
		} else {
			m.Ns = append(m.Ns, apex.RRtypes[dns.TypeSOA].RRs...)
		}
		err := w.WriteMsg(m)
		if err != nil {
			return fmt.Errorf("QueryResponder: unable to WriteMsg() in qtype switch: %w", err)
		}
		return nil

	default:
		// everything we don't want to deal with
		m.MsgHdr.Rcode = dns.RcodeRefused
		m.Ns = append(m.Ns, apex.RRtypes[dns.TypeNS].RRs...)
		glue = zd.FindGlue(apex.RRtypes[dns.TypeNS])
		m.Extra = append(m.Extra, glue.RRs...)
		err := w.WriteMsg(m)
		if err != nil {
			lg.Printf("QueryResponder: unable to WriteMsg() in default statement: %s", err)
		}
	}
	return nil
}

func (td *TemData) QueryResponder(w dns.ResponseWriter, r *dns.Msg, qname string, qtype uint16, lg *log.Logger) error {

	m := new(dns.Msg)
	m.SetReply(r)
	m.MsgHdr.Authoritative = true

	returnNXDOMAIN := func() {
		// return NXDOMAIN
		m.MsgHdr.Rcode = dns.RcodeNameError
		//		m.Ns = append(m.Ns, apex.RRtypes[dns.TypeSOA].RRs...)
		m.Ns = append(m.Ns, dns.RR(&td.Rpz.Axfr.SOA))
		err := w.WriteMsg(m)
		if err != nil {
			log.Printf("QueryResponder: unable to WriteMsg() for NXDOMAIN: %s", err)
		}
	}

	// log.Printf("Zone %s Data: %v", zd.ZoneName, zd.Data)

	//	var err error
	var exist bool
	var tn *tapir.RpzName

	if tn, exist = td.Rpz.Axfr.Data[qname]; exist {
		m.MsgHdr.Rcode = dns.RcodeSuccess
		switch qtype {
		case dns.TypeCNAME, dns.TypeANY:
			m.Answer = append(m.Answer, *tn.RR)
			m.Ns = append(m.Ns, td.Rpz.Axfr.NSrrs...)
		default:
			m.Ns = append(m.Ns, dns.RR(&td.Rpz.Axfr.SOA))
		}
		err := w.WriteMsg(m)
		if err != nil {
			log.Printf("QueryResponder: unable to WriteMsg(): %s", err)
		}
		return nil
	}
	returnNXDOMAIN()
	return nil
}

func (td *TemData) FindZone(qname string) *tapir.ZoneData {
	var tzone string
	labels := strings.Split(qname, ".")
	for i := 1; i < len(labels)-1; i++ {
		tzone = strings.Join(labels[i:], ".")
		log.Printf("FindZone for qname='%s': testing '%s'", qname, tzone)
		if z, ok := td.RpzSources[tzone]; ok {
			log.Printf("Yes, zone=%s for qname=%s", tzone, qname)
			return z
		}
	}
	log.Printf("FindZone: no zone for qname=%s found", qname)
	return nil
}

func (td *TemData) FindZoneNG(qname string) *tapir.ZoneData {
	i := strings.Index(qname, ".")
	for {
		if i == -1 {
			break // done
		}
		log.Printf("FindZone for qname='%s': testing '%s'", qname, qname[i:])
		if z, ok := td.RpzSources[qname[i:]]; ok {
			log.Printf("Yes, zone=%s for qname=%s", qname[i:], qname)
			return z
		}
		i = strings.Index(qname[i:], ".")
	}
	log.Printf("FindZone: no zone for qname=%s found", qname)
	return nil
}
