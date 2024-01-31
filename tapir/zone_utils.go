/*
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tapir

import (
	"fmt"
	"log"
	"strings"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func (zd *ZoneData) Refresh(upstream string, keepfunc func(uint16) bool) (bool, error) {
	verbose := true

	do_transfer, current_serial, upstream_serial, err := zd.DoTransfer(upstream)
	if err != nil {
		log.Printf("Error from DoZoneTransfer(%s): %v", zd.ZoneName, err)
		return false, err
	}

	if do_transfer {
		log.Printf("Refresher: %s: upstream serial has increased: %d-->%d (refresh: %d)",
			zd.ZoneName, current_serial, upstream_serial, zd.SOA.Refresh)
		err = zd.FetchFromUpstream(upstream, current_serial, keepfunc, verbose)
		if err != nil {
			log.Printf("Error from FetchZone(%s, %s): %v", zd.ZoneName, upstream, err)
			return false, err
		}
		return true, nil // zone updated, no error
	}
	log.Printf("Refresher: %s: upstream serial is unchanged: %d (refresh: %d)",
		zd.ZoneName, current_serial, zd.SOA.Refresh)

	return false, nil
}

func (zd *ZoneData) DoTransfer(upstream string) (bool, uint32, uint32, error) {
	var upstream_serial uint32
	var current_serial uint32 = 0

	if zd == nil {
		panic("DoTransfer: zd == nil")
	}

	// log.Printf("%s: known zone, current incoming serial %d", zd.ZoneName, zd.IncomingSerial)
	m := new(dns.Msg)
	m.SetQuestion(zd.ZoneName, dns.TypeSOA)

	r, err := dns.Exchange(m, upstream)
	if err != nil {
		log.Printf("Error from dns.Exchange(%s, SOA): %v", zd.ZoneName, err)
		return false, zd.IncomingSerial, 0, err
	}

	rcode := r.MsgHdr.Rcode
	switch rcode {
	case dns.RcodeRefused, dns.RcodeServerFailure, dns.RcodeNameError:
		return false, current_serial, 0, nil // never mind
	case dns.RcodeSuccess:
		if soa, ok := r.Answer[0].(*dns.SOA); ok {
			// log.Printf("UpstreamSOA: %v", soa.String())
			if soa.Serial <= zd.IncomingSerial {
				// log.Printf("New upstream serial for %s (%d) is <= current serial (%d)",
				// 	zd.ZoneName, soa.Serial, current_serial)
				return false, zd.IncomingSerial, soa.Serial, nil
			}
			// log.Printf("New upstream serial for %s (%d) is > current serial (%d)",
			// 	zd.ZoneName, soa.Serial, current_serial)
			return true, zd.IncomingSerial, soa.Serial, nil
		}
	default:
	}

	return false, zd.IncomingSerial, upstream_serial, nil
}

func (zd *ZoneData) FetchFromUpstream(upstream string, current_serial uint32,
	keepfunc func(uint16) bool, verbose bool) error {

	log.Printf("Transferring zone %s via AXFR from %s\n", zd.ZoneName, upstream)

	zonedata := ZoneData{
		ZoneName: zd.ZoneName,
		ZoneType: zd.ZoneType,
		KeepFunc: zd.KeepFunc,
		Logger:   zd.Logger,
		Verbose:  zd.Verbose,
	}

	_, err := zonedata.ZoneTransferIn(upstream, current_serial, "axfr")
	if err != nil {
		log.Printf("Error from ZoneTransfer(%s): %v", zd.ZoneName, err)
		return err
	}
	log.Printf("FetchFromUpstream: %s has %d apex RRs +  %d RRs",
		zd.ZoneName, zonedata.ApexLen, len(zonedata.FilteredRRs))

	zonedata.Sync()
	if viper.GetString("service.zonemd") == "generate" {
//		zonedata.ZONEMDHashAlgs = []uint8{1}
//		log.Printf("FetchFromUpstream: %s has %d RRs pre ZONEMD generation (%d FilteredRRs)",
//			zd.ZoneName, len(zonedata.RRs), len(zonedata.FilteredRRs))
//		log.Printf("FetchFromUpstream: %s has %d RRs post ZONEMD generation (%d FilteredRRs)",
//			zd.ZoneName, len(zonedata.RRs), len(zonedata.FilteredRRs))
	}

	if viper.GetBool("service.debug") {
		filedir := viper.GetString("log.filedir")
		zonedata.WriteFile(fmt.Sprintf("%s/%s.tapir-em", filedir, zd.ZoneName), log.Default())
	}

	zd.RRs = zonedata.RRs
	zd.Owners = zonedata.Owners
	zd.OwnerIndex = zonedata.OwnerIndex
	zd.FilteredRRs = zonedata.FilteredRRs
	zd.SOA = zonedata.SOA
//	zd.SOA_RRSIG = zonedata.SOA_RRSIG
	zd.IncomingSerial = zd.SOA.Serial
//	zd.ZONEMDrrs = zonedata.ZONEMDrrs
//	zd.ZONEMDHashAlgs = zonedata.ZONEMDHashAlgs
	zd.NSrrs = zonedata.NSrrs
//	zd.TXTrrs = zonedata.TXTrrs
	zd.ApexLen = zonedata.ApexLen
	//	zd.Role = zonedata.Role
	zd.XfrType = zonedata.XfrType
	zd.ZoneType = zonedata.ZoneType
	zd.Data = zonedata.Data

	// XXX: This isn't exactly safe (as there may be multiple ongoing requests),
	// but for the limited test case we have it should work.

	// Zones[zd.ZoneName] = zonedata

	return nil
}

// zd.Sync() is used to ensure that the data in zd.SOA, zd.NSrrs, etc is reflected in the zd.RRs slice.
// Typically used in preparation for a ZONEMD computation or an outbound zone transfer.
func (zd *ZoneData) Sync() error {
	// log.Printf("zd.Sync(): pre sync: there are %d RRs in FilteredRRs and %d RRs in RRs",
	//			    len(zd.FilteredRRs), len(zd.RRs))
	var rrs = []dns.RR{dns.RR(&zd.SOA)}
	rrs = append(rrs, zd.NSrrs...)
//	rrs = append(rrs, zd.ZONEMDrrs...)
//	rrs = append(rrs, zd.TXTrrs...)

	if zd.ZoneType != 3 {
//		rrs = append(rrs, zd.FilteredRRs...)
	} else {
		for _, omap := range zd.Data {
			for _, rrl := range omap.RRtypes {
				rrs = append(rrs, rrl.RRs...)
			}
		}
	}

	zd.RRs = rrs
	// log.Printf("zd.Sync(): post sync: there are %d RRs in FilteredRRs and %d RRs in RRs",
	//			    len(zd.FilteredRRs), len(zd.RRs))
	return nil
}

func (zd *ZoneData) PrintOwners() {
	switch zd.ZoneType {
	case 3:
		fmt.Printf("owner name\tindex\n")
		for i, v := range zd.Owners {
			rrtypes := []string{}
			for t, _ := range v.RRtypes {
				rrtypes = append(rrtypes, dns.TypeToString[t])
			}
			fmt.Printf("%d\t%s\t%s\n", i, v.Name, strings.Join(rrtypes, ", "))
		}
		for k, v := range zd.OwnerIndex {
			fmt.Printf("%s\t%d\n", k, v)
		}
	default:
		zd.Logger.Printf("Sorry, only zonetype=3 for now")
	}
}
