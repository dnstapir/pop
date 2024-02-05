/*
 * Copyright (c) DNS TAPIR
 */

package main

import (
	"github.com/dnstapir/tapir"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
	"log"
	"strings"
)

// XXX: Generating a complete new RPZ zone for output to downstream

// Note that it is not possible to generate the output until all sources have been parsed.

// func (wbg *tapir.WBGlist) List() ([]string, error) {
//      switch wbg.Format {
//      case "rpz":
// //     	  data, exist := RpzZones[wbg.Zone]
// //	  if !exist {
// //	     log.Printf("No data found for RPZ zone \"%s\". Ignoring.", wbg.Zone)
// //	  }
//
//      default:
// 	log.Printf("wbg.List(): Format=%s is not handled yet. Only supported format is \"rpz\"", wbg.Format)
//      }
//      return []string{}, nil
// }

// Generate the RPZ output based on the currently loaded sources.
// The output is a tapir.ZoneData, but with only the RRs (i.e. a []dns.RR) populated.
// Output should consist of:
// 1. Walk all blacklists:
//    a) remove any whitelisted names
//    b) rest goes straight into output
// 2. Walk all greylists:
//    a) remove any already blacklisted name
//    b) remove any whitelisted name
//    c) collect complete grey data on each name
//    d) evalutate the grey data to make a decision on inclusion or not
// 3. When all names that should be in the output have been collected:
//    a) iterate through the list generating dns.RR and put them in a []dns.RR
//    b) add a header SOA+NS

func (td *TemData) GenerateRpzOutput() error {
	rpzzone := viper.GetString("output.rpz.zonename")
	var black = make(map[string]bool, 10000)
	var grey = make(map[string]*tapir.TapirName, 10000)

	//    for bname, blist := range td.Blacklists {
	for bname, blist := range td.Lists["blacklist"] {
		td.Logger.Printf("---> GenerateRpzOutput: working on blacklist %s", bname)
		switch blist.Format {
		case "dawg":
			td.Logger.Printf("Cannot list DAWG lists. Ignoring blacklist %s.", bname)
		case "map":
			for k, _ := range blist.Names {
				td.Logger.Printf("Adding name %s from blacklist %s to tentative output.", k, bname)
				if td.Whitelisted(k) {
					td.Logger.Printf("Blacklisted name %s is also whitelisted. Dropped from output.", k)
				} else {
					td.Logger.Printf("Blacklisted name %s is not whitelisted. Added to output.", k)
					black[k] = true
				}
			}
		}
	}
	td.BlacklistedNames = black
	td.Logger.Printf("Complete set of blacklisted names: %v", black)

	//     for gname, glist := range td.Greylists {
	for gname, glist := range td.Lists["greylist"] {
		td.Logger.Printf("---> GenerateRpzOutput: working on greylist %s", gname)
		switch glist.Format {
		case "map":
			for k, v := range glist.Names {
				td.Logger.Printf("Adding name %s from greylist %s to tentative output.", k, gname)
				if _, exists := td.BlacklistedNames[k]; exists {
					td.Logger.Printf("Greylisted name %s is also blacklisted. No need to add twice.", k)
				} else if td.Whitelisted(k) {
					td.Logger.Printf("Greylisted name %s is also whitelisted. Dropped from output.", k)
				} else {
					td.Logger.Printf("Greylisted name %s is not whitelisted. Added to output.", k)
					if _, exists := grey[k]; exists {
						td.Logger.Printf("Grey name %s already in output. Combining tags and actions.", k)
						tmp := grey[k]
						tmp.Tagmask = grey[k].Tagmask | v.Tagmask
						tmp.Action = tmp.Action | v.Action
						grey[k] = tmp
					} else {
						grey[k] = &v
					}
				}
			}
		default:
			td.Logger.Printf("*** Error: Greylist %s has unknown format \"%s\".", gname, glist.Format)
		}
	}
	td.GreylistedNames = grey

	td.RpzOutput = []dns.RR{}
	for n, _ := range td.BlacklistedNames {
		cname := new(dns.CNAME)
		cname.Hdr = dns.RR_Header{
			Name:   n + rpzzone,
			Rrtype: dns.TypeCNAME,
			Class:  dns.ClassINET,
			Ttl:    3600,
		}
		cname.Target = "." // NXDOMAIN

		td.RpzOutput = append(td.RpzOutput, cname)
	}

	for n, v := range td.GreylistedNames {
		rpzaction := ApplyGreyPolicy(n, v)

		if rpzaction != "" {
			cname := new(dns.CNAME)
			cname.Hdr = dns.RR_Header{
				Name:     n + rpzzone,
				Rrtype:   dns.TypeCNAME,
				Class:    dns.ClassINET,
				Ttl:      3600,
				Rdlength: 1,
			}
			cname.Target = rpzaction
			td.RpzOutput = append(td.RpzOutput, cname)
		}
	}
	td.RpzZones[viper.GetString("output.rpz.zonename")].RRs = td.RpzOutput
	td.Logger.Printf("GenerateRpzOutput: put %d RRs in td.RpzZones[%s].RRs",
		len(td.RpzOutput), viper.GetString("output.rpz.zonename"))
	return nil
}

// Decision to block a greylisted name:
// 1. More than N tags present
// 2. Name is present in more than M sources
// 3. Name 

func ApplyGreyPolicy(name string, v *tapir.TapirName) string {
	var rpzaction string
	if v.HasAction(tapir.NXDOMAIN) {
		rpzaction = "."
	} else if v.HasAction(tapir.NODATA) {
		rpzaction = "*."
	} else if v.HasAction(tapir.DROP) {
		rpzaction = "rpz-drop."
	} else if v.Tagmask != 0 {
		log.Printf("there are tags")
		rpzaction = "rpz-drop."
	}

	return rpzaction
}

func (td *TemData) BootstrapRpzOutput() error {
	apextmpl := `
$TTL 3600
${ZONE}		IN	SOA	mname. hostmaster.dnstapir.se. (
				123
				900
				300
				86400
				300 )
${ZONE}		IN	NS	ns1.${ZONE}
${ZONE}		IN	NS	ns2.${ZONE}
ns1.${ZONE}	IN	A	127.0.0.1
ns2.${ZONE}	IN	AAAA	::1`

	rpzzone := viper.GetString("output.rpz.zonename")
	apex := strings.Replace(apextmpl, "${ZONE}", rpzzone, -1)

	zd := tapir.ZoneData{
		ZoneName: rpzzone,
		ZoneType: tapir.RpzZone,
		Logger:   log.Default(),
		Verbose:  true,
		Debug:    true,
	}

	serial, err := zd.ReadZoneString(apex)
	if err != nil {
		td.Logger.Printf("Error from ReadZoneString(): %v", err)
	}
	zd.IncomingSerial = serial

	td.RpzZones[rpzzone] = &zd // XXX: This is not thread safe
	td.RpzZone = &zd
	return nil
}
