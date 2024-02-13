/*
 * Copyright (c) DNS TAPIR
 */

package main

import (
	"github.com/dnstapir/tapir"
	"github.com/miekg/dns"
	"log"
)

// XXX: Generating a complete new RPZ zone for output to downstream

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

func (td *TemData) GenerateRpzAxfr() error {
	var black = make(map[string]bool, 10000)
	var grey = make(map[string]*tapir.TapirName, 10000)

	for bname, blist := range td.Lists["blacklist"] {
		td.Logger.Printf("---> GenerateRpzAxfr: working on blacklist %s (%d names)",
				       bname, len(blist.Names))
		switch blist.Format {
		case "dawg":
			td.Logger.Printf("Cannot list DAWG lists. Ignoring blacklist %s.", bname)
		case "map":
			for k, _ := range blist.Names {
				if tapir.GlobalCF.Debug {
					td.Logger.Printf("Adding name %s from blacklist %s to tentative output.",
								 k, bname)
				}
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
	td.Logger.Printf("GenRpzAxfr: There are a total of %d blacklisted names in the sources", len(black))

	for gname, glist := range td.Lists["greylist"] {
		td.Logger.Printf("---> GenRpzAxfr: working on greylist %s (%d names)",
			gname, len(glist.Names))
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
						tmp.TagMask = grey[k].TagMask | v.TagMask
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
	td.Logger.Printf("GenRpzAxfr: There are a total of %d greylisted names in the sources", len(grey))

	newaxfrdata := []*tapir.RpzName{}
	td.Rpz.RpzMap = map[string]*tapir.RpzName{}
	for n, _ := range td.BlacklistedNames {
		cname := new(dns.CNAME)
		cname.Hdr = dns.RR_Header{
			Name:   n + td.Rpz.ZoneName,
			Rrtype: dns.TypeCNAME,
			Class:  dns.ClassINET,
			Ttl:    3600,
		}
		cname.Target = tapir.ActionToCNAMETarget[td.Policy.BlacklistAction]
		rr := dns.RR(cname)

		rpzn := tapir.RpzName{
			Name:   n,
			RR:     &rr,
			Action: td.Policy.BlacklistAction,
		}
		newaxfrdata = append(newaxfrdata, &rpzn)
		td.Rpz.RpzMap[n+td.Rpz.ZoneName] = &rpzn
	}

	for n, v := range td.GreylistedNames {
		rpzaction := ApplyGreyPolicy(n, v)

		if rpzaction != "" {
			cname := new(dns.CNAME)
			cname.Hdr = dns.RR_Header{
				Name:     n + td.Rpz.ZoneName,
				Rrtype:   dns.TypeCNAME,
				Class:    dns.ClassINET,
				Ttl:      3600,
				Rdlength: 1,
			}
			cname.Target = rpzaction // XXX: wrong
			rr := dns.RR(cname)

			rpzn := tapir.RpzName{
				Name:   n,
				RR:     &rr,
				Action: td.Policy.BlacklistAction,
			}
			newaxfrdata = append(newaxfrdata, &rpzn)
			td.Rpz.RpzMap[n+td.Rpz.ZoneName] = &rpzn
		}
	}
	//	td.RpzZones[viper.GetString("output.rpz.zonename")].RRs = td.RpzOutput
	td.Rpz.Axfr.Data = td.Rpz.RpzMap
	td.Logger.Printf("GenerateRpzAxfrData: put %d RRs in td.RpzZones[%s].RRs",
		len(td.Rpz.Axfr.Data), td.Rpz.ZoneName)
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
	} else if v.TagMask != 0 {
		log.Printf("there are tags")
		rpzaction = "rpz-drop."
	}

	return rpzaction
}

func (td *TemData) ComputeRpzPolicy(name string) tapir.Action {
	if td.Whitelisted(name) {
		return td.Policy.WhitelistAction
	} else if td.Blacklisted(name) {
		return td.Policy.BlacklistAction
	} else if td.Greylisted(name) {
		return td.Policy.BlacklistAction // This is not complete, only a placeholder for now.
	}
	return tapir.WHITELIST
}

// Generate the RPZ representation of the names in the TapirMsg combined with the currently loaded sources.
// The output is a []dns.RR with the additions and removals, but without the IXFR SOA serial magic.
// Algorithm:
// 1. For each name that is removed in the update:
//    a) is the name NOT present in current RPZ?
//          => do nothing [DONE]
//    b) if name is present in current RPZ:
//          - do a policy evaluation of the name. [DONE]
//          - is the name present in current RPZ with a different policy/action:
//            => DELETE current + ADD new [DONE]
//          - is the name present in current RPZ with same policy/action?
//            => do nothing [DONE]
//
// 2. For each name that is added in the update:
//    a) do a policy evaluation of the name. the result is either "has RPZ policy or does not have RPZ policy"
//    b) if "no RPZ":
//          - is the name present in current output?
//              => DELETE current
//    b) if "RPZ":
//          - is the name NOT present in current RPZ?
//              => ADD new
//          - is the name present in current RPZ with different policy/action:
//              => DELETE current + ADD new
//          - is the name present in current RPZ with same policy/action:
//              => do nothing

func (td *TemData) GenerateRpzIxfr(data *tapir.TapirMsg) (RpzIxfr, error) {

	var removedata, adddata []*tapir.RpzName
	for _, tn := range data.Removed {
//		if cur, exist := td.Rpz.RpzMap[tn.Name]; exist {
		if cur, exist := td.Rpz.Axfr.Data[tn.Name]; exist {
			newaction := td.ComputeRpzPolicy(tn.Name)
			oldaction := cur.Action
			if newaction != oldaction {
				if td.Debug {
					td.Logger.Printf("GenRpzIxfr[DEL]: %s: oldaction(%s) != newaction(%s)",
						tn.Name,
						tapir.ActionToString[oldaction],
						tapir.ActionToString[newaction])
				}
				removedata = append(removedata, cur)

				if newaction != tapir.WHITELIST {
				cname := new(dns.CNAME)
				cname.Hdr = dns.RR_Header{
					Name:     tn.Name + td.Rpz.ZoneName,
					Rrtype:   dns.TypeCNAME,
					Class:    dns.ClassINET,
					Ttl:      3600,
					Rdlength: 1,
				}
				cname.Target = tapir.ActionToCNAMETarget[newaction]
				rr := dns.RR(cname)

				adddata = append(adddata, &tapir.RpzName{
					Name:   tn.Name,
					RR:     &rr,
					Action: newaction,
				})
				}
			} else {
				if td.Debug {
					td.Logger.Printf("GenRpzIxfr[DEL]: name %s present in previous policy with same action, no change", tn.Name)
				}
			}
		} else {
			if td.Debug {
				td.Logger.Printf("GenRpzIxfr[DEL]: name %s not present in previous policy, still not included", tn.Name)
			}
		}
	}

	var addtorpz bool
	for _, tn := range data.Added {
		addtorpz = false
		newaction := td.ComputeRpzPolicy(tn.Name)
//		if cur, exist := td.Rpz.RpzMap[tn.Name]; exist {
		if cur, exist := td.Rpz.Axfr.Data[tn.Name]; exist {
			if newaction == tapir.WHITELIST {
				// delete from rpz
				if td.Debug {
					td.Logger.Printf("GenRpzIxfr[ADD]: name %s already exists in rpz, new action is WHITELIST, remove name", tn.Name)
				}
				removedata = append(removedata, cur)
			} else {
				if cur.Action != newaction {
					// change, delete old rule, add new
					removedata = append(removedata, cur)
					addtorpz = true
					if td.Debug {
						td.Logger.Printf("GenRpzIxfr[ADD]: name %s present in rpz, newaction(%s) != oldaction(%s)",
							tn.Name, tapir.ActionToString[newaction],
							tapir.ActionToString[cur.Action])
					}
				} else {
					// no change, do nothing
				}
			}
		} else {
			// name doesn't exist in current rpz, what is the action?
			if newaction != tapir.WHITELIST {
				// add it
				if td.Debug {
					td.Logger.Printf("GenRpzIxfr[ADD]: name %s NOT present in rpz, newaction(%s) != WHITELIST: ADD",
						tn.Name, tapir.ActionToString[newaction])
				}
				addtorpz = true
			}
		}
		if addtorpz {
			cname := new(dns.CNAME)
			cname.Hdr = dns.RR_Header{
				Name:     tn.Name + td.Rpz.ZoneName,
				Rrtype:   dns.TypeCNAME,
				Class:    dns.ClassINET,
				Ttl:      3600,
				Rdlength: 1,
			}
			cname.Target = tapir.ActionToCNAMETarget[newaction]
			rr := dns.RR(cname)

			adddata = append(adddata, &tapir.RpzName{
				Name:   tn.Name,
				RR:     &rr,
				Action: newaction,
			})
		}
	}

	if len(removedata) != 0 || len(adddata) != 0 {
		curserial := td.Rpz.CurrentSerial
		newserial := curserial + 1 // XXX: not dealing with serial wraps
		thisixfr := RpzIxfr{
				FromSerial: curserial,
				ToSerial:   newserial,
				Removed:    removedata,
				Added:      adddata,
   			    }
		td.Rpz.IxfrChain = append(td.Rpz.IxfrChain, thisixfr)
		td.Rpz.CurrentSerial = newserial
		if td.Verbose {
		   td.Logger.Printf("GenRpzIxfr: added new IXFR (from: %d to: %d) to chain. Chain has %d IXFRs",
		   				 curserial, newserial, len(td.Rpz.IxfrChain))
		}
		return thisixfr, nil
	}

	return RpzIxfr{}, nil
}

