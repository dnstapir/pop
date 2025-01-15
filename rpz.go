/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package main

import (
	"github.com/dnstapir/tapir"
	"github.com/miekg/dns"
)

// XXX: Generating a complete new RPZ zone for output to downstream

// Generate the RPZ output based on the currently loaded sources.
// The output is a tapir.ZoneData, but with only the RRs (i.e. a []dns.RR) populated.
// Output should consist of:
// 1. Walk all denylists:
//    a) remove any allowlisted names
//    b) rest goes straight into output
// 2. Walk all doubtlists:
//    a) remove any already denylisted name
//    b) remove any allowlisted name
//    c) collect complete doubt data on each name
//    d) evalutate the doubt data to make a decision on inclusion or not
// 3. When all names that should be in the output have been collected:
//    a) iterate through the list generating dns.RR and put them in a []dns.RR
//    b) add a header SOA+NS

func (pd *PopData) GenerateRpzAxfr() error {
	var deny = make(map[string]bool, 10000)
	var doubt = make(map[string]*tapir.TapirName, 10000)

	for bname, blist := range pd.Lists["denylist"] {
		pd.Logger.Printf("---> GenerateRpzAxfr: working on denylist %s (%d names)",
			bname, len(blist.Names))
		switch blist.Format {
		case "dawg":
			pd.Logger.Printf("Cannot list DAWG lists. Ignoring denylist %s.", bname)
		case "map":
			for k := range blist.Names {
				// if tapir.GlobalCF.Debug {
				// pd.Logger.Printf("Adding name %s from denylist %s to tentative output.",
				// 	k, bname)
				// }
				// if pd.Allowlisted(k) {
				// pd.Logger.Printf("Denylisted name %s is also allowlisted. Dropped from output.", k)
				// } else {
				// pd.Logger.Printf("Denylisted name %s is not allowlisted. Added to output.", k)
				deny[k] = true
				// }
			}
		}
	}
	pd.DenylistedNames = deny
	pd.Logger.Printf("GenRpzAxfr: There are a total of %d Denylisted names in the sources", len(deny))

	for gname, glist := range pd.Lists["doubtlist"] {
		pd.Logger.Printf("---> GenRpzAxfr: working on doubtlist %s (%d names)",
			gname, len(glist.Names))
		switch glist.Format {
		case "map":
			for k, v := range glist.Names {
				// pd.Logger.Printf("Adding name %s from doubtlist %s to tentative output.", k, gname)
				if _, exists := pd.DenylistedNames[k]; exists {
					// pd.Logger.Printf("Doubtlisted name %s is also denylisted. No need to add twice.", k)
				} else if pd.Allowlisted(k) {
					// pd.Logger.Printf("Doubtlisted name %s is also allowlisted. Dropped from output.", k)
				} else {
					// pd.Logger.Printf("Doubtlisted name %s is not allowlisted. Evalutate inclusion in output.", k)
					action := pd.ComputeRpzAction(k)
					if action == tapir.ALLOWLIST {
						// pd.Logger.Printf("Doubtlisted name %s is not included in output.", k)
					} else {
						// pd.Logger.Printf("Doubtlisted name %s is included in output.", k)

						if _, exists := doubt[k]; exists {
							// pd.Logger.Printf("Doubt name %s already in output. Combining tags and actions.", k)
							tmp := doubt[k]
							tmp.TagMask = doubt[k].TagMask | v.TagMask
							tmp.Action = tmp.Action | v.Action
							doubt[k] = tmp
						} else {
							doubt[k] = &v
						}
					}
				}
			}
		default:
			pd.Logger.Printf("*** Error: Doubtlist %s has unknown format \"%s\".", gname, glist.Format)
		}
	}
	pd.DoubtlistedNames = doubt
	pd.Logger.Printf("GenRpzAxfr: There are a total of %d doubtlisted names in the sources", len(doubt))

	// newaxfrdata := []*tapir.RpzName{}
	// pd.Rpz.RpzMap = map[string]*tapir.RpzName{}
	for name := range pd.DenylistedNames {
		cname := new(dns.CNAME)
		cname.Hdr = dns.RR_Header{
			Name:   name + pd.Rpz.ZoneName,
			Rrtype: dns.TypeCNAME,
			Class:  dns.ClassINET,
			Ttl:    3600,
		}
		cname.Target = tapir.ActionToCNAMETarget[pd.Policy.DenylistAction]
		rr := dns.RR(cname)

		rpzn := tapir.RpzName{
			Name:   name,
			RR:     &rr,
			Action: pd.Policy.DenylistAction,
		}
		// newaxfrdata = append(newaxfrdata, &rpzn)
		// pd.Rpz.RpzMap[nname+pd.Rpz.ZoneName] = &rpzn
		pd.mu.Lock()
		pd.Rpz.Axfr.Data[name+pd.Rpz.ZoneName] = &rpzn
		pd.mu.Unlock()
	}

	for name, v := range pd.DoubtlistedNames {
		rpzaction := ApplyDoubtPolicy(name, v)

		if rpzaction != "" {
			cname := new(dns.CNAME)
			cname.Hdr = dns.RR_Header{
				Name:     name + pd.Rpz.ZoneName,
				Rrtype:   dns.TypeCNAME,
				Class:    dns.ClassINET,
				Ttl:      3600,
				Rdlength: 1,
			}
			cname.Target = rpzaction // XXX: wrong
			rr := dns.RR(cname)

			rpzn := tapir.RpzName{
				Name:   name,
				RR:     &rr,
				Action: pd.Policy.DenylistAction, // XXX: naa
			}
			// newaxfrdata = append(newaxfrdata, &rpzn)
			// pd.Rpz.RpzMap[name+pd.Rpz.ZoneName] = &rpzn
			pd.mu.Lock()
			pd.Rpz.Axfr.Data[name+pd.Rpz.ZoneName] = &rpzn
			pd.mu.Unlock()
		}
	}

	//	pd.Rpz.Axfr.Data = pd.Rpz.RpzMap
	pd.Logger.Printf("GenerateRpzAxfrData: put %d RRs in %s",
		len(pd.Rpz.Axfr.Data), pd.Rpz.ZoneName)
	err := pd.NotifyDownstreams()
	return err
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

func (pd *PopData) GenerateRpzIxfr(data *tapir.TapirMsg) (RpzIxfr, error) {

	var removeData, addData []*tapir.RpzName
	pd.Policy.Logger.Printf("GenerateRpzIxfr: %d removed names and %d added names", len(data.Removed), len(data.Added))
	for _, tn := range data.Removed {
		tn.Name = dns.Fqdn(tn.Name)
		pd.Policy.Logger.Printf("GenerateRpzIxfr: evaluating removed name %s", tn.Name)
		if cur, exist := pd.Rpz.Axfr.Data[tn.Name]; exist {
			newAction := pd.ComputeRpzAction(tn.Name)
			oldAction := cur.Action
			if newAction != oldAction {
				if pd.Debug {
					pd.Policy.Logger.Printf("GenRpzIxfr[DEL]: %s: oldaction(%s) != newaction(%s): -->DELETE",
						tn.Name,
						tapir.ActionToString[oldAction],
						tapir.ActionToString[newAction])
				}
				removeData = append(removeData, cur)

				if newAction != tapir.ALLOWLIST {
					cname := new(dns.CNAME)
					cname.Hdr = dns.RR_Header{
						Name:     tn.Name + pd.Rpz.ZoneName,
						Rrtype:   dns.TypeCNAME,
						Class:    dns.ClassINET,
						Ttl:      3600,
						Rdlength: 1,
					}
					cname.Target = tapir.ActionToCNAMETarget[newAction]
					rr := dns.RR(cname)

					addData = append(addData, &tapir.RpzName{
						Name:   tn.Name,
						RR:     &rr,
						Action: newAction,
					})
				}
			} else {
				if pd.Debug {
					pd.Policy.Logger.Printf("GenRpzIxfr[DEL]: name %s present in previous policy with same action: -->NO CHANGE", tn.Name)
				}
			}
		} else {
			if pd.Debug {
				pd.Policy.Logger.Printf("GenRpzIxfr[DEL]: name %s not present in previous policy, still not included: -->NO CHANGE", tn.Name)
			}
		}
	}

	var addtorpz bool
	for _, tn := range data.Added {
		tn.Name = dns.Fqdn(tn.Name)
		pd.Policy.Logger.Printf("GenerateRpzIxfr: evaluating added name %s", tn.Name)
		addtorpz = false
		newAction := pd.ComputeRpzAction(tn.Name)
		if cur, exist := pd.Rpz.Axfr.Data[tn.Name]; exist {
			if newAction == tapir.ALLOWLIST {
				// delete from rpz
				if pd.Debug {
					pd.Policy.Logger.Printf("GenRpzIxfr[ADD]: name %s already exists in rpz, new action is ALLOWLIST: -->DELETE", tn.Name)
				}
				removeData = append(removeData, cur)
			} else {
				if cur.Action != newAction {
					// change, delete old rule, add new
					removeData = append(removeData, cur)
					addtorpz = true
					if pd.Debug {
						pd.Policy.Logger.Printf("GenRpzIxfr[ADD]: name %s present in rpz, newaction(%s) != oldaction(%s): -->ADD",
							tn.Name, tapir.ActionToString[newAction],
							tapir.ActionToString[cur.Action])
					}
				}
			}
		} else {
			// name doesn't exist in current rpz, what is the action?
			if newAction != tapir.ALLOWLIST {
				// add it
				if pd.Debug {
					pd.Policy.Logger.Printf("GenRpzIxfr[ADD]: name %s NOT present in rpz, newaction(%s) != ALLOWLIST: -->ADD",
						tn.Name, tapir.ActionToString[newAction])
				}
				addtorpz = true
			}
		}
		if addtorpz {
			cname := new(dns.CNAME)
			cname.Hdr = dns.RR_Header{
				Name:     tn.Name + pd.Rpz.ZoneName,
				Rrtype:   dns.TypeCNAME,
				Class:    dns.ClassINET,
				Ttl:      3600,
				Rdlength: 1,
			}
			cname.Target = tapir.ActionToCNAMETarget[newAction]
			rr := dns.RR(cname)

			addData = append(addData, &tapir.RpzName{
				Name:   tn.Name,
				RR:     &rr,
				Action: newAction,
			})
		}
	}

	if len(removeData) != 0 || len(addData) != 0 {
		curserial := pd.Rpz.CurrentSerial
		newserial := curserial + 1 // XXX: not dealing with serial wraps
		thisixfr := RpzIxfr{
			FromSerial: curserial,
			ToSerial:   newserial,
			Removed:    removeData,
			Added:      addData,
		}
		pd.Rpz.IxfrChain = append(pd.Rpz.IxfrChain, thisixfr)
		pd.Rpz.CurrentSerial = newserial
		if pd.Verbose {
			pd.Policy.Logger.Printf("GenRpzIxfr: added new IXFR (serial from %d to %d) to chain. Chain has %d IXFRs",
				curserial, newserial, len(pd.Rpz.IxfrChain))
		}
		return thisixfr, nil
	}

	pd.Policy.Logger.Printf("GenRpzIxfr: no changes in RPZ policy, no new IXFR")
	return RpzIxfr{}, nil
}
