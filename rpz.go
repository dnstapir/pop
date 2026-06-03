/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package main

import (
	"fmt"

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

	// Collect the candidate set of doubtlisted names. A name that is also
	// denylisted is already handled by the denylist; allowlisted names are
	// excluded by decide() below (allowlist is absolute), so the per-name
	// decision is deferred to the emission loop where decide() is the single
	// authority on both inclusion and action.
	for gname, glist := range pd.Lists["doubtlist"] {
		pd.Logger.Printf("---> GenRpzAxfr: working on doubtlist %s (%d names)",
			gname, len(glist.Names))
		switch glist.Format {
		case "map":
			for k, v := range glist.Names {
				if _, exists := pd.DenylistedNames[k]; exists {
					continue // already covered by the denylist
				}
				if existing, exists := doubt[k]; exists {
					// Same name in several doubtlists: merge tags/actions.
					// Order-independent because OR is commutative.
					existing.TagMask |= v.TagMask
					existing.Action |= v.Action
				} else {
					v := v // copy; don't alias the map value
					doubt[k] = &v
				}
			}
		default:
			pd.Logger.Printf("*** Error: Doubtlist %s has unknown format \"%s\".", gname, glist.Format)
		}
	}
	pd.DoubtlistedNames = doubt
	pd.Logger.Printf("GenRpzAxfr: There are a total of %d candidate doubtlisted names in the sources", len(doubt))

	// Build a fresh Data map locally, then publish it as a new snapshot. This
	// is the full-rebuild path (startup / forced regen); it resets the IXFR
	// chain, since a full AXFR regen invalidates the incremental deltas
	// (downstreams that ask for IXFR will fall back to AXFR, which is correct).
	data := make(map[string]*tapir.RpzName, len(pd.DenylistedNames)+len(pd.DoubtlistedNames))

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
		data[name+pd.Rpz.ZoneName] = &tapir.RpzName{
			Name:   name,
			RR:     &rr,
			Action: pd.Policy.DenylistAction,
		}
	}

	for name := range pd.DoubtlistedNames {
		// decide() is the single source of truth: it enforces allowlist
		// precedence and applies the (provisional) doubtlist policy. A name
		// that does not earn an action passes through and is not emitted.
		action, _ := pd.decide(name)
		if action == tapir.ALLOWLIST {
			continue
		}

		cname := new(dns.CNAME)
		cname.Hdr = dns.RR_Header{
			Name:     name + pd.Rpz.ZoneName,
			Rrtype:   dns.TypeCNAME,
			Class:    dns.ClassINET,
			Ttl:      3600,
			Rdlength: 1,
		}
		cname.Target = tapir.ActionToCNAMETarget[action]
		rr := dns.RR(cname)
		data[name+pd.Rpz.ZoneName] = &tapir.RpzName{
			Name:   name,
			RR:     &rr,
			Action: action,
		}
	}

	// Publish the new full zone. Carry SOA/NSrrs forward from the current
	// snapshot (set up by BootstrapRpzOutput); bump nothing here — the serial
	// is owned by pd.Rpz.CurrentSerial.
	old := pd.snapshot.Load()
	snap := &ZoneSnapshot{
		ZoneName:  pd.Rpz.ZoneName,
		Serial:    pd.Rpz.CurrentSerial,
		Data:      data,
		IxfrChain: nil, // full rebuild invalidates the delta chain
	}
	if old != nil {
		snap.SOA = old.SOA
		snap.NSrrs = old.NSrrs
	}
	snap.SOA.Serial = pd.Rpz.CurrentSerial
	pd.snapshot.Store(snap)

	pd.Logger.Printf("GenerateRpzAxfr: published snapshot with %d RRs in %s (serial %d)",
		len(data), pd.Rpz.ZoneName, snap.Serial)
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

	// Read the current served zone from the snapshot. The delta is computed
	// against snap.Data and a NEW snapshot is published at the end; snap is
	// never mutated.
	snap := pd.snapshot.Load()
	if snap == nil {
		return RpzIxfr{}, fmt.Errorf("GenerateRpzIxfr: no snapshot published yet")
	}

	// Data is keyed by the fully-qualified owner name (name + ZoneName) — the
	// same key a DNS query uses (see QueryResponder) and the same key the full
	// AXFR build uses. (Previously the incremental path keyed by bare name,
	// which never matched the AXFR-built entries — a latent bug now fixed by
	// keying consistently here.)
	key := func(name string) string { return dns.Fqdn(name) + pd.Rpz.ZoneName }

	var removeData, addData []*tapir.RpzName
	pd.Policy.Logger.Printf("GenerateRpzIxfr: %d removed names and %d added names", len(data.Removed), len(data.Added))
	for _, tn := range data.Removed {
		tn.Name = dns.Fqdn(tn.Name)
		pd.Policy.Logger.Printf("GenerateRpzIxfr: evaluating removed name %s", tn.Name)
		if cur, exist := snap.Data[key(tn.Name)]; exist {
			newAction, _ := pd.decide(tn.Name)
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
		newAction, _ := pd.decide(tn.Name)
		if cur, exist := snap.Data[key(tn.Name)]; exist {
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

	if len(removeData) == 0 && len(addData) == 0 {
		pd.Policy.Logger.Printf("GenRpzIxfr: no changes in RPZ policy, no new IXFR")
		return RpzIxfr{}, nil
	}

	curserial := pd.Rpz.CurrentSerial
	newserial := curserial + 1 // XXX: serial wrap handled separately (see #166)
	thisixfr := RpzIxfr{
		FromSerial: curserial,
		ToSerial:   newserial,
		Removed:    removeData,
		Added:      addData,
	}

	// Build the next snapshot: a fresh copy of the current Data with the delta
	// applied, plus a fresh IXFR chain (old + this delta, bounded), then
	// publish atomically. The old snapshot is never mutated.
	newData := make(map[string]*tapir.RpzName, len(snap.Data)+len(addData))
	// Shallow copy: unchanged entries share the *RpzName pointer with the old
	// snapshot. This is safe ONLY because a published *RpzName is never mutated
	// in place — changes always produce a NEW *RpzName (see the add loops above
	// and GenerateRpzAxfr). Do not introduce in-place edits of RpzName fields,
	// or snapshots would alias mutable state and break immutability.
	for k, v := range snap.Data {
		newData[k] = v
	}
	for _, rpzn := range removeData {
		delete(newData, key(rpzn.Name))
	}
	for _, rpzn := range addData {
		newData[key(rpzn.Name)] = rpzn
	}

	// Fresh chain slice (never append onto the old snapshot's backing array),
	// oldest-first. Prune deltas all tracked downstreams have moved past, then
	// hard-bound to the most recent maxIxfrChain as a backstop.
	newChain := make([]RpzIxfr, 0, len(snap.IxfrChain)+1)
	newChain = append(newChain, snap.IxfrChain...)
	newChain = append(newChain, thisixfr)
	low, have := pd.downstreamSerials.lowest()
	newChain = pruneIxfrChain(newChain, low, have)
	if len(newChain) > maxIxfrChain {
		newChain = newChain[len(newChain)-maxIxfrChain:]
	}

	newsnap := &ZoneSnapshot{
		ZoneName:  snap.ZoneName,
		Serial:    newserial,
		SOA:       snap.SOA,
		NSrrs:     snap.NSrrs,
		Data:      newData,
		IxfrChain: newChain,
	}
	newsnap.SOA.Serial = newserial
	pd.snapshot.Store(newsnap)
	pd.Rpz.CurrentSerial = newserial

	if pd.Verbose {
		pd.Policy.Logger.Printf("GenRpzIxfr: published snapshot serial %d->%d (%d del, %d add); chain has %d IXFRs",
			curserial, newserial, len(removeData), len(addData), len(newChain))
	}
	return thisixfr, nil
}
