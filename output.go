/*
 * Copyright (c) DNS TAPIR
 */

package main

import (
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/dnstapir/tapir"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

type TemOutput struct {
	Active      bool
	Name        string
	Description string
	Type        string // listtype, usually "greylist"
	Format      string // i.e. rpz, etc
	Downstream  string
}

type TemOutputs struct {
	Outputs map[string]TemOutput
}

func (td *TemData) ParseOutputs() error {
	td.Logger.Printf("ParseOutputs: reading outputs from %s", tapir.TemOutputsCfgFile)
	cfgdata, err := os.ReadFile(tapir.TemOutputsCfgFile)
	if err != nil {
		log.Fatalf("Error from ReadFile(%s): %v", tapir.TemOutputsCfgFile, err)
	}

	var oconf = TemOutputs{
		Outputs: make(map[string]TemOutput),
	}

	// td.Logger.Printf("ParseOutputs: config read: %s", cfgdata)
	err = yaml.Unmarshal(cfgdata, &oconf)
	if err != nil {
		log.Fatalf("Error from yaml.Unmarshal(OutputsConfig): %v", err)
	}

	td.Logger.Printf("ParseOutputs: found %d outputs", len(oconf.Outputs))
	for name, v := range oconf.Outputs {
		td.Logger.Printf("ParseOutputs: output %s: type %s, format %s, downstream %s",
			name, v.Type, v.Format, v.Downstream)
	}

	for name, output := range oconf.Outputs {
		if output.Active && strings.ToLower(output.Format) == "rpz" {
			td.Logger.Printf("Output %s: Adding RPZ downstream %s to list of Notify receivers", name, output.Downstream)
			td.Downstreams.Downstreams = append(td.Downstreams.Downstreams, output.Downstream)
		}
	}
	// Read the current value of td.Downstreams.Serial from a text file
	serialFile := viper.GetString("output.rpz.serialcache")

	if serialFile != "" {
		serialData, err := os.ReadFile(serialFile)
		if err != nil {
			td.Logger.Printf("Error reading serial from file %s: %v", serialFile, err)
			td.Downstreams.Serial = 1
		} else {
			tmp := strings.Replace(string(serialData), "\n", "", -1)
			serial, err := strconv.Atoi(tmp)
			if err != nil {
				td.Logger.Printf("Error converting serial data to integer: %v", err)
			} else {
				td.Downstreams.Serial = uint32(serial)
				td.Logger.Printf("Loaded serial %d from file %s", td.Downstreams.Serial, serialFile)
			}
		}
	} else {
		td.Logger.Printf("No serial cache file specified, starting serial at 1")
		td.Downstreams.Serial = 1
	}
	td.Rpz.CurrentSerial = td.Downstreams.Serial
	return nil
}

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
					// td.Logger.Printf("Adding name %s from blacklist %s to tentative output.",
					// 	k, bname)
				}
				if td.Whitelisted(k) {
					// td.Logger.Printf("Blacklisted name %s is also whitelisted. Dropped from output.", k)
				} else {
					// td.Logger.Printf("Blacklisted name %s is not whitelisted. Added to output.", k)
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
					td.Logger.Printf("Greylisted name %s is not whitelisted. Evalutate inclusion in output.", k)
					action := td.ComputeRpzAction(k)
					if action == tapir.WHITELIST {
						td.Logger.Printf("Greylisted name %s is not included in output.", k)
					} else {
						td.Logger.Printf("Greylisted name %s is included in output.", k)

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
			}
		default:
			td.Logger.Printf("*** Error: Greylist %s has unknown format \"%s\".", gname, glist.Format)
		}
	}
	td.GreylistedNames = grey
	td.Logger.Printf("GenRpzAxfr: There are a total of %d greylisted names in the sources", len(grey))

	newaxfrdata := []*tapir.RpzName{}
	td.Rpz.RpzMap = map[string]*tapir.RpzName{}
	for name, _ := range td.BlacklistedNames {
		cname := new(dns.CNAME)
		cname.Hdr = dns.RR_Header{
			Name:   name + td.Rpz.ZoneName,
			Rrtype: dns.TypeCNAME,
			Class:  dns.ClassINET,
			Ttl:    3600,
		}
		cname.Target = tapir.ActionToCNAMETarget[td.Policy.BlacklistAction]
		rr := dns.RR(cname)

		rpzn := tapir.RpzName{
			Name:   name,
			RR:     &rr,
			Action: td.Policy.BlacklistAction,
		}
		newaxfrdata = append(newaxfrdata, &rpzn)
		// td.Rpz.RpzMap[nname+td.Rpz.ZoneName] = &rpzn
		td.mu.Lock()
		td.Rpz.Axfr.Data[name+td.Rpz.ZoneName] = &rpzn
		td.mu.Unlock()
	}

	for name, v := range td.GreylistedNames {
		rpzaction := ApplyGreyPolicy(name, v)

		if rpzaction != "" {
			cname := new(dns.CNAME)
			cname.Hdr = dns.RR_Header{
				Name:     name + td.Rpz.ZoneName,
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
				Action: td.Policy.BlacklistAction, // XXX: naa
			}
			newaxfrdata = append(newaxfrdata, &rpzn)
			// td.Rpz.RpzMap[name+td.Rpz.ZoneName] = &rpzn
			td.mu.Lock()
			td.Rpz.Axfr.Data[name+td.Rpz.ZoneName] = &rpzn
			td.mu.Unlock()
		}
	}

	//	td.Rpz.Axfr.Data = td.Rpz.RpzMap
	td.Logger.Printf("GenerateRpzAxfrData: put %d RRs in %s",
		len(td.Rpz.Axfr.Data), td.Rpz.ZoneName)
	err := td.NotifyDownstreams()
	return err
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

// Note: we onlygethere when we know that this name is only greylisted
// so no need tocheckfor white- or blacklisting
func (td *TemData) ComputeRpzGreylistAction(name string) tapir.Action {

	var greyHits = map[string]*tapir.TapirName{}
	for listname, list := range td.Lists["greylist"] {
		switch list.Format {
		case "map":
			if v, exists := list.Names[name]; exists {
				// td.Logger.Printf("ComputeRpzGreylistAction: found %s in greylist %s (%d names)",
				// 	name, listname, len(list.Names))
				greyHits[listname] = &v
			}
			//		case "trie":
			//			if list.Trie.Search(name) != nil {
			//				greyHits = append(greyHits, v)
			//			}
		default:
			TEMExiter("Unknown greylist format %s", list.Format)
		}
	}
	if len(greyHits) >= td.Policy.Greylist.NumSources {
		td.Policy.Logger.Printf("ComputeRpzGreylistAction: name %s is in %d or more sources, action is %s",
			name, td.Policy.Greylist.NumSources, tapir.ActionToString[td.Policy.Greylist.NumSourcesAction])
		return td.Policy.Greylist.NumSourcesAction
	}
	td.Policy.Logger.Printf("ComputeRpzGreylistAction: name %s is in %d sources, not enough for action", name, len(greyHits))

	if _, exists := greyHits["dns-tapir"]; exists {
		numtapirtags := greyHits["dns-tapir"].TagMask.NumTags()
		if numtapirtags >= td.Policy.Greylist.NumTapirTags {
			td.Policy.Logger.Printf("ComputeRpzGreylistAction: name %s has more than %d tapir tags, action is %s",
				name, td.Policy.Greylist.NumTapirTags, tapir.ActionToString[td.Policy.Greylist.NumTapirTagsAction])
			return td.Policy.Greylist.NumTapirTagsAction
		}
		td.Policy.Logger.Printf("ComputeRpzGreylistAction: name %s has %d tapir tags, not enough for action", name, numtapirtags)
	}
	td.Policy.Logger.Printf("ComputeRpzGreylistAction: name %s is present in %d greylists, but does not trigger any action",
		name, len(greyHits))
	return td.Policy.WhitelistAction
}

func (td *TemData) ComputeRpzAction(name string) tapir.Action {
	if td.Whitelisted(name) {
		if td.Debug {
			td.Policy.Logger.Printf("ComputeRpzAction: name %s is whitelisted, action is %s", name, tapir.ActionToString[td.Policy.WhitelistAction])
		}
		return td.Policy.WhitelistAction
	} else if td.Blacklisted(name) {
		if td.Debug {
			td.Policy.Logger.Printf("ComputeRpzAction: name %s is blacklisted, action is %s", name, tapir.ActionToString[td.Policy.BlacklistAction])
		}
		return td.Policy.BlacklistAction
	} else if td.Greylisted(name) {
		if td.Debug {
			td.Policy.Logger.Printf("ComputeRpzAction: name %s is greylisted, needs further evaluation to determine action", name)
		}
		return td.ComputeRpzGreylistAction(name) // This is not complete, only a placeholder for now.
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

	var removeData, addData []*tapir.RpzName
	td.Policy.Logger.Printf("GenerateRpzIxfr: %d removed names and %d added names", len(data.Removed), len(data.Added))
	for _, tn := range data.Removed {
		td.Policy.Logger.Printf("GenerateRpzIxfr: evaluating removed name %s", tn.Name)
		if cur, exist := td.Rpz.Axfr.Data[tn.Name]; exist {
			newAction := td.ComputeRpzAction(tn.Name)
			oldAction := cur.Action
			if newAction != oldAction {
				if td.Debug {
					td.Policy.Logger.Printf("GenRpzIxfr[DEL]: %s: oldaction(%s) != newaction(%s): -->DELETE",
						tn.Name,
						tapir.ActionToString[oldAction],
						tapir.ActionToString[newAction])
				}
				removeData = append(removeData, cur)

				if newAction != tapir.WHITELIST {
					cname := new(dns.CNAME)
					cname.Hdr = dns.RR_Header{
						Name:     tn.Name + td.Rpz.ZoneName,
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
				if td.Debug {
					td.Policy.Logger.Printf("GenRpzIxfr[DEL]: name %s present in previous policy with same action: -->NO CHANGE", tn.Name)
				}
			}
		} else {
			if td.Debug {
				td.Policy.Logger.Printf("GenRpzIxfr[DEL]: name %s not present in previous policy, still not included: -->NO CHANGE", tn.Name)
			}
		}
	}

	var addtorpz bool
	for _, tn := range data.Added {
		td.Policy.Logger.Printf("GenerateRpzIxfr: evaluating added name %s", tn.Name)
		addtorpz = false
		newAction := td.ComputeRpzAction(tn.Name)
		if cur, exist := td.Rpz.Axfr.Data[tn.Name]; exist {
			if newAction == tapir.WHITELIST {
				// delete from rpz
				if td.Debug {
					td.Policy.Logger.Printf("GenRpzIxfr[ADD]: name %s already exists in rpz, new action is WHITELIST: -->DELETE", tn.Name)
				}
				removeData = append(removeData, cur)
			} else {
				if cur.Action != newAction {
					// change, delete old rule, add new
					removeData = append(removeData, cur)
					addtorpz = true
					if td.Debug {
						td.Policy.Logger.Printf("GenRpzIxfr[ADD]: name %s present in rpz, newaction(%s) != oldaction(%s): -->ADD",
							tn.Name, tapir.ActionToString[newAction],
							tapir.ActionToString[cur.Action])
					}
				} else {
					// no change, do nothing
				}
			}
		} else {
			// name doesn't exist in current rpz, what is the action?
			if newAction != tapir.WHITELIST {
				// add it
				if td.Debug {
					td.Policy.Logger.Printf("GenRpzIxfr[ADD]: name %s NOT present in rpz, newaction(%s) != WHITELIST: -->ADD",
						tn.Name, tapir.ActionToString[newAction])
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
		curserial := td.Rpz.CurrentSerial
		newserial := curserial + 1 // XXX: not dealing with serial wraps
		thisixfr := RpzIxfr{
			FromSerial: curserial,
			ToSerial:   newserial,
			Removed:    removeData,
			Added:      addData,
		}
		td.Rpz.IxfrChain = append(td.Rpz.IxfrChain, thisixfr)
		td.Rpz.CurrentSerial = newserial
		if td.Verbose {
			td.Policy.Logger.Printf("GenRpzIxfr: added new IXFR (serial from %d to %d) to chain. Chain has %d IXFRs",
				curserial, newserial, len(td.Rpz.IxfrChain))
		}
		return thisixfr, nil
	}

	td.Policy.Logger.Printf("GenRpzIxfr: no changes in RPZ policy, no new IXFR")
	return RpzIxfr{}, nil
}
