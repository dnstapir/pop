/*
 * Copyright (c) DNS TAPIR
 */

package main

import (
	"github.com/dnstapir/tapir"
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

func (td *TemData) GenerateRpzOutput() {

     var black = make(map[string]bool, 10000)
     var grey = make(map[string]tapir.TapirName, 10000)
     
     for bname, blist := range td.Blacklists {
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
	
     for gname, glist := range td.Greylists {
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
			       tmp := grey[k]
			       tmp.Tagmask = grey[k].Tagmask | v.Tagmask
			       tmp.Action = tmp.Action + v.Action
			       grey[k] = tmp
			    } else {
			      grey[k] = v
			    }
			 }
		     }
		default:
			td.Logger.Printf("*** Error: Greylist %s has unknown format \"%s\".", gname, glist.Format)
		}
	}
}