/*
 * Copyright (c) DNS TAPIR
 */

package main

import (
//       "log"

	"github.com/dnstapir/tapir-em/tapir"
)

// XXX: Generatin a complete new RPZ zone for output to downstream

// Note that it is not possible to generate the output until all sources have been parsed.

// 1. Walk through all blacklists and add blocks for those names
// 2. Walk through all greylists and look for correlations between lists
//    - if there are enough indications, then add a block
//    - if there isn't enough indications, then add nothing
//    - match a grey name that has been kept against all whitelists
//      - if there is a match, then drop that grey name

func (td *TemData) GenerateOutput() (string, error) {
     out := tapir.ZoneData{
		ZoneName:	"rpz.",
		ZoneType:	3,
     	    }

//     for _, list := range td.Blacklists {
//     	 td.Logger.Printf("Blacklisted: checking %s in blacklist %s", name, list.Name)
//     	 if list.Dawgf.IndexOf(name) != -1 {
//     	    return true
//	 }
//     }

     td.Output = &out
     return "", nil
}

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