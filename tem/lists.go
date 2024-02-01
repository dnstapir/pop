/*
 * Copyright (c) DNS TAPIR
 */

package main

import (
        "fmt"
	"github.com/smhanov/dawg"
	"github.com/dnstapir/tapir-em/tapir"
)

type xxxWBGlist struct {
	Name        string
	Description string
	Type        string // whitelist | blacklist | greylist
	Mutable     bool   // true = is possible to update. Only local text file sources are mutable
	SrcFormat   string // Format of external source: dawg | rpz | tapir-mqtt-v1 | ...
	Format	    string // Format of internal storage: dawg | map | slice | trie | rbtree | ...
	Datasource  string // file | xfr | mqtt | https | api | ...
	Filename    string
	Dawgf       dawg.Finder

	// greylist sources needs more complex stuff here:
	GreyNames   map[string]tapir.GreyName
	RpzZoneName string
	RpzUpstream string
	RpzSerial   int
	Names	    map[string]string	// XXX: same data as in ZoneData.RpzData, should only keep one
}

type xxxGreyName struct {
	SrcFormat string          // "tapir-feed-v1" | ...
	Tags   map[string]bool // XXX: extremely wasteful, a bitfield would be better,
	//      but don't know how many tags there can be
}

func (td *TemData) Whitelisted(name string) bool {
	for _, list := range td.Whitelists {
		td.Logger.Printf("Whitelisted: checking %s in whitelist %s", name, list.Name)
		switch list.Format {
		case "dawg":
		     if list.Dawgf.IndexOf(name) != -1 {
			return true
		     }
		case "map":
		     if _, exists := list.Names[name]; exists {
		     	return true
		     }
	        }
	}
	return false
}

func (td *TemData) Blacklisted(name string) bool {
	for _, list := range td.Blacklists {
		td.Logger.Printf("Blacklisted: checking %s in blacklist %s", name, list.Name)
		switch list.Format {
		case "dawg":
		     if list.Dawgf.IndexOf(name) != -1 {
			return true
		     }
		case "map":
		     if _, exists := list.Names[name]; exists {
		     	return true
		     }
		}
	}
	return false
}

// func (td *TemData) ListWhitelists() (*tapir.WBGlist, error) {
//      var res = make(map[string]map[string]string, 3)
//      	td.Logger.Printf("ListWhitelists: there are %d whitelists", len(td.Whitelists))
// 	for _, list := range td.Whitelists {
// 		switch list.Format {
// 		case "dawg":
// 		     res[list.Name] = map[string]string{ "dawg-list": "x" }
// 		case "map":
// 		     res[list.Name] = list.Names
// 	        }
// 	}
// 	return res, nil
// }

func (td *TemData) ListBlacklists() (map[string]map[string]string, error) {
     var res = make(map[string]map[string]string, 3)
     	td.Logger.Printf("ListBlacklists: there are %d blacklists", len(td.Blacklists))
	for _, list := range td.Blacklists {
		switch list.Format {
		case "dawg":
		     res[list.Name] = map[string]string{ "dawg-list": "x" }
		case "map":
		     res[list.Name] = list.Names
	        }
	}
	return res, nil
}

func (td *TemData) ListGreylists() (map[string]map[string]string, error) {
     var res = make(map[string]map[string]string, 3)
     	td.Logger.Printf("ListGreylists: there are %d greylists", len(td.Greylists))
	for _, list := range td.Greylists {
		switch list.Format {
		case "map":
		     res[list.Name] = list.Names
	        }
	}
	return res, nil
}

func (td *TemData) GreylistingReport(name string) (bool, string) {
	var report string
	if len(td.Greylists) == 0 {
		return false, fmt.Sprintf("Domain name \"%s\" is not greylisted (there are no active greylists).\n", name)
	}

	for _, list := range td.Greylists {
		td.Logger.Printf("Greylisted: checking %s in greylist %s", name, list.Name)
		report += fmt.Sprintf("Domain name \"%s\" could be present in greylist %s\n", name, list.Name)
	}
	return false, report

}

func (td *TemData) GreylistAdd(name, policy, source string) (string, error) {
     msg := fmt.Sprintf("Domain name \"%s\" added to RPZ source %s with policy %s", name, source, policy)
     return msg, nil
}
