/*
 * Copyright (c) DNS TAPIR
 */

package main

import (
        "fmt"
//	"github.com/smhanov/dawg"
//	"github.com/dnstapir/tapir"
)

func (td *TemData) Whitelisted(name string) bool {
//	for _, list := range td.Whitelists {
	for _, list := range td.Lists["whitelist"] {
		switch list.Format {
		case "dawg":
		     td.Logger.Printf("Whitelisted: DAWG: checking %s in whitelist %s", name, list.Name)
		     if list.Dawgf.IndexOf(name) != -1 {
			return true
		     }
		case "map":
		     td.Logger.Printf("Whitelisted: MAP: checking %s in whitelist %s", name, list.Name)
		     if _, exists := list.Names[name]; exists {
		     	return true
		     }
	        }
	}
	return false
}

func (td *TemData) Blacklisted(name string) bool {
//	for _, list := range td.Blacklists {
	for _, list := range td.Lists["whitelist"] {
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

func (td *TemData) GreylistingReport(name string) (bool, string) {
 	var report string
// 	if len(td.Greylists) == 0 {
 	if len(td.Lists["greylist"]) == 0 {
 		return false, fmt.Sprintf("Domain name \"%s\" is not greylisted (there are no active greylists).\n", name)
 	}
 
// 	for _, list := range td.Greylists {
 	for _, list := range td.Lists["greylist"] {
 		td.Logger.Printf("Greylisted: checking %s in greylist %s", name, list.Name)
 		report += fmt.Sprintf("Domain name \"%s\" could be present in greylist %s\n", name, list.Name)
 	}
 	return false, report
 
}

func (td *TemData) GreylistAdd(name, policy, source string) (string, error) {
      msg := fmt.Sprintf("Domain name \"%s\" added to RPZ source %s with policy %s", name, source, policy)
      return msg, nil
}
