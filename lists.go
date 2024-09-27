/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package main

import (
	"fmt"
	"log"

	//	"github.com/smhanov/dawg"
	"github.com/dnstapir/tapir"
)

func (pd *PopData) Whitelisted(name string) bool {
	for _, list := range pd.Lists["whitelist"] {
		switch list.Format {
		case "dawg":
			if tapir.GlobalCF.Debug {
				pd.Logger.Printf("Whitelisted: DAWG: checking %s in whitelist %s", name, list.Name)
			}
			if list.Dawgf.IndexOf(name) != -1 {
				return true
			}
		case "map":
			if tapir.GlobalCF.Debug {
				pd.Logger.Printf("Whitelisted: MAP: checking %s in whitelist %s", name, list.Name)
			}
			if _, exists := list.Names[name]; exists {
				return true
			}
		}
	}
	return false
}

func (pd *PopData) Blacklisted(name string) bool {
	for _, list := range pd.Lists["blacklist"] {
		if tapir.GlobalCF.Debug {
			pd.Logger.Printf("Blacklisted: checking %s in blacklist %s", name, list.Name)
		}
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

func (pd *PopData) Greylisted(name string) bool {
	for _, list := range pd.Lists["greylist"] {
		if tapir.GlobalCF.Debug {
			pd.Logger.Printf("Greylisted: checking %s in greylist %s", name, list.Name)
		}
		switch list.Format {
		case "map":
			if _, exists := list.Names[name]; exists {
				return true
			}
			//		case "trie":
			//			return list.Trie.Search(name) != nil
		default:
			log.Fatalf("Unknown greylist format %s", list.Format)
		}
	}
	return false
}

func (pd *PopData) GreylistingReport(name string) (bool, string) {
	var report string
	// 	if len(pd.Greylists) == 0 {
	if len(pd.Lists["greylist"]) == 0 {
		return false, fmt.Sprintf("Domain name \"%s\" is not greylisted (there are no active greylists).\n", name)
	}

	// 	for _, list := range pd.Greylists {
	for _, list := range pd.Lists["greylist"] {
		pd.Logger.Printf("Greylisted: checking %s in greylist %s", name, list.Name)
		report += fmt.Sprintf("Domain name \"%s\" could be present in greylist %s\n", name, list.Name)
	}
	return false, report

}

func (pd *PopData) GreylistAdd(name, policy, source string) (string, error) {
	msg := fmt.Sprintf("Domain name \"%s\" added to RPZ source %s with policy %s", name, source, policy)
	return msg, nil
}
