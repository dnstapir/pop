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

func (pd *PopData) Allowlisted(name string) bool {
	for _, list := range pd.Lists["allowlist"] {
		switch list.Format {
		case "dawg":
			if tapir.GlobalCF.Debug {
				pd.Logger.Printf("Allowlisted: DAWG: checking %s in allowlist %s", name, list.Name)
			}
			if list.Dawgf.IndexOf(name) != -1 {
				return true
			}
		case "map":
			if tapir.GlobalCF.Debug {
				pd.Logger.Printf("Allowlisted: MAP: checking %s in allowlist %s", name, list.Name)
			}
			if _, exists := list.Names[name]; exists {
				return true
			}
		}
	}
	return false
}

func (pd *PopData) Denylisted(name string) bool {
	for _, list := range pd.Lists["denylist"] {
		if tapir.GlobalCF.Debug {
			pd.Logger.Printf("Denylisted: checking %s in Denylist %s", name, list.Name)
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

func (pd *PopData) Doubtlisted(name string) bool {
	for _, list := range pd.Lists["doubtlist"] {
		if tapir.GlobalCF.Debug {
			pd.Logger.Printf("Doubtlisted: checking %s in doubtlist %s", name, list.Name)
		}
		switch list.Format {
		case "map":
			if _, exists := list.Names[name]; exists {
				return true
			}
			//		case "trie":
			//			return list.Trie.Search(name) != nil
		default:
			log.Fatalf("Unknown doubtlist format %s", list.Format)
		}
	}
	return false
}

func (pd *PopData) DoubtlistingReport(name string) (bool, string) {
	var report string
	// 	if len(pd.Doubtlists) == 0 {
	if len(pd.Lists["doubtlist"]) == 0 {
		return false, fmt.Sprintf("Domain name \"%s\" is not doubtlisted (there are no active doubtlists).\n", name)
	}

	// 	for _, list := range pd.Doubtlists {
	for _, list := range pd.Lists["doubtlist"] {
		pd.Logger.Printf("Doubtlisted: checking %s in doubtlist %s", name, list.Name)
		report += fmt.Sprintf("Domain name \"%s\" could be present in doubtlist %s\n", name, list.Name)
	}
	return false, report

}

func (pd *PopData) DoubtlistAdd(name, policy, source string) (string, error) {
	msg := fmt.Sprintf("Domain name \"%s\" added to RPZ source %s with policy %s", name, source, policy)
	return msg, nil
}
