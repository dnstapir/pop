/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package main

import (
	"fmt"
)

// Allowlisted / Denylisted / Doubtlisted are thin membership predicates over
// the single listOf() lookup (defined in policy.go). They previously each
// re-implemented the same per-format scan; Doubtlisted additionally crashed
// the daemon (log.Fatalf) on an unknown list format, which listOf() now
// degrades to a logged skip.
func (pd *PopData) Allowlisted(name string) bool { return len(pd.listOf("allowlist", name)) > 0 }
func (pd *PopData) Denylisted(name string) bool  { return len(pd.listOf("denylist", name)) > 0 }
func (pd *PopData) Doubtlisted(name string) bool { return len(pd.listOf("doubtlist", name)) > 0 }

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
