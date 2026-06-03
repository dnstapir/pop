/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package main

import (
	"fmt"
	"strings"

	"github.com/dnstapir/tapir"
	"github.com/miekg/dns"
)

// Allowlisted / Denylisted / Doubtlisted are thin membership predicates over
// the single listOf() lookup (defined in policy.go). They previously each
// re-implemented the same per-format scan; Doubtlisted additionally crashed
// the daemon (log.Fatalf) on an unknown list format, which listOf() now
// degrades to a logged skip.
func (pd *PopData) Allowlisted(name string) bool { return len(pd.listOf("allowlist", name)) > 0 }
func (pd *PopData) Denylisted(name string) bool  { return len(pd.listOf("denylist", name)) > 0 }
func (pd *PopData) Doubtlisted(name string) bool { return len(pd.listOf("doubtlist", name)) > 0 }

// LookupReport explains the RPZ decision for a name using the SAME decide()
// path that builds the served zone, so the explanation can never disagree with
// what is actually served (AXFR/IXFR). It reports the emitted action, the
// deciding stage, the matching sources, and (for doubtlist decisions) which
// rules fired. This is the minimal unification; the richer structured output
// for the "filter reason" CLI command (task a) is built on the same Reason.
func (pd *PopData) LookupReport(name string) string {
	action, reason := pd.decide(name)
	fqdn := dns.Fqdn(name)

	var b strings.Builder
	switch reason.Stage {
	case StageAllowlist:
		fmt.Fprintf(&b, "Domain name %q is allowlisted (sources: %s); not filtered.\n",
			fqdn, sourceNames(reason.Sources))
	case StageDenylist:
		fmt.Fprintf(&b, "Domain name %q is denylisted (sources: %s); served as %s.\n",
			fqdn, sourceNames(reason.Sources), tapir.ActionToString[action])
	case StageDoubtlist:
		if action == tapir.ALLOWLIST {
			fmt.Fprintf(&b, "Domain name %q is in doubtlists (sources: %s) but no rule triggered; not filtered.\n",
				fqdn, sourceNames(reason.Sources))
		} else {
			fmt.Fprintf(&b, "Domain name %q is doubtlisted (sources: %s); served as %s.\n",
				fqdn, sourceNames(reason.Sources), tapir.ActionToString[action])
			for _, rr := range reason.Fired {
				fmt.Fprintf(&b, "  rule %q fired: %s (action %s)\n",
					rr.Rule, rr.Detail, tapir.ActionToString[rr.Action])
			}
		}
	default: // StageNone
		fmt.Fprintf(&b, "Domain name %q is not present in any list; not filtered.\n", fqdn)
	}
	return b.String()
}

// sourceNames renders the source names of a set of ListHits, in the (already
// sorted) order listOf produced.
func sourceNames(hits []ListHit) string {
	if len(hits) == 0 {
		return "(none)"
	}
	names := make([]string, 0, len(hits))
	for _, h := range hits {
		names = append(names, h.Source)
	}
	return strings.Join(names, ", ")
}

func (pd *PopData) DoubtlistAdd(name, policy, source string) (string, error) {
	msg := fmt.Sprintf("Domain name \"%s\" added to RPZ source %s with policy %s", name, source, policy)
	return msg, nil
}
