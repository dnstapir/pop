/*
 * Copyright (c) 2024 Johan Stenstam, joahn.stenstam@internetstiftelsen.se
 */

package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/dnstapir/tapir"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

type PopOutput struct {
	Active      bool
	Name        string
	Description string
	Type        string // listtype, usually "doubtlist"
	Format      string // i.e. rpz, etc
	Downstream  string
}

type PopOutputs struct {
	Outputs map[string]PopOutput
}

func (pd *PopData) ParseOutputs() error {
	pd.Logger.Printf("ParseOutputs: reading outputs from %s", tapir.PopOutputsCfgFile)
	cfgdata, err := os.ReadFile(tapir.PopOutputsCfgFile)
	if err != nil {
		log.Fatalf("Error from ReadFile(%s): %v", tapir.PopOutputsCfgFile, err)
	}

	var oconf = PopOutputs{
		Outputs: make(map[string]PopOutput),
	}

	// pd.Logger.Printf("ParseOutputs: config read: %s", cfgdata)
	err = yaml.Unmarshal(cfgdata, &oconf)
	if err != nil {
		log.Fatalf("Error from yaml.Unmarshal(OutputsConfig): %v", err)
	}

	pd.Logger.Printf("ParseOutputs: found %d outputs", len(oconf.Outputs))
	for name, v := range oconf.Outputs {
		pd.Logger.Printf("ParseOutputs: output %s: type %s, format %s, downstream %s",
			name, v.Type, v.Format, v.Downstream)
	}

	for name, output := range oconf.Outputs {
		if output.Active && strings.ToLower(output.Format) == "rpz" {
			pd.Logger.Printf("Output %s: Adding RPZ downstream %s to list of Notify receivers", name, output.Downstream)
			addr, port, err := net.SplitHostPort(output.Downstream)
			if err != nil {
				pd.Logger.Printf("Invalid downstream address %s: %v", output.Downstream, err)
				continue
			}
			if net.ParseIP(addr) == nil {
				pd.Logger.Printf("Invalid IP address %s", addr)
				continue
			}
			portInt, err := strconv.Atoi(port)
			if err != nil {
				pd.Logger.Printf("Invalid port %s: %v", port, err)
				continue
			}
			pd.Downstreams[addr] = RpzDownstream{Address: addr, Port: portInt}
		}
	}
	// Read the current value of pd.Downstreams.Serial from a text file
	serialFile := viper.GetString("services.rpz.serialcache")

	if serialFile != "" {
		serialFile = filepath.Clean(serialFile)
		serialData, err := os.ReadFile(serialFile)
		if err != nil {
			pd.Logger.Printf("Error reading serial from file %s: %v", serialFile, err)
			pd.Rpz.CurrentSerial = 1
		} else {
			var serialYaml struct {
				CurrentSerial uint32 `yaml:"current_serial"`
			}
			err = yaml.Unmarshal(serialData, &serialYaml)
			if err != nil {
				pd.Logger.Printf("Error unmarshalling YAML serial data: %v", err)
				pd.Rpz.CurrentSerial = 1
			} else {
				pd.Rpz.CurrentSerial = serialYaml.CurrentSerial
				pd.Logger.Printf("Loaded serial %d from file %s", pd.Rpz.CurrentSerial, serialFile)
			}
		}
	} else {
		pd.Logger.Printf("No serial cache file specified, starting serial at 1")
		pd.Rpz.CurrentSerial = 1
	}
	// pd.Rpz.CurrentSerial = pd.Downstreams.Serial
	return nil
}

// ---------------------------------------------------------------------------
// Unified policy engine (issue #156).
//
// decide() is the single decision function used by BOTH the RPZ compilation
// (GenerateRpzAxfr/Ixfr) and any lookup/explain path, so the served zone and
// an explanation of it can never disagree. It returns the emitted Action plus
// a Reason that records why, which is also the substrate for the future
// "filter reason" CLI command.
//
// Invariants (objectives a + b in the design doc; these are NOT provisional):
//   1. Allowlist is absolute: a name on any allowlist is never in the output.
//   2. Order independence: source declaration / map iteration order must not
//      affect the result.
//   3. Determinism: same inputs -> same (Action, Reason).
//
// The doubtlist rules themselves ARE provisional (a future policy language),
// so they are expressed as a slice of pluggable rules rather than an if-ladder:
// adding a knob is one entry + one test, removing one is a deletion.
// ---------------------------------------------------------------------------

// Stage records which precedence level made the decision.
type Stage int

const (
	StageNone Stage = iota // not in any list
	StageAllowlist
	StageDenylist
	StageDoubtlist
)

func (s Stage) String() string {
	switch s {
	case StageAllowlist:
		return "allowlist"
	case StageDenylist:
		return "denylist"
	case StageDoubtlist:
		return "doubtlist"
	default:
		return "none"
	}
}

// ListHit is one source (of a given list class) that contained the name.
// Entry is nil for dawg-format lists, which support membership but not
// per-name metadata.
type ListHit struct {
	Source string
	Entry  *tapir.TapirName
}

// RuleResult is the outcome of evaluating one doubtlist rule.
type RuleResult struct {
	Rule   string // "numsources" | "numtapirtags" | "denytapir"
	Fired  bool
	Action tapir.Action
	Detail string // human-readable explanation, e.g. "in 3 sources (limit 2)"
}

// Reason is the structured explanation returned alongside the action.
type Reason struct {
	Action  tapir.Action
	Stage   Stage
	Sources []ListHit    // sources (of the deciding stage) that contained the name
	Fired   []RuleResult // doubt rules that fired (only when Stage == StageDoubtlist)
	Winner  *RuleResult  // the fired rule whose action was emitted (nil if none fired)
}

// actionSeverity ranks actions from most to least restrictive. mostRestrictive
// picks the highest. Defined as a single ordered table so the ranking is a
// one-line change if operators push back (e.g. on REDIRECT's placement).
// ALLOWLIST is the "no action / passthru" value (note: tapir.Action is a
// bitmask and tapir.PASSTHRU is a distinct unused bit; the codebase uses
// ALLOWLIST as the pass value, matching the old ComputeRpzAction).
var actionSeverity = map[tapir.Action]int{
	tapir.DROP:      5,
	tapir.NXDOMAIN:  4,
	tapir.NODATA:    3,
	tapir.REDIRECT:  2,
	tapir.ALLOWLIST: 1,
}

// listOf returns every source in the given class that contains name. This is
// the single membership-lookup helper that replaces the former
// Allowlisted/Denylisted/Doubtlisted trio. Order-independent: it scans all
// sources and the caller does not rely on iteration order.
func (pd *PopData) listOf(class, name string) []ListHit {
	var hits []ListHit
	for src, list := range pd.Lists[class] {
		switch list.Format {
		case "dawg":
			if list.Dawgf.IndexOf(name) != -1 {
				hits = append(hits, ListHit{Source: src})
			}
		case "map":
			if e, ok := list.Names[name]; ok {
				e := e // copy; don't alias the map value
				hits = append(hits, ListHit{Source: src, Entry: &e})
			}
		default:
			// Degrade, never crash a long-running daemon on a bad list format
			// (was log.Fatalf in the old Doubtlisted()). See issue #6.
			pd.Logger.Printf("listOf: skipping source %q: unknown format %q", src, list.Format)
		}
	}
	return hits
}

// doubtRule is a single pluggable doubtlist rule.
type doubtRule struct {
	name string
	eval func(hits []ListHit, p DoubtlistPolicy) RuleResult
}

// doubtRules is the ordered set of rules evaluated for a doubtlisted name.
// This release ships exactly the three knobs documented in pop-policy.yaml.
// To add a future knob, append a rule here and a test row in policy_test.go.
var doubtRules = []doubtRule{
	{
		name: "numsources",
		eval: func(hits []ListHit, p DoubtlistPolicy) RuleResult {
			r := RuleResult{Rule: "numsources"}
			if len(hits) >= p.NumSources {
				r.Fired, r.Action = true, p.NumSourcesAction
				r.Detail = fmt.Sprintf("in %d sources (limit %d)", len(hits), p.NumSources)
			}
			return r
		},
	},
	{
		name: "numtapirtags",
		eval: func(hits []ListHit, p DoubtlistPolicy) RuleResult {
			// Counts tags on the dns-tapir source's entry ONLY (Q2). A future
			// "numtags" rule could count the merged tag set across sources.
			r := RuleResult{Rule: "numtapirtags"}
			if e := dnsTapirEntry(hits); e != nil {
				if n := e.TagMask.NumTags(); n >= p.NumTapirTags {
					r.Fired, r.Action = true, p.NumTapirTagsAction
					r.Detail = fmt.Sprintf("dns-tapir entry has %d tags (limit %d)", n, p.NumTapirTags)
				}
			}
			return r
		},
	},
	{
		name: "denytapir",
		eval: func(hits []ListHit, p DoubtlistPolicy) RuleResult {
			// Fires when the dns-tapir entry carries any tag in DenyTapirTags.
			// Newly wired in: parsed from config today but never consulted.
			// Default DenyTapirTags is empty, so this is a no-op until set.
			r := RuleResult{Rule: "denytapir"}
			if p.DenyTapirTags == 0 {
				return r
			}
			if e := dnsTapirEntry(hits); e != nil && e.TagMask&p.DenyTapirTags != 0 {
				r.Fired, r.Action = true, p.DenyTapirAction
				r.Detail = "dns-tapir entry carries a denytapir tag"
			}
			return r
		},
	},
}

// dnsTapirEntry returns the TapirName from the special "dns-tapir" source among
// the hits, or nil if that source did not contain the name (or had no entry,
// e.g. a dawg list).
func dnsTapirEntry(hits []ListHit) *tapir.TapirName {
	for _, h := range hits {
		if h.Source == "dns-tapir" {
			return h.Entry
		}
	}
	return nil
}

// decide is the single source of truth for the policy decision on a name.
func (pd *PopData) decide(name string) (tapir.Action, Reason) {
	// Stage 1: allowlist is absolute (invariant 1).
	if hits := pd.listOf("allowlist", name); len(hits) > 0 {
		return pd.Policy.AllowlistAction, Reason{
			Action: pd.Policy.AllowlistAction, Stage: StageAllowlist, Sources: hits,
		}
	}

	// Stage 2: denylist.
	if hits := pd.listOf("denylist", name); len(hits) > 0 {
		return pd.Policy.DenylistAction, Reason{
			Action: pd.Policy.DenylistAction, Stage: StageDenylist, Sources: hits,
		}
	}

	// Stage 3: doubtlist (provisional, pluggable rules).
	hits := pd.listOf("doubtlist", name)
	if len(hits) == 0 {
		return tapir.ALLOWLIST, Reason{Action: tapir.ALLOWLIST, Stage: StageNone}
	}

	var fired []RuleResult
	for _, rule := range doubtRules {
		if r := rule.eval(hits, pd.Policy.Doubtlist); r.Fired {
			fired = append(fired, r)
		}
	}

	if len(fired) == 0 {
		// In one or more doubtlists, but no rule triggered -> passthru.
		return tapir.ALLOWLIST, Reason{Action: tapir.ALLOWLIST, Stage: StageDoubtlist, Sources: hits}
	}

	// Conflict resolution: most-restrictive action wins (order-independent).
	winner := &fired[0]
	for i := 1; i < len(fired); i++ {
		if actionSeverity[fired[i].Action] > actionSeverity[winner.Action] {
			winner = &fired[i]
		}
	}
	return winner.Action, Reason{
		Action: winner.Action, Stage: StageDoubtlist, Sources: hits, Fired: fired, Winner: winner,
	}
}
