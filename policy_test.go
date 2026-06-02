/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package main

// This is the first test file in the POP codebase, so a short orientation on
// the Go testing machinery (no third-party framework is involved):
//
//   - A test file must end in `_test.go`. It is compiled ONLY when running
//     `go test`, never into the normal binary, so test-only helpers here do
//     not bloat the daemon.
//   - It shares the package (`package main`) with the code under test, so it
//     can reach unexported identifiers like `decide`, `PopData`, `Reason`.
//     (The alternative, `package main_test`, would only see exported names.)
//   - Any function `func TestXxx(t *testing.T)` is a test. Run them with
//     `go test ./pop/`. The `*testing.T` is how a test reports failure:
//       t.Errorf(...)  -> mark failed, keep going (good for table rows)
//       t.Fatalf(...)  -> mark failed, stop THIS test immediately
//   - `t.Run(name, func)` creates a named SUBTEST. Each table row becomes its
//     own subtest, so a failure prints e.g. `TestDecide/numsources_at_limit`
//     and you can re-run just that row with `-run 'TestDecide/numsources'`.
//
// The style below is "table-driven": the test cases are DATA (a slice of
// structs), and one loop drives them all. This is idiomatic Go and is exactly
// why the policy engine is the right first target — decide() is almost a pure
// function (name + in-memory lists + policy config -> action), so a case is
// just "given these lists and this policy, expect this action".

import (
	"log"
	"strings"
	"testing"

	"github.com/dnstapir/tapir"
)

// --- fixture helpers -------------------------------------------------------
//
// These build a minimal PopData carrying only what decide() needs: the Lists
// map, the Policy, and a Logger. No config files, no MQTT, no DNS server.

// tn is a terse constructor for a TapirName with a set of tags and an action.
func tn(name string, tags tapir.TagMask, action tapir.Action) tapir.TapirName {
	return tapir.TapirName{Name: name, TagMask: tags, Action: action}
}

// listFixture describes one source list to install into a PopData.
type listFixture struct {
	class  string // "allowlist" | "denylist" | "doubtlist"
	source string // source name, e.g. "dns-tapir"
	names  []tapir.TapirName
}

// newTestPopData assembles a PopData from a default policy plus a set of list
// fixtures. The policy mirrors the documented pop-policy.yaml template.
func newTestPopData(policy DoubtlistPolicy, fixtures ...listFixture) *PopData {
	pd := &PopData{
		Lists:  map[string]map[string]*tapir.WBGlist{},
		Logger: log.Default(),
	}
	pd.Lists["allowlist"] = map[string]*tapir.WBGlist{}
	pd.Lists["denylist"] = map[string]*tapir.WBGlist{}
	pd.Lists["doubtlist"] = map[string]*tapir.WBGlist{}

	pd.Policy = PopPolicy{
		Logger:          log.Default(),
		AllowlistAction: tapir.ALLOWLIST,
		DenylistAction:  tapir.NODATA, // per the config template
		Doubtlist:       policy,
	}

	for _, f := range fixtures {
		names := map[string]tapir.TapirName{}
		for _, n := range f.names {
			names[n.Name] = n
		}
		pd.Lists[f.class][f.source] = &tapir.WBGlist{
			Name:   f.source,
			Type:   f.class,
			Format: "map",
			Names:  names,
		}
	}
	return pd
}

// defaultDoubtPolicy matches the pop-policy.yaml template:
//
//	numsources:   {limit: 2, action: NXDOMAIN}
//	numtapirtags: {limit: 3, action: NXDOMAIN}
//	denytapir:    {tags: [likelymalware], action: REDIRECT}
func defaultDoubtPolicy() DoubtlistPolicy {
	return DoubtlistPolicy{
		NumSources:         2,
		NumSourcesAction:   tapir.NXDOMAIN,
		NumTapirTags:       3,
		NumTapirTagsAction: tapir.NXDOMAIN,
		DenyTapirTags:      tapir.LikelyMalware,
		DenyTapirAction:    tapir.REDIRECT,
	}
}

// --- TestDecide ------------------------------------------------------------
//
// The core table-driven test. Each row sets up lists, runs decide(), and
// asserts the emitted action AND which precedence stage made the decision.

func TestDecide(t *testing.T) {
	const q = "evil.example."

	tests := []struct {
		name       string // subtest name
		fixtures   []listFixture
		policy     DoubtlistPolicy
		wantAction tapir.Action
		wantStage  Stage
	}{
		{
			// INVARIANT 1: allowlist is absolute. A name on an allowlist is
			// never in the output, even if it is ALSO on a denylist and a
			// doubtlist that would otherwise block it.
			name: "allowlist beats deny and doubt",
			fixtures: []listFixture{
				{"allowlist", "corp-allow", []tapir.TapirName{tn(q, 0, 0)}},
				{"denylist", "blocky", []tapir.TapirName{tn(q, 0, 0)}},
				{"doubtlist", "a", []tapir.TapirName{tn(q, 0, 0)}},
				{"doubtlist", "b", []tapir.TapirName{tn(q, 0, 0)}},
			},
			policy:     defaultDoubtPolicy(),
			wantAction: tapir.ALLOWLIST,
			wantStage:  StageAllowlist,
		},
		{
			name: "denylist only -> DenylistAction",
			fixtures: []listFixture{
				{"denylist", "blocky", []tapir.TapirName{tn(q, 0, 0)}},
			},
			policy:     defaultDoubtPolicy(),
			wantAction: tapir.NODATA, // == DenylistAction
			wantStage:  StageDenylist,
		},
		{
			// numsources threshold is 2: one source is below it.
			name: "doubt in 1 source, below numsources -> passthru",
			fixtures: []listFixture{
				{"doubtlist", "a", []tapir.TapirName{tn(q, 0, 0)}},
			},
			policy:     defaultDoubtPolicy(),
			wantAction: tapir.ALLOWLIST, // not included in output
			wantStage:  StageDoubtlist,
		},
		{
			name: "doubt in 2 sources, at numsources limit -> NumSourcesAction",
			fixtures: []listFixture{
				{"doubtlist", "a", []tapir.TapirName{tn(q, 0, 0)}},
				{"doubtlist", "b", []tapir.TapirName{tn(q, 0, 0)}},
			},
			policy:     defaultDoubtPolicy(),
			wantAction: tapir.NXDOMAIN,
			wantStage:  StageDoubtlist,
		},
		{
			// numtapirtags: 3 tags on the dns-tapir entry, limit is 3 -> fires.
			name: "dns-tapir entry with >= numtapirtags tags -> NumTapirTagsAction",
			fixtures: []listFixture{
				{"doubtlist", "dns-tapir", []tapir.TapirName{
					tn(q, tapir.BadIP|tapir.CdnTracker|tapir.HighVolume, 0),
				}},
			},
			policy:     defaultDoubtPolicy(),
			wantAction: tapir.NXDOMAIN,
			wantStage:  StageDoubtlist,
		},
		{
			// Q2 GUARD: the same 3 tags on a NON-dns-tapir source must NOT
			// trigger numtapirtags (it counts dns-tapir tags only). One source,
			// below numsources too, so it should pass through.
			name: "3 tags on non-dns-tapir source does not fire numtapirtags",
			fixtures: []listFixture{
				{"doubtlist", "somefeed", []tapir.TapirName{
					tn(q, tapir.BadIP|tapir.CdnTracker|tapir.HighVolume, 0),
				}},
			},
			policy:     defaultDoubtPolicy(),
			wantAction: tapir.ALLOWLIST,
			wantStage:  StageDoubtlist,
		},
		{
			// denytapir: dns-tapir entry carries LikelyMalware, which is in
			// DenyTapirTags -> REDIRECT. Only one source and only one tag, so
			// neither numsources nor numtapirtags fires; denytapir is the only
			// firing rule.
			name: "dns-tapir entry with denytapir tag -> DenyTapirAction",
			fixtures: []listFixture{
				{"doubtlist", "dns-tapir", []tapir.TapirName{
					tn(q, tapir.LikelyMalware, 0),
				}},
			},
			policy:     defaultDoubtPolicy(),
			wantAction: tapir.REDIRECT,
			wantStage:  StageDoubtlist,
		},
		{
			// CONFLICT RESOLUTION: most-restrictive wins.
			// In 2 sources -> numsources fires (NXDOMAIN). The dns-tapir entry
			// also carries a denytapir tag -> denytapir fires (REDIRECT).
			// Ranking DROP > NXDOMAIN > NODATA > REDIRECT > PASSTHRU means
			// NXDOMAIN (more restrictive) wins over REDIRECT.
			name: "numsources(NXDOMAIN) vs denytapir(REDIRECT) -> NXDOMAIN wins",
			fixtures: []listFixture{
				{"doubtlist", "dns-tapir", []tapir.TapirName{tn(q, tapir.LikelyMalware, 0)}},
				{"doubtlist", "other", []tapir.TapirName{tn(q, 0, 0)}},
			},
			policy:     defaultDoubtPolicy(),
			wantAction: tapir.NXDOMAIN,
			wantStage:  StageDoubtlist,
		},
		{
			// not in any list -> passthru, decided at the "none" stage.
			name:       "unknown name -> passthru (stage none)",
			fixtures:   []listFixture{},
			policy:     defaultDoubtPolicy(),
			wantAction: tapir.ALLOWLIST,
			wantStage:  StageNone,
		},
	}

	for _, tc := range tests {
		// tc captured per-iteration; t.Run makes each row an isolated subtest.
		t.Run(tc.name, func(t *testing.T) {
			pd := newTestPopData(tc.policy, tc.fixtures...)
			gotAction, gotReason := pd.decide(q)
			if gotAction != tc.wantAction {
				t.Errorf("decide(%q) action = %s, want %s",
					q, tapir.ActionToString[gotAction], tapir.ActionToString[tc.wantAction])
			}
			if gotReason.Stage != tc.wantStage {
				t.Errorf("decide(%q) stage = %v, want %v", q, gotReason.Stage, tc.wantStage)
			}
		})
	}
}

// --- TestDecideOrderIndependence -------------------------------------------
//
// INVARIANT 2: the result must not depend on source ordering. We build the
// same logical doubtlist set under different source names/insertion patterns
// and assert the action is identical. (Go already randomizes map iteration
// order between runs, so a hidden iteration-order dependence would also show
// up here as flakiness.)

func TestDecideOrderIndependence(t *testing.T) {
	const q = "evil.example."
	policy := defaultDoubtPolicy()

	// Two sources, names inserted in two different orders. numsources(2) fires.
	a := newTestPopData(policy,
		listFixture{"doubtlist", "alpha", []tapir.TapirName{tn(q, 0, 0)}},
		listFixture{"doubtlist", "zeta", []tapir.TapirName{tn(q, 0, 0)}},
	)
	b := newTestPopData(policy,
		listFixture{"doubtlist", "zeta", []tapir.TapirName{tn(q, 0, 0)}},
		listFixture{"doubtlist", "alpha", []tapir.TapirName{tn(q, 0, 0)}},
	)

	actA, reasonA := a.decide(q)
	actB, reasonB := b.decide(q)
	if actA != actB {
		t.Errorf("decide is order-dependent: %s vs %s",
			tapir.ActionToString[actA], tapir.ActionToString[actB])
	}
	// Reason.Sources must also be order-independent: listOf sorts by source
	// name, so both insertion orders must yield the same sequence (alpha, zeta).
	if got := sourceList(reasonA.Sources); got != "alpha,zeta" {
		t.Errorf("reasonA.Sources = %q, want alpha,zeta", got)
	}
	if sourceList(reasonA.Sources) != sourceList(reasonB.Sources) {
		t.Errorf("Reason.Sources order depends on insertion order: %q vs %q",
			sourceList(reasonA.Sources), sourceList(reasonB.Sources))
	}
}

func sourceList(hits []ListHit) string {
	var ss []string
	for _, h := range hits {
		ss = append(ss, h.Source)
	}
	return strings.Join(ss, ",")
}

// --- TestDecideDeterminism -------------------------------------------------
//
// INVARIANT 3: same inputs -> same output, every call.

func TestDecideDeterminism(t *testing.T) {
	const q = "evil.example."
	pd := newTestPopData(defaultDoubtPolicy(),
		listFixture{"doubtlist", "dns-tapir", []tapir.TapirName{tn(q, tapir.LikelyMalware, 0)}},
		listFixture{"doubtlist", "other", []tapir.TapirName{tn(q, 0, 0)}},
	)

	first, firstReason := pd.decide(q)
	firstSources := sourceList(firstReason.Sources)
	for i := 0; i < 100; i++ {
		got, gotReason := pd.decide(q)
		if got != first {
			t.Fatalf("decide is non-deterministic: call %d gave %s, first gave %s",
				i, tapir.ActionToString[got], tapir.ActionToString[first])
		}
		// Reason.Sources ordering must be stable too (listOf sorts).
		if gs := sourceList(gotReason.Sources); gs != firstSources {
			t.Fatalf("Reason.Sources non-deterministic: call %d gave %q, first gave %q",
				i, gs, firstSources)
		}
	}
}
