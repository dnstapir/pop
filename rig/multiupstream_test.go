/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * More than one RPZ upstream at a time.
 *
 * pop's job is to merge several feeds into one zone with the conflicts
 * resolved, so a single feed tests the transport but not the point.
 */
package rig

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// ruleSet is the served zone reduced to its policy rules: owner -> CNAME
// target. The apex NS and SOA are constant and not what these tests are about.
func ruleSet(p *Pop) (map[string]string, error) {
	rrs, err := p.AXFR()
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, rr := range rrs {
		if c, ok := rr.(*dns.CNAME); ok {
			out[strings.ToLower(c.Hdr.Name)] = c.Target
		}
	}
	return out, nil
}

// wantRules is what pop should be serving for these names under the rig's
// policy, which answers every denylisted name with NXDOMAIN regardless of the
// action the upstream asked for.
func wantRules(p *Pop, names ...string) map[string]string {
	want := map[string]string{}
	for _, n := range names {
		want[strings.ToLower(n+p.ZoneName)] = string(NXDOMAIN)
	}
	return want
}

// waitForRules polls until the served rules match want exactly, and reports
// what still differed if they never did.
//
// Exactly, not "contains": a name that should have gone away but did not is the
// failure these tests exist to catch, and a subset check would miss it.
func waitForRules(p *Pop, want map[string]string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var got map[string]string
	for time.Now().Before(deadline) {
		var err error
		got, err = ruleSet(p)
		if err == nil && sameRules(got, want) {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("served rules never matched within %s:%s", timeout, rulesDiff(got, want))
}

func sameRules(got, want map[string]string) bool {
	if len(got) != len(want) {
		return false
	}
	for k, v := range want {
		if got[k] != v {
			return false
		}
	}
	return true
}

func rulesDiff(got, want map[string]string) string {
	var b strings.Builder
	var missing, extra []string
	for k, v := range want {
		if got[k] != v {
			missing = append(missing, fmt.Sprintf("%s -> %s (have %q)", k, v, got[k]))
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			extra = append(extra, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	for _, m := range missing {
		fmt.Fprintf(&b, "\n  missing: %s", m)
	}
	for _, e := range extra {
		fmt.Fprintf(&b, "\n  unexpected: %s", e)
	}
	return b.String()
}

// Two upstreams, distinct names: the served zone is the union.
func TestTwoUpstreamsAreMerged(t *testing.T) {
	requireEtc(t)

	a := newFeedT(t, "deny-a.rig.test.")
	a.Set("from-a.example.", NXDOMAIN)
	b := newFeedT(t, "deny-b.rig.test.")
	b.Set("from-b.example.", NXDOMAIN)

	p := startPop(t, PopConfig{
		Sources: []Source{
			XfrSource("upstream-a", Denylist, a),
			XfrSource("upstream-b", Denylist, b),
		},
	})

	if err := waitForRules(p, wantRules(p, "from-a.example.", "from-b.example."), 30*time.Second); err != nil {
		t.Fatalf("the two upstreams were not merged: %v", err)
	}
}

// A name carried by BOTH upstreams must survive removal from one of them.
//
// This is where a per-source delta could go wrong in a way a single-feed test
// cannot see: the removal is real for the source that dropped it, but the name
// is still denylisted, so the SERVED zone must not change.
func TestNameInTwoUpstreamsSurvivesRemovalFromOne(t *testing.T) {
	requireEtc(t)

	const shared = "shared.example."
	a := newFeedT(t, "deny-a.rig.test.")
	a.Set(shared, NXDOMAIN)
	a.Set("only-a.example.", NXDOMAIN)
	b := newFeedT(t, "deny-b.rig.test.")
	b.Set(shared, NXDOMAIN)

	p := startPop(t, PopConfig{
		Sources: []Source{
			XfrSource("upstream-a", Denylist, a),
			XfrSource("upstream-b", Denylist, b),
		},
	})
	if err := waitForRules(p, wantRules(p, shared, "only-a.example."), 30*time.Second); err != nil {
		t.Fatalf("initial merge: %v", err)
	}

	// Drop the shared name from A only. B still carries it, so it must still
	// be served.
	a.Remove(shared)
	if err := waitForRules(p, wantRules(p, shared, "only-a.example."), 20*time.Second); err != nil {
		t.Errorf("a name still carried by upstream-b stopped being served after upstream-a dropped it: %v", err)
	}

	// Now drop it from B as well: with no source left carrying it, it must go.
	b.Remove(shared)
	if err := waitForRules(p, wantRules(p, "only-a.example."), 20*time.Second); err != nil {
		t.Errorf("a name dropped by every upstream is still served: %v", err)
	}
}

// Sustained churn across several upstreams: pop must converge on the union
// after every round, and the IXFR chain must still describe the same zone at
// the end as a fresh AXFR does.
//
// The two halves matter together. Convergence alone says the full-zone view is
// right; the chain check says a downstream that only ever saw the deltas ends
// up in the same place. Under churn from several sources at once is exactly
// where those two could diverge.
func TestChurnAcrossUpstreamsConvergesAndChainAgrees(t *testing.T) {
	requireEtc(t)

	feeds := []*Feed{
		newFeedT(t, "deny-a.rig.test."),
		newFeedT(t, "deny-b.rig.test."),
		newFeedT(t, "deny-c.rig.test."),
	}
	feeds[0].Set("anchor.example.", NXDOMAIN) // so there is a zone from the start

	p := startPop(t, PopConfig{
		Sources: []Source{
			XfrSource("upstream-a", Denylist, feeds[0]),
			XfrSource("upstream-b", Denylist, feeds[1]),
			XfrSource("upstream-c", Denylist, feeds[2]),
		},
	})
	if err := waitForRules(p, wantRules(p, "anchor.example."), 30*time.Second); err != nil {
		t.Fatalf("pop never served the initial feed: %v", err)
	}

	base, baseSerial := zoneNow(t, p)

	const seed = 20260824
	churn := NewChurn(seed, 12, feeds...)
	defer func() {
		if t.Failed() {
			t.Logf("churn seed %d, operations in order:", seed)
			for i, op := range churn.Ops() {
				t.Logf("  %3d. %s", i+1, op)
			}
		}
	}()

	for round := 0; round < 8; round++ {
		for i := 0; i < 3; i++ {
			churn.Step()
		}
		if err := waitForRules(p, wantRules(p, churn.Expected()...), 30*time.Second); err != nil {
			t.Fatalf("round %d did not converge: %v", round, err)
		}
	}

	want, headSerial := zoneNow(t, p)
	if headSerial == baseSerial {
		t.Fatalf("the serial never moved across %d rounds of churn", 8)
	}
	t.Logf("churn: serial %d -> %d, %d records now", baseSerial, headSerial, len(want))

	rrs, err := p.IXFR(baseSerial)
	if err != nil {
		t.Fatalf("IXFR from %d: %v", baseSerial, err)
	}
	got, err := ApplyIXFR(base, rrs)
	if err != nil {
		t.Fatalf("applying the IXFR response: %v", err)
	}
	if !got.Incremental {
		t.Fatalf("pop answered with the whole zone, so the delta path went untested")
	}
	t.Logf("chain: %d deltas, ending at serial %d", got.Deltas, got.Serial)

	if got.Serial != headSerial {
		t.Errorf("the chain ends at serial %d but the zone is at %d", got.Serial, headSerial)
	}
	if !got.Body.Equal(want) {
		t.Errorf("after churn from %d upstreams, a downstream following the chain would hold a different zone:%s",
			len(feeds), got.Body.Diff(want))
	}
}

// A burst: many changes across all upstreams with no pause, so several land
// between one poll and the next, and different sources change while pop is
// mid-transfer on another.
//
// The round-by-round test above always lets pop settle, which is the gentle
// case. This is the one where an update can be lost -- a transfer that started
// before a change and finished after it, committed as though it had seen the
// whole thing.
func TestBurstChurnLosesNothing(t *testing.T) {
	requireEtc(t)

	feeds := []*Feed{
		newFeedT(t, "deny-a.rig.test."),
		newFeedT(t, "deny-b.rig.test."),
		newFeedT(t, "deny-c.rig.test."),
	}
	feeds[0].Set("anchor.example.", NXDOMAIN)

	p := startPop(t, PopConfig{
		Sources: []Source{
			XfrSource("upstream-a", Denylist, feeds[0]),
			XfrSource("upstream-b", Denylist, feeds[1]),
			XfrSource("upstream-c", Denylist, feeds[2]),
		},
	})
	if err := waitForRules(p, wantRules(p, "anchor.example."), 30*time.Second); err != nil {
		t.Fatalf("pop never served the initial feed: %v", err)
	}

	const seed = 20260825
	churn := NewChurn(seed, 20, feeds...)
	defer func() {
		if t.Failed() {
			t.Logf("churn seed %d, operations in order:", seed)
			for i, op := range churn.Ops() {
				t.Logf("  %3d. %s", i+1, op)
			}
		}
	}()

	for i := 0; i < 40; i++ {
		churn.Step()
	}

	// Everything must arrive eventually. Nothing here is about how fast: the
	// claim is that no update is DROPPED, however they interleave.
	if err := waitForRules(p, wantRules(p, churn.Expected()...), 60*time.Second); err != nil {
		t.Fatalf("pop did not converge after a burst of 40 changes: %v", err)
	}

	// And a second burst on top of the first, from a state that is no longer
	// quiet.
	for i := 0; i < 20; i++ {
		churn.Step()
	}
	if err := waitForRules(p, wantRules(p, churn.Expected()...), 60*time.Second); err != nil {
		t.Fatalf("pop did not converge after a second burst: %v", err)
	}
}
