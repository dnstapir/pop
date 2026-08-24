package rig

import (
	"strings"
	"testing"
	"time"
)

// Where does an upstream change actually stop? (#195)
//
// Deliberately verbose: the STEP lines are the diagnostic, and they are what
// separates "the data never arrived" from "the data arrived and nothing
// rebuilt the zone". Those two look identical from outside, because in both
// the served zone is simply stale.
//
// It asserts two distinct defects, either of which is enough to keep a
// downstream on stale data:
//
//  1. an upstream change never triggers a rebuild, so no snapshot is
//     published at all;
//  2. a rebuild that IS forced publishes changed content under an UNCHANGED
//     serial, so a downstream has no reason to fetch it.
//
// The second matters on its own: fixing the first by calling GenerateRpzAxfr
// from the refresh path would still leave the serial standing still.
func TestTraceUpstreamChange(t *testing.T) {
	requireEtc(t)
	reproducesOpenBug(t, "#195", "upstream changes are ingested but never republished")

	feed := newFeedT(t, "deny.rig.test.")
	feed.Set("first.example.", NXDOMAIN)

	p := startPop(t, PopConfig{Sources: []Source{XfrSource("upstream", Denylist, feed)}})
	if _, err := p.WaitForRule("first.example."+p.ZoneName, NXDOMAIN, 20*time.Second); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	s0, _ := p.Serial()
	t.Logf("STEP 0  baseline served, serial=%d", s0)

	// Change upstream.
	feed.Set("second.example.", NXDOMAIN)
	t.Logf("STEP 1  upstream now at serial %d, carrying second.example.", feed.Serial())

	// Give pop several refresh cycles (its SOA refresh here is 1s).
	time.Sleep(5 * time.Second)

	s1, _ := p.Serial()
	served := servedRules(t, p)
	_, inZone := served[strings.ToLower("second.example."+p.ZoneName)]
	t.Logf("STEP 2  after 5s: pop serial=%d (was %d), second.example in served zone=%v, zone has %d rules",
		s1, s0, inZone, len(served))

	// Now force a rebuild from whatever pop currently holds in its lists.
	out, err := p.GenOutput()
	if err != nil {
		t.Fatalf("STEP 3  gen-output failed: %v", err)
	}
	inLists := false
	for n := range out.DenylistedNames {
		if strings.EqualFold(n, "second.example.") {
			inLists = true
		}
	}
	inRebuild := false
	for _, r := range out.RpzOutput {
		if strings.Contains(strings.ToLower(r.Name), "second.example") {
			inRebuild = true
		}
	}
	t.Logf("STEP 3  forced rebuild: second.example in DenylistedNames=%v, in RpzOutput=%v (%d denylisted, %d output)",
		inLists, inRebuild, len(out.DenylistedNames), len(out.RpzOutput))

	s2, _ := p.Serial()
	served2 := servedRules(t, p)
	_, inZone2 := served2[strings.ToLower("second.example."+p.ZoneName)]
	t.Logf("STEP 4  after forced rebuild: pop serial=%d, second.example in served zone=%v, zone has %d rules",
		s2, inZone2, len(served2))

	if !inLists {
		t.Fatalf("the transferred name never reached pop's lists; the loss is EARLIER than this test assumes")
	}

	// Defect 1: the upstream change should have reached the served zone on its
	// own, without anyone forcing a rebuild.
	if !inZone {
		t.Errorf("after 5 refresh cycles the upstream change is in pop's lists but not in the served zone: "+
			"no rebuild was triggered (serial still %d)", s1)
	}

	// Defect 2: the forced rebuild changed what is served without changing the
	// serial, so no downstream will fetch it.
	if inZone2 && s2 == s0 {
		t.Errorf("a rebuild changed the served zone from %d rules to %d but left the serial at %d; "+
			"a downstream holding that serial has no reason to transfer",
			len(served), len(served2), s2)
	}
}
