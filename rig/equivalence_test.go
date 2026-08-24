/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * THE invariant for a zone served two ways: a downstream that follows the chain
 * of IXFR deltas must end up holding exactly what a fresh AXFR would give it.
 *
 * Nothing checked this before, and pop only started publishing a delta per
 * upstream change recently (#195/#197/#198) -- so the incremental path is both
 * newly load-bearing and, until now, unverified. Drift here is silent: the
 * downstream serves a zone that no longer matches its source, reports no error,
 * and nothing upstream can tell.
 */
package rig

import (
	"fmt"
	"testing"
	"time"
)

// zoneNow is the served zone as a comparable set, plus its serial.
func zoneNow(t *testing.T, p *Pop) (ZoneBody, uint32) {
	t.Helper()
	rrs, err := p.AXFR()
	if err != nil {
		t.Fatalf("AXFR: %v", err)
	}
	serial, err := p.Serial()
	if err != nil {
		t.Fatalf("Serial: %v", err)
	}
	return ZoneBodyOf(rrs), serial
}

// The headline: take a baseline, churn the upstream, then reconstruct the zone
// from the deltas alone and require it to match the real thing.
func TestIxfrChainRebuildsTheZone(t *testing.T) {
	requireEtc(t)

	feed := newFeedT(t, "deny.rig.test.")
	feed.Set("first.example.", NXDOMAIN)

	p := startPop(t, PopConfig{
		Sources: []Source{XfrSource("upstream", Denylist, feed)},
	})
	if _, err := p.WaitForRule("first.example."+p.ZoneName, NXDOMAIN, 30*time.Second); err != nil {
		t.Fatalf("pop never served the feed: %v", err)
	}

	base, baseSerial := zoneNow(t, p)
	t.Logf("baseline: serial %d, %d records", baseSerial, len(base))

	// Churn: additions, and removals of both a name that was in the baseline
	// and one added along the way. A chain that only ever grows would not
	// exercise the removal side of the delta at all.
	for i := 0; i < 4; i++ {
		name := fmt.Sprintf("churn%d.example.", i)
		feed.Set(name, NXDOMAIN)
		if _, _, err := p.WaitForPresent(name+p.ZoneName, 30*time.Second); err != nil {
			t.Fatalf("added %s never arrived: %v", name, err)
		}
	}
	feed.Remove("churn1.example.")
	if err := p.WaitForAbsent("churn1.example."+p.ZoneName, 30*time.Second); err != nil {
		t.Fatalf("removed churn1 never went away: %v", err)
	}
	feed.Remove("first.example.")
	if err := p.WaitForAbsent("first.example."+p.ZoneName, 30*time.Second); err != nil {
		t.Fatalf("removed first.example never went away: %v", err)
	}

	want, headSerial := zoneNow(t, p)
	if headSerial == baseSerial {
		t.Fatalf("the serial never moved across the churn (%d): nothing to compare", headSerial)
	}
	t.Logf("head: serial %d, %d records", headSerial, len(want))

	rrs, err := p.IXFR(baseSerial)
	if err != nil {
		t.Fatalf("IXFR from %d: %v", baseSerial, err)
	}
	got, err := ApplyIXFR(base, rrs)
	if err != nil {
		t.Fatalf("applying the IXFR response: %v", err)
	}

	// Without this the test is vacuous: a whole-zone answer equals the zone by
	// definition and would prove nothing about the delta path.
	if !got.Incremental {
		t.Fatalf("pop answered IXFR from %d with the whole zone, so the delta path was never tested"+
			" (chain could not reach that serial)", baseSerial)
	}
	t.Logf("IXFR: %d deltas, ending at serial %d", got.Deltas, got.Serial)

	if got.Serial != headSerial {
		t.Errorf("the chain ends at serial %d but the zone is at %d", got.Serial, headSerial)
	}
	if !got.Body.Equal(want) {
		t.Errorf("a downstream following the IXFR chain from %d would hold a different zone than AXFR gives:%s",
			baseSerial, got.Body.Diff(want))
	}
}

// A downstream that is already current must be told so, and must not be handed
// a whole zone for nothing.
func TestIxfrAtHeadIsANoOp(t *testing.T) {
	requireEtc(t)

	feed := newFeedT(t, "deny.rig.test.")
	feed.Set("first.example.", NXDOMAIN)

	p := startPop(t, PopConfig{
		Sources: []Source{XfrSource("upstream", Denylist, feed)},
	})
	if _, err := p.WaitForRule("first.example."+p.ZoneName, NXDOMAIN, 30*time.Second); err != nil {
		t.Fatalf("pop never served the feed: %v", err)
	}

	body, serial := zoneNow(t, p)

	rrs, err := p.IXFR(serial)
	if err != nil {
		t.Fatalf("IXFR from the current serial %d: %v", serial, err)
	}
	got, err := ApplyIXFR(body, rrs)
	if err != nil {
		t.Fatalf("applying the IXFR response: %v", err)
	}
	if got.Deltas != 0 {
		t.Errorf("a downstream already at serial %d was sent %d delta(s)", serial, got.Deltas)
	}
	if !got.Body.Equal(body) {
		t.Errorf("an IXFR at the current serial changed the zone:%s", got.Body.Diff(body))
	}
}

// Asking from a serial the chain cannot reach must produce the whole zone, and
// that whole zone must itself be right. This is the fallback pop relies on to
// keep a lagging downstream correct rather than merely quiet.
func TestIxfrFromUnknownSerialFallsBackToFullZone(t *testing.T) {
	requireEtc(t)

	feed := newFeedT(t, "deny.rig.test.")
	feed.Set("first.example.", NXDOMAIN)

	p := startPop(t, PopConfig{
		Sources: []Source{XfrSource("upstream", Denylist, feed)},
	})
	if _, err := p.WaitForRule("first.example."+p.ZoneName, NXDOMAIN, 30*time.Second); err != nil {
		t.Fatalf("pop never served the feed: %v", err)
	}
	want, _ := zoneNow(t, p)

	// A serial far below anything pop has ever published.
	rrs, err := p.IXFR(1)
	if err != nil {
		t.Fatalf("IXFR from serial 1: %v", err)
	}
	got, err := ApplyIXFR(ZoneBody{}, rrs)
	if err != nil {
		t.Fatalf("applying the IXFR response: %v", err)
	}
	if got.Incremental {
		t.Fatalf("pop answered with deltas from a serial it cannot have a chain for")
	}
	if !got.Body.Equal(want) {
		t.Errorf("the full-zone fallback does not match AXFR:%s", got.Body.Diff(want))
	}
}
