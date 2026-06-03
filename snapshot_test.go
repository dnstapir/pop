/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package main

// Tests for the immutable-snapshot concurrency model (#149). Three kinds:
//   - property tests for the pure helpers (pruneIxfrChain, downstreamTracker),
//   - a concurrency stress test that MUST be run under `go test -race` — it is
//     the regression test for the concurrent map read/write panic the snapshot
//     model removes (it would have panicked against the old in-place code),
//   - an in-process RpzIxfrOut test that drives the real serving code with a
//     fake dns.ResponseWriter and asserts the emitted IXFR wire structure.

import (
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/dnstapir/tapir"
	"github.com/miekg/dns"
)

func discardLogger() *log.Logger { return log.New(io.Discard, "", 0) }

// --- pruneIxfrChain --------------------------------------------------------

func chainOf(pairs ...[2]uint32) []RpzIxfr {
	var c []RpzIxfr
	for _, p := range pairs {
		c = append(c, RpzIxfr{FromSerial: p[0], ToSerial: p[1]})
	}
	return c
}

func TestPruneIxfrChain(t *testing.T) {
	// chain covering serials 1->2->3->4->5 (oldest first)
	full := chainOf([2]uint32{1, 2}, [2]uint32{2, 3}, [2]uint32{3, 4}, [2]uint32{4, 5})

	tests := []struct {
		name      string
		chain     []RpzIxfr
		low       uint32
		have      bool
		wantFroms []uint32 // expected FromSerials after prune
	}{
		{
			name:      "no downstreams -> unchanged",
			chain:     full,
			have:      false,
			wantFroms: []uint32{1, 2, 3, 4},
		},
		{
			name:      "slowest at 1 -> keep everything (all deltas advance past 1)",
			chain:     full,
			low:       1,
			have:      true,
			wantFroms: []uint32{1, 2, 3, 4},
		},
		{
			name:      "slowest at 3 -> drop deltas fully superseded (ToSerial <= 3)",
			chain:     full,
			low:       3,
			have:      true,
			wantFroms: []uint32{3, 4}, // 1->2 and 2->3 dropped
		},
		{
			name:      "slowest already at latest -> keep most recent delta only",
			chain:     full,
			low:       5,
			have:      true,
			wantFroms: []uint32{4},
		},
		{
			name:      "empty chain",
			chain:     nil,
			low:       3,
			have:      true,
			wantFroms: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := pruneIxfrChain(tc.chain, tc.low, tc.have)
			var froms []uint32
			for _, ix := range got {
				froms = append(froms, ix.FromSerial)
			}
			if len(froms) != len(tc.wantFroms) {
				t.Fatalf("got FromSerials %v, want %v", froms, tc.wantFroms)
			}
			for i := range froms {
				if froms[i] != tc.wantFroms[i] {
					t.Fatalf("got FromSerials %v, want %v", froms, tc.wantFroms)
				}
			}
		})
	}
}

// --- downstreamTracker (under -race) ---------------------------------------

func TestDownstreamTracker(t *testing.T) {
	tr := newDownstreamTracker()

	if _, have := tr.lowest(); have {
		t.Fatalf("empty tracker should report no downstreams")
	}

	tr.record("10.0.0.1", 5)
	tr.record("10.0.0.2", 3)
	tr.record("10.0.0.3", 9)
	low, have := tr.lowest()
	if !have || low != 3 {
		t.Fatalf("lowest = %d (have=%v), want 3", low, have)
	}

	// Concurrent record() + lowest() — meaningful under -race.
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func(n int) { defer wg.Done(); tr.record("10.0.0.1", uint32(n)) }(i)
		go func() { defer wg.Done(); _, _ = tr.lowest() }()
	}
	wg.Wait()
}

// --- snapshot immutability -------------------------------------------------

func TestSnapshotImmutability(t *testing.T) {
	pd := newSnapshotTestPopData()

	// Publish an initial snapshot with one name.
	rr := mustCNAME("evil.example.rpz.zone.", ".")
	pd.snapshot.Store(&ZoneSnapshot{
		ZoneName: "rpz.zone.",
		Serial:   2,
		Data: map[string]*tapir.RpzName{
			"evil.example.rpz.zone.": {Name: "evil.example.", RR: &rr, Action: tapir.NXDOMAIN},
		},
	})

	snap := pd.snapshot.Load()

	// Publishing a new snapshot must not mutate the one a reader already holds.
	pd.snapshot.Store(&ZoneSnapshot{ZoneName: "rpz.zone.", Serial: 3, Data: map[string]*tapir.RpzName{}})

	if snap.Serial != 2 {
		t.Errorf("held snapshot serial mutated: got %d, want 2", snap.Serial)
	}
	if _, ok := snap.Data["evil.example.rpz.zone."]; !ok {
		t.Errorf("held snapshot Data mutated: entry disappeared")
	}
	if cur := pd.snapshot.Load(); cur.Serial != 3 {
		t.Errorf("current snapshot serial = %d, want 3", cur.Serial)
	}
}

// --- concurrent serve + update (the -race regression test) -----------------
//
// Spawns readers that iterate the published snapshot's Data map while the
// "engine" repeatedly publishes new snapshots. Under the OLD in-place code
// this pattern (map iteration vs map write) is a hard runtime panic; under
// the snapshot model each reader holds an immutable map. Run with -race.

func TestConcurrentServeAndUpdate(t *testing.T) {
	pd := newSnapshotTestPopData()
	pd.snapshot.Store(&ZoneSnapshot{ZoneName: "rpz.zone.", Serial: 1, Data: map[string]*tapir.RpzName{}})

	const readers = 8
	const rounds = 200
	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Readers: continuously Load() and iterate the immutable Data map.
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					snap := pd.snapshot.Load()
					n := 0
					for range snap.Data {
						n++
					}
					_ = n
				}
			}
		}()
	}

	// Engine: publish a fresh snapshot each round (fresh map, never mutated
	// after Store).
	for r := 0; r < rounds; r++ {
		data := make(map[string]*tapir.RpzName, r)
		for j := 0; j <= r%20; j++ {
			name := dns.Fqdn("n"+strconv.Itoa(j)+".example") + "rpz.zone."
			rr := mustCNAME(name, ".")
			data[name] = &tapir.RpzName{Name: name, RR: &rr, Action: tapir.NXDOMAIN}
		}
		pd.snapshot.Store(&ZoneSnapshot{ZoneName: "rpz.zone.", Serial: uint32(r + 2), Data: data})
	}
	close(stop)
	wg.Wait()
}

// --- in-process RpzIxfrOut wire-structure test -----------------------------
//
// Drives the real RpzIxfrOut with a fake ResponseWriter and asserts the
// emitted IXFR has the documented shape:
//   leading SOA(current) | FROM-SOA | removals | TO-SOA | additions | trailing SOA(current)

func TestRpzIxfrOutStructure(t *testing.T) {
	pd := newSnapshotTestPopData()
	pd.downstreamSerials = newDownstreamTracker()
	pd.ComponentStatusCh = make(chan tapir.ComponentStatusUpdate, 16)
	// Drain status updates so RpzIxfrOut's sends don't block.
	go func() {
		for range pd.ComponentStatusCh {
		}
	}()

	soa := mustSOA("rpz.zone.", 3)
	delRR := mustCNAME("gone.example.rpz.zone.", ".")
	addRR := mustCNAME("new.example.rpz.zone.", ".")
	pd.snapshot.Store(&ZoneSnapshot{
		ZoneName: "rpz.zone.",
		Serial:   3,
		SOA:      soa,
		Data:     map[string]*tapir.RpzName{"new.example.rpz.zone.": {Name: "new.example.", RR: &addRR}},
		IxfrChain: []RpzIxfr{{
			FromSerial: 2, ToSerial: 3,
			Removed: []*tapir.RpzName{{Name: "gone.example.", RR: &delRR}},
			Added:   []*tapir.RpzName{{Name: "new.example.", RR: &addRR}},
		}},
	})

	// IXFR request claiming serial 2.
	req := new(dns.Msg)
	req.SetIxfr("rpz.zone.", 2, "mname.", "hostmaster.")

	fw := newFakeXfrWriter()
	_, _, err := pd.RpzIxfrOut(fw, req)
	if err != nil {
		t.Fatalf("RpzIxfrOut error: %v", err)
	}

	rrs := fw.allRRs()
	if len(rrs) < 6 {
		t.Fatalf("expected >=6 RRs in IXFR, got %d: %v", len(rrs), rrs)
	}
	// First and last must be SOA at the current serial (3).
	first, firstOK := rrs[0].(*dns.SOA)
	last, lastOK := rrs[len(rrs)-1].(*dns.SOA)
	if !firstOK || first.Serial != 3 {
		t.Errorf("leading RR should be SOA serial 3, got %v", rrs[0])
	}
	if !lastOK || last.Serial != 3 {
		t.Errorf("trailing RR should be SOA serial 3, got %v", rrs[len(rrs)-1])
	}
	// Somewhere in between: FROM-SOA(2) then TO-SOA(3).
	var sawFrom2, sawTo3 bool
	for _, rr := range rrs[1 : len(rrs)-1] {
		if s, ok := rr.(*dns.SOA); ok {
			if s.Serial == 2 {
				sawFrom2 = true
			}
			if s.Serial == 3 && sawFrom2 {
				sawTo3 = true
			}
		}
	}
	if !sawFrom2 || !sawTo3 {
		t.Errorf("expected FROM-SOA(2) then TO-SOA(3) inside the IXFR; sawFrom2=%v sawTo3=%v", sawFrom2, sawTo3)
	}
}

// --- real engine publish path under -race ----------------------------------
//
// Closes the gap that TestConcurrentServeAndUpdate left: that test published
// synthetic snapshots via Store(). This one drives the REAL GenerateRpzIxfr
// (the engine's incremental publish path — copies snap.Data, applies the
// delta, builds/prunes the chain, Stores) on a single "engine" goroutine while
// readers iterate the published snapshot. Under -race this exercises the actual
// production publish code against concurrent serving.

func TestGenerateRpzIxfrConcurrentWithReaders(t *testing.T) {
	pd := newSnapshotTestPopData()
	pd.Policy = PopPolicy{
		Logger:          discardLogger(),
		AllowlistAction: tapir.ALLOWLIST,
		DenylistAction:  tapir.NODATA,
		Doubtlist:       DoubtlistPolicy{NumSources: 1, NumSourcesAction: tapir.NXDOMAIN},
	}
	pd.Lists = map[string]map[string]*tapir.WBGlist{
		"allowlist": {},
		"denylist":  {},
		"doubtlist": {"feed": {Name: "feed", Type: "doubtlist", Format: "map", Names: map[string]tapir.TapirName{}}},
	}
	pd.downstreamSerials = newDownstreamTracker()
	pd.Downstreams = map[string]RpzDownstream{} // empty -> NotifyDownstreams is a no-op
	pd.snapshot.Store(&ZoneSnapshot{ZoneName: "rpz.zone.", Serial: 1, SOA: mustSOA("rpz.zone.", 1), Data: map[string]*tapir.RpzName{}})

	const readers = 6
	const rounds = 150
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					snap := pd.snapshot.Load()
					for range snap.Data {
					}
					for range snap.IxfrChain {
					}
				}
			}
		}()
	}

	// "Engine" goroutine: add then remove a name each round via the real
	// GenerateRpzIxfr publish path. (decide() with NumSources:1 makes a single
	// doubtlist hit NXDOMAIN, so adds produce output.)
	feed := pd.Lists["doubtlist"]["feed"]
	for r := 0; r < rounds; r++ {
		name := dns.Fqdn("n" + strconv.Itoa(r%32) + ".example")
		feed.Names[name] = tapir.TapirName{Name: name}
		if _, err := pd.GenerateRpzIxfr(&tapir.TapirMsg{Added: []tapir.Domain{{Name: name}}}); err != nil {
			t.Fatalf("GenerateRpzIxfr add: %v", err)
		}
		delete(feed.Names, name)
		if _, err := pd.GenerateRpzIxfr(&tapir.TapirMsg{Removed: []tapir.Domain{{Name: name}}}); err != nil {
			t.Fatalf("GenerateRpzIxfr remove: %v", err)
		}
	}
	close(stop)
	wg.Wait()

	// Sanity: the chain stayed within the hard bound throughout.
	if snap := pd.snapshot.Load(); len(snap.IxfrChain) > maxIxfrChain {
		t.Errorf("IxfrChain grew past maxIxfrChain: %d", len(snap.IxfrChain))
	}
}

// --- reaper two-phase commit (CodeRabbit reaper.go finding) -----------------
//
// If the snapshot publish fails, the reaper must keep the ReaperData bucket so
// the next tick can retry — otherwise the expired names are gone from pd.Lists
// but never removed from the served zone, and the retry source is lost.

func TestReaperKeepsReaperDataOnPublishFailure(t *testing.T) {
	pd := newSnapshotTestPopData()
	pd.Policy = PopPolicy{Logger: discardLogger(), AllowlistAction: tapir.ALLOWLIST, DenylistAction: tapir.NODATA,
		Doubtlist: DoubtlistPolicy{NumSources: 1, NumSourcesAction: tapir.NXDOMAIN}}
	pd.downstreamSerials = newDownstreamTracker()
	pd.Downstreams = map[string]RpzDownstream{}
	pd.ReaperInterval = time.Minute

	// A doubtlist entry due for reaping in the current time slot.
	timekey := timeNowTrunc(pd.ReaperInterval)
	name := dns.Fqdn("expired.example")
	feed := &tapir.WBGlist{
		Name: "feed", Type: "doubtlist", Format: "map",
		Names:      map[string]tapir.TapirName{name: {Name: name}},
		ReaperData: map[time.Time]map[string]bool{timekey: {name: true}},
	}
	pd.Lists = map[string]map[string]*tapir.WBGlist{
		"allowlist": {}, "denylist": {}, "doubtlist": {"feed": feed},
	}

	// Force GenerateRpzIxfr to fail: no snapshot published yet -> it errors.
	// (pd.snapshot is the zero value here.)
	err := pd.Reaper(false)
	if err == nil {
		t.Fatalf("expected Reaper to return the publish error, got nil")
	}
	// The name was removed from the source list (phase 1)...
	if _, still := feed.Names[name]; still {
		t.Errorf("name should have been removed from Names in phase 1")
	}
	// ...but the ReaperData bucket MUST survive for the next tick to retry.
	if _, ok := feed.ReaperData[timekey]; !ok {
		t.Errorf("ReaperData[timekey] was cleared despite publish failure; retry data lost")
	}
	if !feed.ReaperData[timekey][name] {
		t.Errorf("ReaperData bucket no longer contains %q after failed publish", name)
	}
}

func timeNowTrunc(d time.Duration) time.Time { return time.Now().Truncate(d) }

// --- helpers ---------------------------------------------------------------

func newSnapshotTestPopData() *PopData {
	pd := &PopData{}
	pd.Logger = discardLogger()
	pd.Rpz = RpzData{ZoneName: "rpz.zone.", CurrentSerial: 1}
	return pd
}

func mustCNAME(owner, target string) dns.RR {
	rr := new(dns.CNAME)
	rr.Hdr = dns.RR_Header{Name: owner, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 3600}
	rr.Target = target
	return dns.RR(rr)
}

func mustSOA(zone string, serial uint32) dns.SOA {
	return dns.SOA{
		Hdr:     dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns:      "mname.",
		Mbox:    "hostmaster.",
		Serial:  serial,
		Refresh: 60, Retry: 60, Expire: 86400, Minttl: 60,
	}
}

// fakeXfrWriter captures the dns.Msgs that dns.Transfer.Out writes.
type fakeXfrWriter struct {
	mu   sync.Mutex
	msgs []*dns.Msg
}

func newFakeXfrWriter() *fakeXfrWriter { return &fakeXfrWriter{} }

func (f *fakeXfrWriter) allRRs() []dns.RR {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []dns.RR
	for _, m := range f.msgs {
		out = append(out, m.Answer...)
	}
	return out
}

func (f *fakeXfrWriter) WriteMsg(m *dns.Msg) error {
	f.mu.Lock()
	f.msgs = append(f.msgs, m)
	f.mu.Unlock()
	return nil
}
func (f *fakeXfrWriter) Write(b []byte) (int, error) { return len(b), nil }
func (f *fakeXfrWriter) Close() error                { return nil }
func (f *fakeXfrWriter) TsigStatus() error           { return nil }
func (f *fakeXfrWriter) TsigTimersOnly(bool)         {}
func (f *fakeXfrWriter) Hijack()                     {}
func (f *fakeXfrWriter) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}
}
func (f *fakeXfrWriter) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.2"), Port: 12345}
}
