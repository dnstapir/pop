/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"testing"

	"github.com/dnstapir/tapir"
	"github.com/miekg/dns"
)

// Tests that put pop's shared RPZ state under concurrent access.
//
// Everything in this file exists because the repository's high-priority
// backlog is dominated by ONE bug class -- data races on the served zone --
// and until now nothing in the test suite started a second goroutine, so
// `go test -race` had nothing to observe and passed in 1.4 seconds while the
// races sat in the code.
//
// The reproducers are opt-in. See raceReproEnv below for why.

// raceReproEnv gates the reproducers that are EXPECTED to fail.
//
// They demonstrate open, unfixed bugs (#149, #150, #151, #153). Leaving them
// on by default would paint CI red on every PR for defects the PR did not
// introduce, and a permanently red gate is worse than no gate: it gets
// ignored, then removed. So they are skipped unless explicitly asked for:
//
//	POP_RACE_REPRO=1 go test -race -run Concurrent -v ./...
//
// When the fix for a given issue lands (PR #174 carries the snapshot-based
// model for #149), the corresponding reproducer should become unconditional
// -- that is the point at which it turns from a demonstration into a
// regression test, and it is the cheapest possible proof that the fix works.
const raceReproEnv = "POP_RACE_REPRO"

func skipUnlessRaceRepro(t *testing.T, issues string) {
	t.Helper()
	if os.Getenv(raceReproEnv) != "1" {
		t.Skipf("reproduces open issue(s) %s; set %s=1 to run it", issues, raceReproEnv)
	}
}

// discardResponseWriter is the minimum dns.ResponseWriter that QueryResponder
// needs. It only ever calls WriteMsg, and we do not care what it wrote -- the
// point is to exercise the read of pd.Rpz.Axfr.Data on the DNS-handler side,
// which is where the engine's writes collide with it.
type discardResponseWriter struct{}

var testAddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}

func (discardResponseWriter) LocalAddr() net.Addr       { return testAddr }
func (discardResponseWriter) RemoteAddr() net.Addr      { return testAddr }
func (discardResponseWriter) WriteMsg(*dns.Msg) error   { return nil }
func (discardResponseWriter) Write([]byte) (int, error) { return 0, nil }
func (discardResponseWriter) Close() error              { return nil }
func (discardResponseWriter) TsigStatus() error         { return nil }
func (discardResponseWriter) TsigTimersOnly(bool)       {}
func (discardResponseWriter) Hijack()                   {}

const testZone = "rpz.example."

// newZoneTestPopData builds the smallest PopData that the zone-mutation and
// zone-read paths will run against: a live Axfr.Data map, an empty IXFR
// chain, and no downstreams -- NotifyDownstreams ranges Downstreams, so an
// empty map makes it a log line rather than a network call.
func newZoneTestPopData(t *testing.T) *PopData {
	t.Helper()
	return &PopData{
		Logger:            log.New(io.Discard, "", 0),
		MqttLogger:        log.New(io.Discard, "", 0),
		Downstreams:       map[string]RpzDownstream{},
		DownstreamSerials: map[string]uint32{},
		Rpz: RpzData{
			CurrentSerial: 1,
			ZoneName:      testZone,
			Axfr: RpzAxfr{
				Serial: 1,
				SOA:    dns.SOA{Hdr: dns.RR_Header{Name: testZone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60}, Ns: "ns." + testZone, Mbox: "hostmaster." + testZone, Serial: 1},
				Data:   map[string]*tapir.RpzName{},
			},
			IxfrChain: []RpzIxfr{},
		},
	}
}

func testRpzName(t *testing.T, name string) *tapir.RpzName {
	t.Helper()
	rr, err := dns.NewRR(name + " 60 IN CNAME .")
	if err != nil {
		t.Fatalf("building CNAME for %s: %v", name, err)
	}
	return &tapir.RpzName{Name: name, RR: &rr, Action: tapir.NXDOMAIN}
}

// ---------------------------------------------------------------------------
// Single-goroutine tests. These pass today, and they cover code that had no
// test at all -- ProcessIxfrIntoAxfr and PruneRpzIxfrChain were both
// completely untested.
// ---------------------------------------------------------------------------

func TestProcessIxfrIntoAxfrAppliesRemovalsAndAdditions(t *testing.T) {
	pd := newZoneTestPopData(t)
	stale := testRpzName(t, "gone.example.")
	pd.Rpz.Axfr.Data[stale.Name] = stale

	fresh := testRpzName(t, "added.example.")
	if err := pd.ProcessIxfrIntoAxfr(RpzIxfr{
		FromSerial: 1, ToSerial: 2,
		Removed: []*tapir.RpzName{stale},
		Added:   []*tapir.RpzName{fresh},
	}); err != nil {
		t.Fatalf("ProcessIxfrIntoAxfr: %v", err)
	}

	if _, exist := pd.Rpz.Axfr.Data[stale.Name]; exist {
		t.Errorf("%s was in Removed but is still in the served zone", stale.Name)
	}
	got, exist := pd.Rpz.Axfr.Data[fresh.Name]
	if !exist {
		t.Fatalf("%s was in Added but is not in the served zone", fresh.Name)
	}
	if got.Name != fresh.Name {
		t.Errorf("stored entry is %q, want %q", got.Name, fresh.Name)
	}
}

// An empty DownstreamSerials map means no downstream has told us where it is,
// so there is no safe floor and nothing may be pruned. Getting this wrong
// would silently discard IXFR history that downstreams still need, which is
// the failure mode behind #160.
func TestPruneRpzIxfrChainPrunesNothingWithoutDownstreamSerials(t *testing.T) {
	pd := newZoneTestPopData(t)
	for i := uint32(1); i <= 5; i++ {
		pd.Rpz.IxfrChain = append(pd.Rpz.IxfrChain, RpzIxfr{FromSerial: i, ToSerial: i + 1})
	}

	if err := pd.PruneRpzIxfrChain(); err != nil {
		t.Fatalf("PruneRpzIxfrChain: %v", err)
	}
	if len(pd.Rpz.IxfrChain) != 5 {
		t.Errorf("chain length %d, want 5 kept: with no downstream serials there is no floor to prune to",
			len(pd.Rpz.IxfrChain))
	}
}

// ---------------------------------------------------------------------------
// Concurrency reproducers. Opt-in; see raceReproEnv.
// ---------------------------------------------------------------------------

// The engine mutating the served zone while the DNS handler answers from it.
// This is the production pairing exactly: ProcessIxfrIntoAxfr writes
// pd.Rpz.Axfr.Data from the refresh path (mqtt.go, no lock held anywhere in
// that file) while QueryResponder reads the same map from the DNS handler
// (dnshandler.go:429, outside the only lock in that file).
//
// Reproduces #149 (concurrent map read/write on Rpz.Axfr.Data, reported as a
// runtime panic under normal load) and #153 (unlocked reads from the handler).
func TestConcurrentAxfrDataReadWrite(t *testing.T) {
	skipUnlessRaceRepro(t, "#149, #153")

	pd := newZoneTestPopData(t)
	const iterations = 500

	var wg sync.WaitGroup
	wg.Add(2)

	// Engine side: add and remove names, as an inbound IXFR would.
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			tn := testRpzName(t, fmt.Sprintf("churn%d.example.", i))
			_ = pd.ProcessIxfrIntoAxfr(RpzIxfr{
				FromSerial: uint32(i) + 1, ToSerial: uint32(i) + 2,
				Added: []*tapir.RpzName{tn},
			})
			_ = pd.ProcessIxfrIntoAxfr(RpzIxfr{
				FromSerial: uint32(i) + 2, ToSerial: uint32(i) + 3,
				Removed: []*tapir.RpzName{tn},
			})
		}
	}()

	// DNS side: answer queries out of the same map.
	go func() {
		defer wg.Done()
		w := discardResponseWriter{}
		for i := 0; i < iterations; i++ {
			qname := fmt.Sprintf("churn%d.example.", i)
			r := new(dns.Msg)
			r.SetQuestion(qname, dns.TypeCNAME)
			_ = pd.QueryResponder(w, r, qname, dns.TypeCNAME, pd.Logger)
		}
	}()

	wg.Wait()
}

// PruneRpzIxfrChain reslices pd.Rpz.IxfrChain and reads pd.DownstreamSerials
// with no lock at all (xfr.go). It is called per inbound IXFR request from
// RpzIxfrOut, so two downstreams asking at once is enough -- and since there
// is no ACL on IXFR (#152), who gets to cause that is not controlled either.
//
// Reproduces #150 (unsynchronized IxfrChain access) and #151 (Prune runs
// fully unlocked).
func TestConcurrentIxfrChainPrune(t *testing.T) {
	skipUnlessRaceRepro(t, "#150, #151")

	pd := newZoneTestPopData(t)
	for i := uint32(1); i <= 200; i++ {
		pd.Rpz.IxfrChain = append(pd.Rpz.IxfrChain, RpzIxfr{FromSerial: i, ToSerial: i + 1})
	}
	pd.DownstreamSerials["192.0.2.1"] = 100

	const goroutines = 4
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				// Each "downstream" also reports its position, which is what
				// the real IXFR path does before pruning.
				pd.DownstreamSerials[fmt.Sprintf("192.0.2.%d", g+2)] = uint32(100 + i)
				_ = pd.PruneRpzIxfrChain()
			}
		}(g)
	}
	wg.Wait()
}
