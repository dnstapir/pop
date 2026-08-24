/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package rig

import (
	"sync"
	"testing"

	"github.com/miekg/dns"
)

// The feed is the rig's stand-in for an upstream RPZ publisher, so it has to
// be right before anything built on it means anything. These tests drive it
// the way pop does: query the SOA, then pull an AXFR.

const testZone = "rpz.test."

func newTestFeed(t *testing.T) *Feed {
	t.Helper()
	f, err := NewFeed(testZone)
	if err != nil {
		t.Fatalf("NewFeed: %v", err)
	}
	t.Cleanup(f.Close)
	return f
}

// querySOA does what tapir's DoTransfer does: a plain SOA exchange.
func querySOA(t *testing.T, f *Feed) *dns.SOA {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(f.Zone(), dns.TypeSOA)
	r, err := dns.Exchange(m, f.Addr())
	if err != nil {
		t.Fatalf("SOA exchange: %v", err)
	}
	if len(r.Answer) != 1 {
		t.Fatalf("SOA answer has %d RRs, want 1", len(r.Answer))
	}
	soa, ok := r.Answer[0].(*dns.SOA)
	if !ok {
		t.Fatalf("SOA answer is %T, not *dns.SOA", r.Answer[0])
	}
	return soa
}

// axfr does what tapir's ZoneTransferIn does.
func axfr(t *testing.T, f *Feed) []dns.RR {
	t.Helper()
	m := new(dns.Msg)
	m.SetAxfr(f.Zone())
	tr := new(dns.Transfer)
	ch, err := tr.In(m, f.Addr())
	if err != nil {
		t.Fatalf("AXFR In: %v", err)
	}
	var out []dns.RR
	for env := range ch {
		if env.Error != nil {
			t.Fatalf("AXFR envelope: %v", env.Error)
		}
		out = append(out, env.RR...)
	}
	return out
}

// cnames reduces a transfer to the rules it carries: owner -> target.
func cnames(rrs []dns.RR) map[string]string {
	out := map[string]string{}
	for _, rr := range rrs {
		if c, ok := rr.(*dns.CNAME); ok {
			out[c.Hdr.Name] = c.Target
		}
	}
	return out
}

func TestFeedServesSOAWithCurrentSerial(t *testing.T) {
	f := newTestFeed(t)

	if got, want := querySOA(t, f).Serial, f.Serial(); got != want {
		t.Errorf("SOA serial = %d, feed says %d", got, want)
	}

	before := f.Serial()
	f.Set("evil.example.", NXDOMAIN)
	after := querySOA(t, f).Serial
	if after <= before {
		t.Errorf("serial did not advance on Set: %d -> %d; pop only refreshes when it increases", before, after)
	}
}

// The transfer must be a well-formed AXFR — SOA first, SOA last — because
// that is what a slave uses to know it got the whole zone.
func TestFeedAxfrIsWellFormed(t *testing.T) {
	f := newTestFeed(t)
	f.Set("a.example.", NXDOMAIN)
	f.Set("b.example.", PASSTHRU)

	rrs := axfr(t, f)
	if len(rrs) < 4 {
		t.Fatalf("transfer has %d RRs, want at least SOA, NS, 2 CNAMEs, SOA", len(rrs))
	}
	first, ok := rrs[0].(*dns.SOA)
	if !ok {
		t.Fatalf("first RR is %T, want *dns.SOA", rrs[0])
	}
	last, ok := rrs[len(rrs)-1].(*dns.SOA)
	if !ok {
		t.Fatalf("last RR is %T, want *dns.SOA", rrs[len(rrs)-1])
	}
	if first.Serial != last.Serial {
		t.Errorf("opening SOA serial %d != closing %d: the transfer straddled a change",
			first.Serial, last.Serial)
	}

	var sawNS bool
	for _, rr := range rrs {
		if _, ok := rr.(*dns.NS); ok {
			sawNS = true
		}
	}
	if !sawNS {
		t.Error("no NS RR in the transfer")
	}
}

// Every action must reach the wire as the RPZ target the specification gives
// it. This is the rig's independent statement of that mapping; if it ever
// disagrees with pop's, one of them is wrong and we want to be told.
func TestFeedRendersEveryActionAsItsRpzTarget(t *testing.T) {
	f := newTestFeed(t)
	want := map[string]string{
		"block.example." + testZone:  ".",
		"nodata.example." + testZone: "*.",
		"drop.example." + testZone:   "rpz-drop.",
		"allow.example." + testZone:  "rpz-passthru.",
	}
	f.Set("block.example.", NXDOMAIN)
	f.Set("nodata.example.", NODATA)
	f.Set("drop.example.", DROP)
	f.Set("allow.example.", PASSTHRU)

	got := cnames(axfr(t, f))
	if len(got) != len(want) {
		t.Fatalf("transfer carries %d rules, want %d: %v", len(got), len(want), got)
	}
	for owner, target := range want {
		if got[owner] != target {
			t.Errorf("%s -> %q, want %q", owner, got[owner], target)
		}
	}
}

func TestFeedRemoveDropsTheRule(t *testing.T) {
	f := newTestFeed(t)
	f.Set("gone.example.", NXDOMAIN)
	f.Set("stays.example.", NXDOMAIN)
	f.Remove("gone.example.")

	got := cnames(axfr(t, f))
	if _, still := got["gone.example."+testZone]; still {
		t.Error("removed rule is still in the transfer")
	}
	if _, ok := got["stays.example."+testZone]; !ok {
		t.Error("Remove took out the wrong rule")
	}
}

// Rules() is half the oracle: it is what the rig will compare pop's output
// against, so it must describe what the feed actually served.
func TestFeedRulesMatchesWhatIsServed(t *testing.T) {
	f := newTestFeed(t)
	f.Set("one.example.", NXDOMAIN)
	f.Set("two.example.", PASSTHRU)

	rules := f.Rules()
	served := cnames(axfr(t, f))
	if len(rules) != len(served) {
		t.Fatalf("Rules() has %d entries, the transfer carries %d", len(rules), len(served))
	}
	for name, action := range rules {
		if got := served[name+testZone]; got != string(action) {
			t.Errorf("Rules() says %s -> %q, transfer served %q", name, action, got)
		}
	}

	// And it must be a copy: a caller holding the oracle's view must not be
	// able to change the feed by mutating it.
	rules["injected.example."] = DROP
	if _, leaked := f.Rules()["injected.example."]; leaked {
		t.Error("Rules() handed out the live map; the oracle can be corrupted by its own reader")
	}
}

// The rig must be at least as careful about consistency as pop is: a change
// landing mid-transfer must not tear it. Run under -race.
func TestFeedTransferDoesNotTearUnderConcurrentChange(t *testing.T) {
	f := newTestFeed(t)
	for i := 0; i < 20; i++ {
		f.Set(dns.Fqdn("n"+string(rune('a'+i))+".example"), NXDOMAIN)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
				f.Set(dns.Fqdn("churn"+string(rune('a'+i%20))+".example"), NODATA)
			}
		}
	}()

	for i := 0; i < 25; i++ {
		rrs := axfr(t, f)
		first := rrs[0].(*dns.SOA)
		last := rrs[len(rrs)-1].(*dns.SOA)
		if first.Serial != last.Serial {
			t.Fatalf("transfer straddled a change: opening serial %d, closing %d", first.Serial, last.Serial)
		}
	}
	close(stop)
	wg.Wait()
}
