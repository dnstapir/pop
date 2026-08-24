/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package rig

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// End-to-end: a real pop binary, started by the rig, fed by rig feeds and rig
// files, read back over DNS.
//
// These need somewhere disposable to write /etc/dnstapir (see AllowEtcEnv), so
// they skip unless told it is safe. That keeps "make test" honest on a
// developer machine while letting CI, where the runner is thrown away, run
// them.

// KnownBugsEnv runs the tests that reproduce OPEN bugs.
//
// They fail by design, because the bugs are real and unfixed. Left on, they
// would paint CI red on every PR for defects that PR did not introduce, and a
// permanently red gate is worse than no gate -- it gets ignored, then removed.
// When a fix lands, drop the guard: that is the moment the reproducer stops
// being a demonstration and becomes a regression test.
//
//	POP_RIG_KNOWN_BUGS=1 POP_RIG_ALLOW_ETC=1 go test -run ... ./rig/
const KnownBugsEnv = "POP_RIG_KNOWN_BUGS"

func reproducesOpenBug(t *testing.T, issue, summary string) {
	t.Helper()
	if os.Getenv(KnownBugsEnv) != "1" {
		t.Skipf("reproduces open issue %s (%s); set %s=1 to run", issue, summary, KnownBugsEnv)
	}
}

func requireEtc(t *testing.T) {
	t.Helper()
	if os.Getenv(AllowEtcEnv) != "1" {
		t.Skipf("needs to write %s; set %s=1 on a disposable machine to run", EtcDir, AllowEtcEnv)
	}
}

func startPop(t *testing.T, cfg PopConfig) *Pop {
	t.Helper()
	p, err := StartPop(cfg)
	if err != nil {
		t.Fatalf("StartPop: %v", err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("--- pop stdout/stderr ---\n%s", p.Output())
			t.Logf("--- pop.log ---\n%s", p.Log())
		}
		p.Stop()
	})
	return p
}

func newFeedT(t *testing.T, zone string) *Feed {
	t.Helper()
	f, err := NewFeed(zone)
	if err != nil {
		t.Fatalf("NewFeed(%s): %v", zone, err)
	}
	t.Cleanup(f.Close)
	return f
}

// servedRules reduces pop's zone to owner -> RPZ target.
func servedRules(t *testing.T, p *Pop) map[string]string {
	t.Helper()
	rrs, err := p.AXFR()
	if err != nil {
		t.Fatalf("AXFR from pop: %v", err)
	}
	out := map[string]string{}
	for _, rr := range rrs {
		if c, ok := rr.(*dns.CNAME); ok {
			out[strings.ToLower(c.Hdr.Name)] = c.Target
		}
	}
	return out
}

// The baseline: pop starts, slaves a rig feed, and serves what it was fed.
func TestPopServesWhatAFeedGivesIt(t *testing.T) {
	requireEtc(t)

	feed := newFeedT(t, "deny.rig.test.")
	feed.Set("evil.example.", NXDOMAIN)

	p := startPop(t, PopConfig{
		Sources: []Source{XfrSource("upstream", Denylist, feed)},
	})

	if _, err := p.WaitForRule("evil.example."+p.ZoneName, NXDOMAIN, 30*time.Second); err != nil {
		t.Fatalf("pop never served the feed's rule: %v", err)
	}
}

// A change at the upstream reaches the served zone without anyone being told
// to wait a fixed number of seconds.
func TestPopFollowsUpstreamChanges(t *testing.T) {
	requireEtc(t)
	reproducesOpenBug(t, "#195", "xfr upstream changes are fetched but never republished")

	feed := newFeedT(t, "deny.rig.test.")
	feed.Set("first.example.", NXDOMAIN)

	p := startPop(t, PopConfig{
		Sources: []Source{XfrSource("upstream", Denylist, feed)},
	})
	if _, err := p.WaitForRule("first.example."+p.ZoneName, NXDOMAIN, 30*time.Second); err != nil {
		t.Fatalf("initial rule: %v", err)
	}
	before, err := p.Serial()
	if err != nil {
		t.Fatalf("Serial: %v", err)
	}

	// Add upstream, expect it downstream.
	feed.Set("second.example.", NXDOMAIN)
	if _, err := p.WaitForRule("second.example."+p.ZoneName, NXDOMAIN, 30*time.Second); err != nil {
		t.Fatalf("added rule never arrived: %v", err)
	}

	// Remove upstream, expect it gone downstream.
	feed.Remove("first.example.")
	if err := p.WaitForAbsent("first.example."+p.ZoneName, 30*time.Second); err != nil {
		t.Fatalf("removed rule never went away: %v", err)
	}

	after, err := p.Serial()
	if err != nil {
		t.Fatalf("Serial: %v", err)
	}
	if after <= before {
		t.Errorf("pop's serial did not advance across two upstream changes: %d -> %d", before, after)
	}
}

// THE headline behaviour: a name on both an allowlist and a denylist must not
// be blocked. This is what pop is for -- "a single output with all conflicts
// resolved" -- and nothing tested it before.
func TestAllowlistBeatsDenylist(t *testing.T) {
	requireEtc(t)
	reproducesOpenBug(t, "#175", "the full rebuild bypasses allowlist precedence")

	const contested = "contested.example."
	feed := newFeedT(t, "deny.rig.test.")
	feed.Set(contested, NXDOMAIN)
	feed.Set("uncontested.example.", NXDOMAIN)

	p := startPop(t, PopConfig{
		Sources: []Source{
			XfrSource("upstream", Denylist, feed),
			FileSource("local-allow", Allowlist, contested),
		},
	})

	// Wait for the uncontested name, so we know the feed has been ingested
	// before judging the contested one. Otherwise "not blocked" could just
	// mean "not loaded yet", which would make this test pass for the wrong
	// reason.
	if _, err := p.WaitForRule("uncontested.example."+p.ZoneName, NXDOMAIN, 30*time.Second); err != nil {
		t.Fatalf("feed was never ingested: %v", err)
	}

	rules := servedRules(t, p)
	got, present := rules[strings.ToLower(contested+p.ZoneName)]
	if present && got == string(NXDOMAIN) {
		t.Errorf("%s is on an allowlist AND a denylist and pop blocked it (%q); allowlist must win",
			contested, got)
	}
	if present && got != string(PASSTHRU) {
		t.Logf("note: %s served as %q (present but not passthru)", contested, got)
	}
}

// A local file source alone is enough: no feed, no MQTT, nothing external.
func TestPopServesFromLocalFileOnly(t *testing.T) {
	requireEtc(t)

	p := startPop(t, PopConfig{
		Sources: []Source{FileSource("local-deny", Denylist, "blocked.example.")},
	})
	if _, err := p.WaitForRule("blocked.example."+p.ZoneName, NXDOMAIN, 30*time.Second); err != nil {
		t.Fatalf("local denylist entry never served: %v", err)
	}
}

// Refusing to clobber a real /etc/dnstapir is a safety property, so it is
// worth a test of its own rather than trusting the code path.
func TestRefusesEtcDirWithoutOptIn(t *testing.T) {
	t.Setenv(AllowEtcEnv, "")
	if err := prepareEtcDir(); err == nil {
		t.Fatal("prepareEtcDir allowed writing /etc/dnstapir without the opt-in")
	} else if !strings.Contains(err.Error(), AllowEtcEnv) {
		t.Errorf("refusal should name %s so the reader knows what to set; got: %v", AllowEtcEnv, err)
	}
}
