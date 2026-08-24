/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * SIGHUP: what a config reload must not do.
 *
 * These FAIL without the lifecycle-hardening change (#155): on a config that
 * does not parse pop exits, and on a config that does parse it silently
 * replaces the whole live config with the last file it read -- losing, among
 * other things, the serial cache path, so shutdown then dies too.
 */
package rig

import (
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A SIGHUP with a config that does not parse must not kill the daemon, and must
// leave the running config alone (#155). The old handler POPExiter'd, so an
// operator's typo took pop down.
func TestReloadWithBrokenConfigKeepsServing(t *testing.T) {
	requireEtc(t)

	feed := newFeedT(t, "deny.rig.test.")
	feed.Set("evil.example.", NXDOMAIN)

	p := startPop(t, PopConfig{
		Sources: []Source{XfrSource("upstream", Denylist, feed)},
	})
	owner := "evil.example." + p.ZoneName
	if _, err := p.WaitForRule(owner, NXDOMAIN, 30*time.Second); err != nil {
		t.Fatalf("pop never served the feed: %v", err)
	}
	before, err := p.Serial()
	if err != nil {
		t.Fatalf("Serial: %v", err)
	}

	// Break one of the files a reload reads. Policy is a good choice: it is
	// merged like the others, and it is the kind of file an operator edits.
	policy := p.EtcFile("pop-policy.yaml")
	good, err := os.ReadFile(policy)
	if err != nil {
		t.Fatalf("reading %s: %v", policy, err)
	}
	t.Cleanup(func() { _ = os.WriteFile(policy, good, 0o644) })

	if err := os.WriteFile(policy, []byte("policy:\n  this is not: [valid: yaml\n"), 0o644); err != nil {
		t.Fatalf("writing a broken %s: %v", policy, err)
	}

	if err := p.Signal(syscall.SIGHUP); err != nil {
		t.Fatalf("SIGHUP: %v", err)
	}
	// The reload is synchronous in the dispatcher, but the signal delivery is
	// not; give it a moment to have happened at all.
	time.Sleep(2 * time.Second)

	if !p.Alive() {
		t.Fatalf("pop died on a SIGHUP with an unparseable config:\n%s", tail(p.Output(), 900))
	}
	// Still serving, and still serving the config it started with.
	if _, err := p.WaitForRule(owner, NXDOMAIN, 10*time.Second); err != nil {
		t.Errorf("pop survived the bad reload but stopped serving: %v", err)
	}
	after, err := p.Serial()
	if err != nil {
		t.Errorf("Serial after the bad reload: %v", err)
	} else if after != before {
		t.Errorf("a rejected reload changed the served serial: %d -> %d", before, after)
	}
}

// A SIGHUP with a config that is fine must also leave pop serving. Guards the
// other direction: a reload that rejects everything would pass the test above.
func TestReloadWithGoodConfigKeepsServing(t *testing.T) {
	requireEtc(t)

	feed := newFeedT(t, "deny.rig.test.")
	feed.Set("evil.example.", NXDOMAIN)

	p := startPop(t, PopConfig{
		Sources: []Source{XfrSource("upstream", Denylist, feed)},
	})
	owner := "evil.example." + p.ZoneName
	if _, err := p.WaitForRule(owner, NXDOMAIN, 30*time.Second); err != nil {
		t.Fatalf("pop never served the feed: %v", err)
	}

	if err := p.Signal(syscall.SIGHUP); err != nil {
		t.Fatalf("SIGHUP: %v", err)
	}
	time.Sleep(2 * time.Second)

	if !p.Alive() {
		t.Fatalf("pop died on a SIGHUP with a valid config:\n%s", tail(p.Output(), 900))
	}
	if _, err := p.WaitForRule(owner, NXDOMAIN, 10*time.Second); err != nil {
		t.Errorf("pop stopped serving after a good reload: %v", err)
	}

	// And it must still shut down cleanly afterwards: a reload that left the
	// dispatcher in a bad state would show up here rather than above.
	p.Stop()
	if err := p.ExitOK(); err != nil {
		t.Errorf("unclean shutdown after a reload: %v", err)
	}
}

func tail(s string, n int) string {
	s = strings.TrimRight(s, "\n")
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n:]
}
