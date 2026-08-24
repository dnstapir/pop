/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Lifecycle: what pop does on SIGINT and on SIGHUP.
 *
 * These assert the two guarantees #177 is about (#155, #159), against a live
 * daemon rather than in-process. That distinction is the whole point: both bugs
 * are in mainloop's signal dispatcher, which a unit test does not run.
 */
package rig

import (
	"os"
	"testing"
	"time"
)

// Shutdown must be clean. The signal dispatcher used to call wg.Done() and keep
// dispatching, so a second shutdown signal drove the WaitGroup negative and
// panicked the process on the way out (#159).
func TestShutdownIsClean(t *testing.T) {
	requireEtc(t)

	feed := newFeedT(t, "deny.rig.test.")
	feed.Set("evil.example.", NXDOMAIN)

	p := startPop(t, PopConfig{
		Sources: []Source{XfrSource("upstream", Denylist, feed)},
	})
	if _, err := p.WaitForRule("evil.example."+p.ZoneName, NXDOMAIN, 30*time.Second); err != nil {
		t.Fatalf("pop never served the feed: %v", err)
	}

	p.Stop()

	if err := p.ExitOK(); err != nil {
		t.Errorf("unclean shutdown: %v", err)
	}
}

// Two shutdown signals in quick succession. This is what #159 is actually
// about: the dispatcher called wg.Done() and kept dispatching, so a SECOND
// shutdown event drove the counter negative and panicked the process.
//
// One SIGINT does not reproduce it -- TestShutdownIsClean passes with or
// without the fix -- because a single Done is legal. The signal channel is
// buffered, so a second SIGINT delivered before the process is gone is still
// queued and dispatched after the first case returns.
func TestDoubleShutdownSignalIsClean(t *testing.T) {
	requireEtc(t)

	feed := newFeedT(t, "deny.rig.test.")
	feed.Set("evil.example.", NXDOMAIN)

	p := startPop(t, PopConfig{
		Sources: []Source{XfrSource("upstream", Denylist, feed)},
	})
	if _, err := p.WaitForRule("evil.example."+p.ZoneName, NXDOMAIN, 30*time.Second); err != nil {
		t.Fatalf("pop never served the feed: %v", err)
	}

	// Both before pop can finish exiting, so the second is already queued.
	if err := p.Signal(os.Interrupt); err != nil {
		t.Fatalf("first SIGINT: %v", err)
	}
	if err := p.Signal(os.Interrupt); err != nil && p.Alive() {
		t.Fatalf("second SIGINT: %v", err)
	}

	p.Stop()
	if err := p.ExitOK(); err != nil {
		t.Errorf("unclean shutdown on two signals: %v", err)
	}
}

// The condition #159 actually describes: two shutdown paths at once. pop can be
// told to stop by a signal AND by its management API, and the dispatcher used
// to call wg.Done() for each without leaving the loop, driving the WaitGroup
// negative.
func TestSignalAndApiStopTogetherIsClean(t *testing.T) {
	requireEtc(t)

	feed := newFeedT(t, "deny.rig.test.")
	feed.Set("evil.example.", NXDOMAIN)

	p := startPop(t, PopConfig{
		Sources: []Source{XfrSource("upstream", Denylist, feed)},
	})
	if _, err := p.WaitForRule("evil.example."+p.ZoneName, NXDOMAIN, 30*time.Second); err != nil {
		t.Fatalf("pop never served the feed: %v", err)
	}

	go func() { _ = p.APICommand("stop") }()
	_ = p.Signal(os.Interrupt)

	p.Stop()
	if err := p.ExitOK(); err != nil {
		t.Errorf("unclean shutdown when a signal and an API stop arrive together: %v", err)
	}
}
