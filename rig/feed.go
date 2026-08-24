/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

// Package rig is the test rig for dnstapir-pop.
//
// It drives pop from OUTSIDE, over the same interfaces a real deployment uses:
// RPZ feeds arrive by zone transfer, local lists by file, and the result is
// read back by pulling the served zone. Nothing here imports pop's internals,
// and that is deliberate — a rig that shares code with the thing it tests
// cannot catch a bug that lives in the shared part.
//
// The same rule applies to the expectations. Where the rig has to decide what
// pop SHOULD have produced, it works it out independently rather than calling
// pop's own logic. The mapping from action to RPZ CNAME target below is the
// first instance: pop has one, and the rig deliberately writes its own.
package rig

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Action is what an RPZ rule tells the resolver to do.
//
// Written out here rather than imported from pop or from the tapir module, so
// that the rig's idea of correct is arrived at independently. If pop's mapping
// ever drifts from the RPZ specification, the rig should notice rather than
// drift with it.
type Action string

const (
	NXDOMAIN Action = "."             // block: name does not exist
	NODATA   Action = "*."            // block: name exists, no data
	DROP     Action = "rpz-drop."     // block: no answer at all
	PASSTHRU Action = "rpz-passthru." // allowlist: never block this name
)

// Feed is a fake upstream RPZ zone that pop can slave from.
//
// pop's upstream protocol is narrow: it queries the SOA, and when the serial
// has increased it pulls a full AXFR (tapir's FetchFromUpstream ->
// ZoneTransferIn(..., "axfr")). No IXFR, no NOTIFY. So this serves exactly
// those two things.
//
// Everything mutating bumps the serial, because that is the only signal pop
// watches. A change that did not bump would simply never be noticed, which is
// a realistic upstream bug worth being able to simulate later — see
// SetSerial.
type Feed struct {
	zone string

	mu     sync.Mutex
	serial uint32
	rules  map[string]Action // owner name (relative, no zone suffix) -> action

	udp *dns.Server
	tcp *dns.Server

	addr string
}

// refreshSeconds is the SOA REFRESH the feed advertises.
//
// pop polls on this, so it sets the floor for how quickly a change can reach
// the served zone. One second keeps churn tests brisk without special-casing
// anything in pop.
const refreshSeconds = 1

// NewFeed starts a feed for zone on 127.0.0.1 with an ephemeral port, serving
// UDP and TCP. Call Close when done.
func NewFeed(zone string) (*Feed, error) {
	f := &Feed{
		zone:   dns.Fqdn(zone),
		serial: 1,
		rules:  map[string]Action{},
	}

	// UDP and TCP must share a port, and the two port spaces are independent,
	// so ":0" twice would give two different numbers. Take a TCP port first
	// and then ask for the same one on UDP, retrying if that number happens to
	// be taken.
	var lastErr error
	for attempt := 0; attempt < 20; attempt++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, fmt.Errorf("rig: listening on tcp: %w", err)
		}
		addr := l.Addr().String()
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			l.Close()
			lastErr = err
			continue
		}
		f.addr = addr
		f.tcp = &dns.Server{Listener: l, Handler: dns.HandlerFunc(f.handle)}
		f.udp = &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(f.handle)}
		break
	}
	if f.addr == "" {
		return nil, fmt.Errorf("rig: could not get a matching udp/tcp port: %w", lastErr)
	}

	started := make(chan error, 2)
	go func() { started <- f.tcp.ActivateAndServe() }()
	go func() { started <- f.udp.ActivateAndServe() }()

	// Give the servers a moment to fail loudly rather than hanging a test on a
	// feed that never came up.
	select {
	case err := <-started:
		if err != nil {
			return nil, fmt.Errorf("rig: feed for %s failed to start: %w", f.zone, err)
		}
	case <-time.After(200 * time.Millisecond):
	}
	return f, nil
}

// Addr is the host:port pop should be pointed at.
func (f *Feed) Addr() string { return f.addr }

// Zone is the feed's zone name, fully qualified.
func (f *Feed) Zone() string { return f.zone }

// Close stops the feed.
func (f *Feed) Close() {
	if f.tcp != nil {
		_ = f.tcp.Shutdown()
	}
	if f.udp != nil {
		_ = f.udp.Shutdown()
	}
}

// Set adds or replaces a rule and bumps the serial. name is relative to the
// zone ("evil.example.") and is stored fully qualified against it.
func (f *Feed) Set(name string, action Action) uint32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules[dns.Fqdn(name)] = action
	f.serial++
	return f.serial
}

// Remove drops a rule and bumps the serial. Removing a name that is not there
// still bumps: an upstream that republishes is entitled to say nothing changed
// in content while still advancing its serial, and pop must cope.
func (f *Feed) Remove(name string) uint32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.rules, dns.Fqdn(name))
	f.serial++
	return f.serial
}

// SetSerial forces the serial, without touching content.
//
// For simulating upstreams that misbehave: one that never bumps despite
// changing, or one that goes backwards. pop's refresh only looks at whether
// the serial increased, so both are worth being able to produce.
func (f *Feed) SetSerial(s uint32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.serial = s
}

// Serial is the serial the feed is currently advertising.
func (f *Feed) Serial() uint32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.serial
}

// Rules is a copy of what the feed is currently publishing. This is the rig's
// record of what it injected, and therefore half of the oracle.
func (f *Feed) Rules() map[string]Action {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]Action, len(f.rules))
	for k, v := range f.rules {
		out[k] = v
	}
	return out
}

// soaLocked builds the zone's SOA. Caller holds f.mu.
func (f *Feed) soaLocked() *dns.SOA {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: f.zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
		Ns:      "ns." + f.zone,
		Mbox:    "hostmaster." + f.zone,
		Serial:  f.serial,
		Refresh: refreshSeconds,
		Retry:   refreshSeconds,
		Expire:  86400,
		Minttl:  60,
	}
}

// contentLocked renders the zone as RRs, without the enclosing SOAs. Caller
// holds f.mu.
func (f *Feed) contentLocked() []dns.RR {
	ns := &dns.NS{
		Hdr: dns.RR_Header{Name: f.zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60},
		Ns:  "ns." + f.zone,
	}
	out := []dns.RR{ns}
	for name, action := range f.rules {
		cname := &dns.CNAME{
			Hdr:    dns.RR_Header{Name: name + f.zone, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
			Target: string(action),
		}
		out = append(out, cname)
	}
	return out
}

func (f *Feed) handle(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) != 1 {
		f.refuse(w, r)
		return
	}
	q := r.Question[0]
	if !dns.IsSubDomain(f.zone, q.Name) {
		f.refuse(w, r)
		return
	}

	switch q.Qtype {
	case dns.TypeSOA:
		f.mu.Lock()
		soa := f.soaLocked()
		f.mu.Unlock()

		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		m.Answer = append(m.Answer, soa)
		_ = w.WriteMsg(m)

	case dns.TypeAXFR:
		f.mu.Lock()
		soa := f.soaLocked()
		rrs := f.contentLocked()
		f.mu.Unlock()

		// One consistent view per transfer: the snapshot is taken under the
		// lock above and the transfer is served from it, so a concurrent Set
		// cannot tear a transfer in half. The rig has to be at least as
		// careful about this as pop is, or a rig bug looks like a pop bug.
		ch := make(chan *dns.Envelope)
		tr := new(dns.Transfer)
		go func() {
			_ = tr.Out(w, r, ch)
		}()
		body := []dns.RR{soa}
		body = append(body, rrs...)
		body = append(body, soa) // closing SOA
		ch <- &dns.Envelope{RR: body}
		close(ch)

	default:
		f.refuse(w, r)
	}
}

func (f *Feed) refuse(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeRefused)
	_ = w.WriteMsg(m)
}
