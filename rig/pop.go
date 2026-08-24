/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package rig

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Launching pop under test.
//
// pop is driven as the real deployed binary, over real sockets. The rig never
// imports it, so what is exercised here is what ships.
//
// The awkward part is that pop's config paths are FIXED at /etc/dnstapir --
// deliberately, so that a host cannot accumulate stale or conflicting configs.
// There is no --config flag and there should not be one. So a rig cannot point
// pop at a temporary directory; it has to write the real one. Everything about
// EtcDir below follows from that, and from not being willing to destroy an
// operator's configuration to run a test.

// EtcDir is where pop insists its configuration lives.
const EtcDir = "/etc/dnstapir"

// rigMarker marks EtcDir as rig-owned. Its absence is what stops the rig
// overwriting a real installation.
const rigMarker = ".rig-generated"

// APIKey is the key the rig configures pop's API with.
const APIKey = "rig-api-key"

// AllowEtcEnv must be set before the rig will write to EtcDir.
//
// Two gates rather than one, because the failure mode is destroying someone's
// production configuration. The operator opts in with this variable, AND the
// directory must be empty or already rig-owned. Neither alone is enough: the
// variable could be left set in a shell, and an empty directory could be a
// fresh install someone is halfway through populating.
const AllowEtcEnv = "POP_RIG_ALLOW_ETC"

// ListType is which of pop's three lists a source feeds.
type ListType string

const (
	Allowlist ListType = "allowlist"
	Denylist  ListType = "denylist"
	Doubtlist ListType = "doubtlist"
)

// Source is one intelligence feed for pop under test.
type Source struct {
	Name string
	Type ListType

	// Exactly one of these. Feed makes it a zone-transfer source pointed at a
	// rig Feed; Domains makes it a local file the rig writes.
	Feed    *Feed
	Domains []string
}

// XfrSource feeds pop from a rig Feed by zone transfer.
func XfrSource(name string, t ListType, f *Feed) Source {
	return Source{Name: name, Type: t, Feed: f}
}

// FileSource feeds pop from a local file of domain names.
func FileSource(name string, t ListType, domains ...string) Source {
	return Source{Name: name, Type: t, Domains: domains}
}

// PopConfig is what to start pop with. Everything not named here is chosen by
// the rig: ports, paths and the settings that only exist to satisfy config
// validation.
type PopConfig struct {
	// ZoneName is the RPZ zone pop serves. Defaults to "rpz.rig.test.".
	ZoneName string

	// Sources feed pop. May be empty, which is a legitimate thing to test.
	Sources []Source

	// Downstream is where pop sends NOTIFY. Defaults to a closed port, which
	// is fine: the NOTIFY failing is logged and changes nothing else.
	Downstream string

	// Binary is the pop executable. Defaults to POP_BINARY, then to
	// ../out/dnstapir-pop relative to the working directory.
	Binary string

	// StartTimeout bounds how long to wait for pop to answer DNS. Defaults to
	// 30s.
	StartTimeout time.Duration
}

// Pop is a running pop under test.
type Pop struct {
	DNSAddr  string // where its dnsengine listens
	APIAddr  string // where its REST API listens
	ZoneName string
	WorkDir  string // logs, serial cache, generated list files

	cmd    *exec.Cmd
	out    *lockedBuffer
	closed bool
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// Output is everything pop has written to stdout and stderr. Worth printing
// when a test fails: pop says a great deal about why it will not start.
func (p *Pop) Output() string { return p.out.String() }

// Log is pop's own logfile.
//
// Necessary, not a convenience: pop writes almost nothing to stdout once
// logging is configured, so a failing test that only has Output() can see that
// pop started and nothing about what it then did. Reading this is usually the
// difference between "the served zone was wrong" and knowing why.
func (p *Pop) Log() string {
	b, err := os.ReadFile(filepath.Join(p.WorkDir, "pop.log"))
	if err != nil {
		return fmt.Sprintf("(no pop.log: %v)", err)
	}
	return string(b)
}

// KeepWorkDirEnv keeps the working directory after Stop, for when the logs
// need looking at by hand.
const KeepWorkDirEnv = "POP_RIG_KEEP_WORKDIR"

// freePort returns a TCP port nothing is listening on.
//
// Racy by nature -- the port is free when we look and could be taken before
// pop binds it -- but the alternative is fixed ports, which collide with each
// other and with whatever else is on the machine.
func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// prepareEtcDir makes EtcDir safe to write, or explains why it is not.
func prepareEtcDir() error {
	if os.Getenv(AllowEtcEnv) != "1" {
		return fmt.Errorf(
			"refusing to write %s: set %s=1 to allow it.\n"+
				"pop's config paths are fixed, so the rig has to use the real directory. "+
				"Only do this on a machine where losing %s costs nothing -- a CI runner or a container.",
			EtcDir, AllowEtcEnv, EtcDir)
	}

	entries, err := os.ReadDir(EtcDir)
	switch {
	case os.IsNotExist(err):
		return os.MkdirAll(EtcDir, 0o755)
	case err != nil:
		return fmt.Errorf("reading %s: %w", EtcDir, err)
	}

	if len(entries) == 0 {
		return nil
	}
	if _, err := os.Stat(filepath.Join(EtcDir, rigMarker)); err == nil {
		return nil // ours already
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return fmt.Errorf(
		"refusing to overwrite %s: it is not empty and has no %s marker, so it looks like a real installation.\n"+
			"It contains: %s\n"+
			"Move it aside if this machine is genuinely disposable.",
		EtcDir, rigMarker, strings.Join(names, ", "))
}

// StartPop writes a configuration, starts pop, and waits until it answers DNS.
//
// Call Stop when done. On any failure the process is cleaned up before the
// error is returned, so a caller that ignores the error does not leak a pop.
func StartPop(cfg PopConfig) (*Pop, error) {
	if cfg.ZoneName == "" {
		cfg.ZoneName = "rpz.rig.test."
	}
	cfg.ZoneName = dns.Fqdn(cfg.ZoneName)
	if cfg.StartTimeout == 0 {
		cfg.StartTimeout = 30 * time.Second
	}
	if cfg.Binary == "" {
		cfg.Binary = popBinary()
	}
	if _, err := os.Stat(cfg.Binary); err != nil {
		return nil, fmt.Errorf("pop binary %q not found (%v); run 'make build' or set POP_BINARY", cfg.Binary, err)
	}
	if cfg.Downstream == "" {
		port, err := freePort()
		if err != nil {
			return nil, err
		}
		cfg.Downstream = fmt.Sprintf("127.0.0.1:%d", port)
	}

	if err := prepareEtcDir(); err != nil {
		return nil, err
	}

	workdir, err := os.MkdirTemp("", "poprig-")
	if err != nil {
		return nil, err
	}

	dnsPort, err := freePort()
	if err != nil {
		return nil, err
	}
	apiPort, err := freePort()
	if err != nil {
		return nil, err
	}
	tlsPort, err := freePort()
	if err != nil {
		return nil, err
	}
	bootPort, err := freePort()
	if err != nil {
		return nil, err
	}
	bootTLSPort, err := freePort()
	if err != nil {
		return nil, err
	}

	p := &Pop{
		DNSAddr:  fmt.Sprintf("127.0.0.1:%d", dnsPort),
		APIAddr:  fmt.Sprintf("127.0.0.1:%d", apiPort),
		ZoneName: cfg.ZoneName,
		WorkDir:  workdir,
		out:      &lockedBuffer{},
	}

	if err := writeConfigs(p, cfg, apiPort, tlsPort, bootPort, bootTLSPort); err != nil {
		return nil, err
	}

	p.cmd = exec.Command(cfg.Binary)
	p.cmd.Dir = workdir
	p.cmd.Stdout = p.out
	p.cmd.Stderr = p.out
	if err := p.cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting %s: %w", cfg.Binary, err)
	}

	if err := p.waitUntilServing(cfg.StartTimeout); err != nil {
		out := p.Output()
		p.Stop()
		return nil, fmt.Errorf("%w\n--- pop output ---\n%s", err, out)
	}
	return p, nil
}

func popBinary() string {
	if b := os.Getenv("POP_BINARY"); b != "" {
		return b
	}
	// Tests run in the package directory, so the binary make build produces is
	// one level up.
	abs, err := filepath.Abs(filepath.Join("..", "out", "dnstapir-pop"))
	if err != nil {
		return filepath.Join("..", "out", "dnstapir-pop")
	}
	return abs
}

// waitUntilServing polls the DNS engine until it answers for the zone.
//
// Polling the actual service rather than sleeping, because "pop has started"
// is not a useful claim: what a test needs to know is that the thing it is
// about to query will answer. pop reports plenty on the way up that does not
// mean it is serving yet.
func (p *Pop) waitUntilServing(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if p.cmd.ProcessState != nil && p.cmd.ProcessState.Exited() {
			return fmt.Errorf("pop exited during startup")
		}
		m := new(dns.Msg)
		m.SetQuestion(p.ZoneName, dns.TypeSOA)
		c := &dns.Client{Timeout: 2 * time.Second}
		r, _, err := c.Exchange(m, p.DNSAddr)
		switch {
		case err != nil:
			lastErr = err
		case r.Rcode != dns.RcodeSuccess:
			lastErr = fmt.Errorf("SOA query answered %s", dns.RcodeToString[r.Rcode])
		case len(r.Answer) == 0:
			lastErr = fmt.Errorf("SOA query answered NOERROR but with no answer")
		default:
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("pop did not serve %s on %s within %s (last: %v)", p.ZoneName, p.DNSAddr, timeout, lastErr)
}

// Stop terminates pop and removes its working directory.
func (p *Pop) Stop() {
	if p == nil || p.closed {
		return
	}
	p.closed = true
	if p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { _, _ = p.cmd.Process.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = p.cmd.Process.Kill()
			<-done
		}
	}
	if os.Getenv(KeepWorkDirEnv) == "1" {
		fmt.Printf("rig: keeping pop working directory %s\n", p.WorkDir)
		return
	}
	_ = os.RemoveAll(p.WorkDir)
}

// AXFR pulls the whole zone pop is currently serving.
func (p *Pop) AXFR() ([]dns.RR, error) {
	m := new(dns.Msg)
	m.SetAxfr(p.ZoneName)
	ch, err := new(dns.Transfer).In(m, p.DNSAddr)
	if err != nil {
		return nil, err
	}
	var out []dns.RR
	for env := range ch {
		if env.Error != nil {
			return nil, env.Error
		}
		out = append(out, env.RR...)
	}
	return out, nil
}

// Serial is the serial pop is currently serving.
func (p *Pop) Serial() (uint32, error) {
	m := new(dns.Msg)
	m.SetQuestion(p.ZoneName, dns.TypeSOA)
	c := &dns.Client{Timeout: 2 * time.Second}
	r, _, err := c.Exchange(m, p.DNSAddr)
	if err != nil {
		return 0, err
	}
	for _, rr := range r.Answer {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa.Serial, nil
		}
	}
	return 0, fmt.Errorf("no SOA in the answer")
}

// WaitForRule waits until pop serves owner with the given RPZ target, or until
// timeout. Returns the serial it settled on.
//
// This is the convergence primitive the churn tests will need. pop polls its
// upstreams on their SOA refresh, so a change made at a feed is not visible
// immediately -- and how long it takes is not something a test should encode
// as a sleep.
func (p *Pop) WaitForRule(owner string, want Action, timeout time.Duration) (uint32, error) {
	owner = dns.Fqdn(owner)
	deadline := time.Now().Add(timeout)
	var last string
	for time.Now().Before(deadline) {
		rrs, err := p.AXFR()
		if err == nil {
			for _, rr := range rrs {
				c, ok := rr.(*dns.CNAME)
				if !ok || !strings.EqualFold(c.Hdr.Name, owner) {
					continue
				}
				last = c.Target
				if c.Target == string(want) {
					s, _ := p.Serial()
					return s, nil
				}
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	if last == "" {
		return 0, fmt.Errorf("%s never appeared in the served zone within %s", owner, timeout)
	}
	return 0, fmt.Errorf("%s served as %q, want %q, after %s", owner, last, want, timeout)
}

// WaitForPresent waits until pop serves owner with ANY action, and reports the
// action it settled on.
//
// Separate from WaitForRule because the action pop serves is NOT the action the
// upstream asked for. A denylist source's per-name action is parsed and stored,
// but decide() answers a denylisted name with the CONFIGURED
// policy.denylist.action -- so an upstream rule of rpz-drop. is served as
// NXDOMAIN under the usual config. Waiting for the upstream's own action there
// waits for something that will never arrive.
//
// So: use WaitForRule when the test is about WHICH action is served, and this
// when it is about the name arriving at all.
func (p *Pop) WaitForPresent(owner string, timeout time.Duration) (Action, uint32, error) {
	owner = dns.Fqdn(owner)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		rrs, err := p.AXFR()
		if err == nil {
			for _, rr := range rrs {
				c, ok := rr.(*dns.CNAME)
				if !ok || !strings.EqualFold(c.Hdr.Name, owner) {
					continue
				}
				s, _ := p.Serial()
				return Action(c.Target), s, nil
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return "", 0, fmt.Errorf("%s never appeared in the served zone within %s", owner, timeout)
}

// WaitForAbsent waits until owner is NOT in the served zone.
func (p *Pop) WaitForAbsent(owner string, timeout time.Duration) error {
	owner = dns.Fqdn(owner)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		rrs, err := p.AXFR()
		if err == nil {
			found := false
			for _, rr := range rrs {
				if c, ok := rr.(*dns.CNAME); ok && strings.EqualFold(c.Hdr.Name, owner) {
					found = true
					break
				}
			}
			if !found {
				return nil
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("%s was still in the served zone after %s", owner, timeout)
}

// DebugOutput is the part of pop's /debug gen-output answer the rig uses.
//
// Declared here rather than imported: pop is package main, so nothing can
// import its types even if that were desirable.
type DebugOutput struct {
	Error           bool
	ErrorMsg        string
	DenylistedNames map[string]bool
	RpzOutput       []struct {
		Name   string
		Action int
	}
}

// GenOutput asks pop to rebuild its RPZ from the lists it currently holds, and
// returns what that rebuild produced.
//
// This is a diagnostic rather than something a normal test should need. It is
// how you tell "the data never reached pop's lists" apart from "the data is in
// the lists and nothing rebuilt the zone" -- two failures that look identical
// from outside, because in both the served zone is stale.
func (p *Pop) GenOutput() (*DebugOutput, error) {
	body, err := json.Marshal(map[string]string{"command": "gen-output"})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, "http://"+p.APIAddr+"/api/v1/debug", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", APIKey)

	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("posting gen-output to %s: %w", p.APIAddr, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gen-output answered %s", resp.Status)
	}
	var out DebugOutput
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decoding gen-output response: %w", err)
	}
	if out.Error {
		return &out, fmt.Errorf("gen-output failed: %s", out.ErrorMsg)
	}
	return &out, nil
}
