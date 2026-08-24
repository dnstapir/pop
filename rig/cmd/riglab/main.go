/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * riglab keeps the pop test rig up and lets a human drive it.
 *
 * The rig's Go tests assert and exit. This runs the same machinery -- a fake
 * upstream RPZ feed and a real pop slaving from it -- and then just stays up,
 * so changes can be made at the upstream by hand and the result watched in the
 * zone pop actually serves. dig at it, not just curl: the point is that the
 * served zone is a real zone.
 *
 * Every mutating command waits for the change to reach the served zone and
 * reports how long it took and what the serial did, because that is the
 * behaviour worth seeing (issues #195, #197 and #198).
 */
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"

	"dnstapir-pop/rig"
)

var (
	listen   = flag.String("listen", "127.0.0.1:8099", "address for the control API")
	zoneName = flag.String("zone", "rpz.rig.test.", "the RPZ zone pop serves")
	feedZone = flag.String("feed-zone", "deny.rig.test.", "the upstream RPZ zone pop slaves")
	seed     = flag.String("seed", "evil.example.", "comma-separated names to put in the feed at startup")
	waitFor  = flag.Duration("wait", 30*time.Second, "how long to wait for a change to reach the served zone")
	popBin   = flag.String("pop", "out/dnstapir-pop", "the pop binary to run (relative to the repo root)")
)

type lab struct {
	feed *rig.Feed
	pop  *rig.Pop
	quit chan struct{}
}

func main() {
	flag.Parse()
	log.SetFlags(log.Ltime)

	// Running this binary IS the opt-in the rig's tests demand via the
	// environment: pop reads its configuration from a hardcoded /etc/dnstapir
	// (by design -- it avoids stale and conflicting configs), so there is
	// nowhere else for the rig to put it. The rig still refuses to touch a
	// directory it did not create itself.
	os.Setenv(rig.AllowEtcEnv, "1")

	feed, err := rig.NewFeed(*feedZone)
	if err != nil {
		log.Fatalf("starting the upstream feed: %v", err)
	}
	for _, n := range strings.Split(*seed, ",") {
		if n = strings.TrimSpace(n); n != "" {
			feed.Set(dns.Fqdn(n), rig.NXDOMAIN)
		}
	}

	bin, err := resolvePop(*popBin)
	if err != nil {
		feed.Close()
		log.Fatalf("%v", err)
	}

	p, err := rig.StartPop(rig.PopConfig{
		ZoneName: *zoneName,
		Binary:   bin,
		Sources:  []rig.Source{rig.XfrSource("upstream", rig.Denylist, feed)},
	})
	if err != nil {
		feed.Close()
		log.Fatalf("starting pop: %v", err)
	}

	l := &lab{feed: feed, pop: p, quit: make(chan struct{})}

	mux := http.NewServeMux()
	mux.HandleFunc("/", l.help)
	mux.HandleFunc("/info", l.info)
	mux.HandleFunc("/state", l.state)
	mux.HandleFunc("/add", l.add)
	mux.HandleFunc("/del", l.del)
	mux.HandleFunc("/zone", l.zone)
	mux.HandleFunc("/log", l.logtail)
	mux.HandleFunc("/quit", l.stop)
	srv := &http.Server{Addr: *listen, Handler: mux}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("control API: %v", err)
			close(l.quit)
		}
	}()

	l.banner()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sig:
		log.Printf("shutting down")
	case <-l.quit:
	}
	p.Stop()
	feed.Close()
}

// resolvePop finds the pop binary without depending on the working directory.
//
// A relative -pop is tried against the cwd first, then beside this executable
// -- which is where "make riglab" puts both. Resolved to an absolute path
// before pop is started, so a lab launched from anywhere behaves the same.
func resolvePop(path string) (string, error) {
	tried := []string{}
	if abs, err := filepath.Abs(path); err == nil {
		if _, serr := os.Stat(abs); serr == nil {
			return abs, nil
		}
		tried = append(tried, abs)
	}
	if self, err := os.Executable(); err == nil {
		beside := filepath.Join(filepath.Dir(self), filepath.Base(path))
		if _, serr := os.Stat(beside); serr == nil {
			return beside, nil
		}
		tried = append(tried, beside)
	}
	return "", fmt.Errorf("cannot find the pop binary %q (looked in: %s); build it with \"make build\" or pass -pop",
		path, strings.Join(tried, ", "))
}

func (l *lab) banner() {
	fmt.Printf(`
pop rig is up.

  pop serves        %s on %s
  upstream feed     %s on %s
  control API       http://%s/
  pop's work dir    %s   (pop.log, pop-policy.log, ...)

Look at the served zone yourself:

  dig @%s -p %s AXFR %s

Drive it:

  curl "http://%s/state"
  curl "http://%s/add?name=badguy.example."
  curl "http://%s/del?name=badguy.example."
  curl "http://%s/zone"
  curl "http://%s/log?n=40"
  curl "http://%s/quit"

`, l.pop.ZoneName, l.pop.DNSAddr, l.feed.Zone(), l.feed.Addr(), *listen, l.pop.WorkDir,
		host(l.pop.DNSAddr), port(l.pop.DNSAddr), l.pop.ZoneName,
		*listen, *listen, *listen, *listen, *listen, *listen)
}

func (l *lab) help(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	fmt.Fprintf(w, `pop rig control

  /info                        machine-readable addresses and zone names
  /state                       what the upstream holds and what pop serves
  /zone                        the served zone, as pop answers AXFR for it
  /add?name=X[&action=A]       add X upstream, wait for it to reach the served zone
  /del?name=X                  remove X upstream, wait for it to leave the served zone
  /log?n=N                     last N lines of pop.log
  /quit                        stop pop and exit

action is NXDOMAIN (default), NODATA, DROP or PASSTHRU.

The feed is a DENYLIST source, so a PASSTHRU rule in it is misplaced by
definition: pop moves it to its allow_catchall bucket and it will NOT appear
in the served zone. /add does not wait for those.

  dig @%s -p %s AXFR %s
`, host(l.pop.DNSAddr), port(l.pop.DNSAddr), l.pop.ZoneName)
}

// info is what rig-cli reads to learn the shape of this lab: which zone the
// upstream feed carries (so it can strip it off an RR's owner) and where pop
// answers (so it can print a dig command that works).
func (l *lab) info(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "feed_zone=%s\n", l.feed.Zone())
	fmt.Fprintf(w, "feed_addr=%s\n", l.feed.Addr())
	fmt.Fprintf(w, "pop_zone=%s\n", l.pop.ZoneName)
	fmt.Fprintf(w, "pop_dns=%s\n", l.pop.DNSAddr)
	fmt.Fprintf(w, "pop_api=%s\n", l.pop.APIAddr)
	fmt.Fprintf(w, "workdir=%s\n", l.pop.WorkDir)
}

func (l *lab) state(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "upstream  %s @%s  serial %d\n", l.feed.Zone(), l.feed.Addr(), l.feed.Serial())
	rules := l.feed.Rules()
	for _, n := range sortedKeys(rules) {
		fmt.Fprintf(w, "    %-40s CNAME %-14s %s\n", n, rules[n], actionName(string(rules[n])))
	}
	if len(rules) == 0 {
		fmt.Fprintf(w, "    (empty)\n")
	}

	serial, err := l.pop.Serial()
	if err != nil {
		fmt.Fprintf(w, "\npop       %s @%s  serial unavailable: %v\n", l.pop.ZoneName, l.pop.DNSAddr, err)
		return
	}
	fmt.Fprintf(w, "\npop       %s @%s  serial %d\n", l.pop.ZoneName, l.pop.DNSAddr, serial)
	l.writeZone(w)
}

func (l *lab) zone(w http.ResponseWriter, r *http.Request) { l.writeZone(w) }

func (l *lab) writeZone(w http.ResponseWriter) {
	served, err := l.servedRules()
	if err != nil {
		fmt.Fprintf(w, "    AXFR failed: %v\n", err)
		return
	}
	for _, n := range sortedKeys(served) {
		fmt.Fprintf(w, "    %-40s CNAME %-14s %s\n", n, served[n], actionName(served[n]))
	}
	if len(served) == 0 {
		fmt.Fprintf(w, "    (no rules)\n")
	}
}

func (l *lab) add(w http.ResponseWriter, r *http.Request) {
	name := dns.Fqdn(r.URL.Query().Get("name"))
	if name == "." {
		http.Error(w, "need ?name=", http.StatusBadRequest)
		return
	}
	action, err := parseAction(r.URL.Query().Get("action"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	before, _ := l.pop.Serial()
	upstream := l.feed.Set(name, action)
	fmt.Fprintf(w, "upstream: %s %s, feed serial now %d\n", name, action, upstream)

	if action == rig.PASSTHRU {
		fmt.Fprintf(w, "pop:      not waiting -- a PASSTHRU rule in a DENYLIST feed is misplaced by\n"+
			"          definition, so pop moves it to its allow_catchall bucket instead of\n"+
			"          serving it. Note that bucket is STICKY: it is shared by every source\n"+
			"          and carries no record of who contributed what, so removing the rule\n"+
			"          upstream will NOT take the name back out, and the name stays\n"+
			"          allowlisted -- which outranks any later denylist rule for it.\n")
		return
	}

	owner := name + l.pop.ZoneName
	start := time.Now()
	served, got, err := l.pop.WaitForPresent(owner, *waitFor)
	if err != nil {
		fmt.Fprintf(w, "pop:      FAILED after %s: %v\n", time.Since(start).Round(time.Millisecond), err)
		fmt.Fprintf(w, "          if this name was ever added as PASSTHRU, it is stuck in\n"+
			"          allow_catchall and no denylist rule will bring it back.\n")
		return
	}
	fmt.Fprintf(w, "pop:      serving %s as %s %s after %s; serial %d -> %d\n",
		owner, served, actionName(string(served)), time.Since(start).Round(time.Millisecond), before, got)
	if served != action {
		fmt.Fprintf(w, "          (upstream asked for %s %s. pop answers a denylisted name with the\n"+
			"          CONFIGURED policy.denylist.action, so the upstream's own action is not\n"+
			"          what gets served. This is pop's behaviour, not the rig's.)\n",
			action, actionName(string(action)))
	}
}

func (l *lab) del(w http.ResponseWriter, r *http.Request) {
	name := dns.Fqdn(r.URL.Query().Get("name"))
	if name == "." {
		http.Error(w, "need ?name=", http.StatusBadRequest)
		return
	}

	before, _ := l.pop.Serial()
	upstream := l.feed.Remove(name)
	fmt.Fprintf(w, "upstream: removed %s, feed serial now %d\n", name, upstream)

	owner := name + l.pop.ZoneName
	start := time.Now()
	if err := l.pop.WaitForAbsent(owner, *waitFor); err != nil {
		fmt.Fprintf(w, "pop:      FAILED after %s: %v\n", time.Since(start).Round(time.Millisecond), err)
		return
	}
	after, _ := l.pop.Serial()
	fmt.Fprintf(w, "pop:      %s gone after %s; serial %d -> %d\n",
		owner, time.Since(start).Round(time.Millisecond), before, after)
}

func (l *lab) logtail(w http.ResponseWriter, r *http.Request) {
	n := 40
	if v := r.URL.Query().Get("n"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			n = parsed
		}
	}
	lines := strings.Split(strings.TrimRight(l.pop.Log(), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	fmt.Fprintln(w, strings.Join(lines, "\n"))
}

func (l *lab) stop(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "stopping pop and exiting")
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	select {
	case <-l.quit:
	default:
		close(l.quit)
	}
}

func (l *lab) servedRules() (map[string]string, error) {
	rrs, err := l.pop.AXFR()
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, rr := range rrs {
		if c, ok := rr.(*dns.CNAME); ok {
			out[strings.ToLower(c.Hdr.Name)] = c.Target
		}
	}
	return out, nil
}

// actionName names a CNAME target, so the zone reads as policy and not just as
// punctuation. Unrecognised targets are shown as-is rather than guessed at.
func actionName(target string) string {
	switch strings.ToLower(target) {
	case ".":
		return "(NXDOMAIN)"
	case "*.":
		return "(NODATA)"
	case "rpz-drop.":
		return "(DROP)"
	case "rpz-passthru.":
		return "(PASSTHRU)"
	}
	return ""
}

func parseAction(s string) (rig.Action, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "", "NXDOMAIN":
		return rig.NXDOMAIN, nil
	case "NODATA":
		return rig.NODATA, nil
	case "DROP":
		return rig.DROP, nil
	case "PASSTHRU", "ALLOWLIST", "RPZ-PASSTHRU":
		return rig.PASSTHRU, nil
	}
	return "", fmt.Errorf("unknown action %q: use NXDOMAIN, NODATA, DROP or PASSTHRU", s)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func host(addr string) string {
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[:i]
	}
	return addr
}

func port(addr string) string {
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[i+1:]
	}
	return ""
}
