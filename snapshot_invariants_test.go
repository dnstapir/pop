/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/dnstapir/tapir"
	"github.com/miekg/dns"
)

// Invariants of the snapshot model that are NOT expressible as ordinary
// behavioural tests, because what they forbid is a shape of code rather than a
// wrong answer.
//
// These exist because tdns adopted this same snapshot model from pop and then
// spent a series of post-merge fixes rediscovering its failure modes. Two of
// those are guarded here so pop does not repeat them: intra-response snapshot
// reloading (tdns's C1/M1) and publication escaping the engine goroutine
// (which tdns eventually had to enforce structurally rather than by comment).
//
// A comment saying "the engine is the sole publisher" is worth exactly nothing
// the day someone adds a Store() somewhere else. These fail the build instead.

// ---------------------------------------------------------------------------
// Source-level invariants
// ---------------------------------------------------------------------------

type funcInfo struct {
	name string
	file string
	decl *ast.FuncDecl
}

// packageFuncs parses the package's non-test sources.
func packageFuncs(t *testing.T) []funcInfo {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	fset := token.NewFileSet()
	var out []funcInfo
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", f, err)
		}
		for _, d := range af.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok {
				out = append(out, funcInfo{name: fd.Name.Name, file: f, decl: fd})
			}
		}
	}
	if len(out) == 0 {
		t.Fatal("parsed no functions; the test is not looking where it thinks it is")
	}
	return out
}

// countSnapshotOps counts `<x>.snapshot.<method>(...)` calls in a function.
func countSnapshotOps(fd *ast.FuncDecl, method string) int {
	n := 0
	ast.Inspect(fd, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != method {
			return true
		}
		inner, ok := sel.X.(*ast.SelectorExpr)
		if !ok || inner.Sel.Name != "snapshot" {
			return true
		}
		n++
		return true
	})
	return n
}

// callsAnyOf reports which of the named methods a function calls.
func callsAnyOf(fd *ast.FuncDecl, names ...string) []string {
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	var found []string
	ast.Inspect(fd, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && want[sel.Sel.Name] {
			found = append(found, sel.Sel.Name)
		}
		return true
	})
	return found
}

// A response must be served from exactly ONE snapshot.
//
// The snapshot is immutable, so serving from a slightly stale publish is always
// self-consistent. The danger is building one response out of TWO of them: a
// transfer that decides what to do from snapshot A and sends the data from
// snapshot C can report a serial that does not describe the bytes it sent.
//
// So Load() is allowed only in the outermost entry points, exactly once each,
// and the workers that do the serving must take the snapshot as a parameter.
func TestOneSnapshotLoadPerResponse(t *testing.T) {
	// The only functions permitted to pin a snapshot, and how many times.
	//
	// The two Generate* publishers are here because publishing is a
	// read-modify-publish: they load the current snapshot to build the next
	// one. That is safe ONLY because there is exactly one publisher, which is
	// what TestSnapshotPublisherIsEngineOwned enforces — the two tests hold
	// each other up. If a second publisher were ever added, this load-then-
	// store would become a lost-update race and that test would fail first.
	allowed := map[string]int{
		"RpzAxfrOut":      1, // public entry point: pins, then delegates
		"RpzIxfrOut":      1, // ditto
		"RpzResponder":    1, // pins once and threads it into the workers
		"QueryResponder":  1,
		"RefreshEngine":   1, // engine's own read-back
		"GenerateRpzAxfr": 1, // engine: read-modify-publish
		"GenerateRpzIxfr": 1, // engine: read-modify-publish
	}

	for _, fi := range packageFuncs(t) {
		n := countSnapshotOps(fi.decl, "Load")
		if n == 0 {
			continue
		}
		want, ok := allowed[fi.name]
		if !ok {
			t.Errorf("%s (%s) calls snapshot.Load(); only the response entry points may pin a snapshot. "+
				"If this needs one, take it as a parameter from the caller instead.", fi.name, fi.file)
			continue
		}
		if n != want {
			t.Errorf("%s (%s) calls snapshot.Load() %d times, want %d: a response served from two "+
				"snapshots can report a serial that does not describe what it sent", fi.name, fi.file, n, want)
		}
	}
}

// The snapshot-taking workers must not reload, and the entry point that pins
// must not call the wrappers that pin again.
func TestServingWorkersDoNotRepin(t *testing.T) {
	for _, fi := range packageFuncs(t) {
		switch fi.name {
		case "rpzAxfrOutFrom", "rpzIxfrOutFrom":
			if n := countSnapshotOps(fi.decl, "Load"); n != 0 {
				t.Errorf("%s calls snapshot.Load() %d times; it is given a snapshot precisely so it does not", fi.name, n)
			}
		case "RpzResponder":
			// Calling the public wrappers would re-pin and reintroduce the tear.
			if got := callsAnyOf(fi.decl, "RpzAxfrOut", "RpzIxfrOut"); len(got) > 0 {
				t.Errorf("RpzResponder calls %v, which pin their own snapshot. "+
					"Use rpzAxfrOutFrom / rpzIxfrOutFrom with the snapshot it already pinned.", got)
			}
		}
	}
}

// Publication belongs to the engine goroutine and nowhere else.
//
// The whole model rests on there being a single publisher: readers are
// lock-free because nothing races them, and a Store() from an HTTP or DNS
// handler would silently break that with no test failing. tdns ended up
// enforcing this structurally after the same model went in there; this is the
// cheap version of the same guard.
func TestSnapshotPublisherIsEngineOwned(t *testing.T) {
	allowed := map[string]bool{
		"GenerateRpzAxfr":    true, // engine: full rebuild
		"GenerateRpzIxfr":    true, // engine: incremental publish
		"BootstrapRpzOutput": true, // startup, before the engine serves
	}
	for _, fi := range packageFuncs(t) {
		if n := countSnapshotOps(fi.decl, "Store"); n > 0 && !allowed[fi.name] {
			t.Errorf("%s (%s) calls snapshot.Store(); publication must stay on the engine goroutine. "+
				"If a new publisher is genuinely needed, add it here deliberately and say why.", fi.name, fi.file)
		}
	}
}

// ---------------------------------------------------------------------------
// The sharing invariant
// ---------------------------------------------------------------------------

// A snapshot a reader is holding must never change under it.
//
// This is the invariant the whole model depends on, and it is NOT free: each
// publish builds a fresh Data map, but it carries NSrrs forward by reference
// and the *tapir.RpzName values are shared between publishes. That is a
// deliberate performance choice, and it means the rule "once published, a
// snapshot and everything reachable from it is frozen" has to hold by
// discipline. tdns had to write the equivalent invariant down after being
// bitten by it.
//
// This test pins the part that can be checked mechanically: a retained
// snapshot is unaffected by later publishes, and each publish really does
// allocate a new map rather than mutating the old one in place.
func TestPublishDoesNotMutateRetainedSnapshot(t *testing.T) {
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
	pd.snapshot.Store(&ZoneSnapshot{
		ZoneName: "rpz.zone.",
		Serial:   1,
		SOA:      mustSOA("rpz.zone.", 1),
		NSrrs:    []dns.RR{mustCNAME("ns.rpz.zone.", "placeholder.")},
		Data:     map[string]*tapir.RpzName{},
	})

	// A reader pins the snapshot, as any in-flight transfer would.
	held := pd.snapshot.Load()
	heldSerial := held.Serial
	heldSOASerial := held.SOA.Serial
	heldLen := len(held.Data)
	heldMap := reflect.ValueOf(held.Data).Pointer()
	heldNS := len(held.NSrrs)

	// The engine publishes repeatedly underneath it, through the real path.
	feed := pd.Lists["doubtlist"]["feed"]
	for r := 0; r < 25; r++ {
		name := dns.Fqdn("n" + strconv.Itoa(r) + ".example")
		feed.Names[name] = tapir.TapirName{Name: name}
		if _, err := pd.GenerateRpzIxfr(&tapir.TapirMsg{Added: []tapir.Domain{{Name: name}}}); err != nil {
			t.Fatalf("GenerateRpzIxfr: %v", err)
		}
	}

	if got := pd.snapshot.Load(); got.Serial == heldSerial {
		t.Fatalf("no publish happened (serial still %d); the test proves nothing", got.Serial)
	}

	// The retained snapshot must be exactly as it was.
	if held.Serial != heldSerial {
		t.Errorf("retained snapshot Serial changed: %d -> %d", heldSerial, held.Serial)
	}
	if held.SOA.Serial != heldSOASerial {
		t.Errorf("retained snapshot SOA.Serial changed: %d -> %d", heldSOASerial, held.SOA.Serial)
	}
	if len(held.Data) != heldLen {
		t.Errorf("retained snapshot Data grew from %d to %d entries: a publish mutated a map a reader was holding",
			heldLen, len(held.Data))
	}
	if len(held.NSrrs) != heldNS {
		t.Errorf("retained snapshot NSrrs changed length %d -> %d; NSrrs is shared between publishes "+
			"by reference and must be treated as frozen", heldNS, len(held.NSrrs))
	}

	// And each publish must allocate, not reuse.
	if cur := reflect.ValueOf(pd.snapshot.Load().Data).Pointer(); cur == heldMap {
		t.Error("the published snapshot reuses the same Data map object as the retained one; " +
			"publishes must build a fresh map, or readers see mutation")
	}
}
