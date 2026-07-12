/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package main

import (
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dnstapir/tapir"
	"github.com/miekg/dns"
)

type PopData struct {
	mu                     sync.RWMutex
	Lists                  map[string]map[string]*tapir.WBGlist
	RpzRefreshCh           chan RpzRefresh
	RpzCommandCh           chan RpzCmdData
	TapirMqttEngineRunning bool
	TapirMqttCmdCh         chan tapir.MqttEngineCmd
	// TapirMqttSubCh         chan tapir.MqttPkg
	TapirObservations chan tapir.MqttPkgIn
	TapirMqttPubCh    chan tapir.MqttPkgOut
	ComponentStatusCh chan tapir.ComponentStatusUpdate
	Logger            *log.Logger
	MqttLogger        *log.Logger
	DenylistedNames   map[string]bool
	DoubtlistedNames  map[string]*tapir.TapirName
	Policy            PopPolicy

	// snapshot is the immutable, currently-served RPZ zone. Readers (DNS
	// AXFR/IXFR/SOA handlers, HTTP debug) do snapshot.Load() and read the
	// returned *ZoneSnapshot lock-free; it is never mutated after publish.
	// The RefreshEngine goroutine is the sole publisher (snapshot.Store()).
	// See docs/2026-06-02-pop-149-snapshot-concurrency-design.md.
	snapshot atomic.Pointer[ZoneSnapshot]

	// Rpz holds engine-private working state used to BUILD snapshots
	// (the canonical serial, the zone name). Only touched on the engine
	// goroutine (plus the guarded startup window).
	Rpz RpzData

	RpzSources        map[string]*tapir.ZoneData // input feeds (generic zones); engine-side
	Downstreams       map[string]RpzDownstream   // map[ipaddr]RpzDownstream
	downstreamSerials *downstreamTracker         // SOA serials by downstream IP; own mutex
	ReaperInterval    time.Duration
	MqttEngine        *tapir.MqttEngine
	Verbose           bool
	Debug             bool
}

type RpzDownstream struct {
	Address string
	Port    int
}

// RpzData is engine-private working state. The served zone lives in the
// published ZoneSnapshot, not here.
type RpzData struct {
	CurrentSerial uint32
	ZoneName      string
}

type RpzIxfr struct {
	FromSerial uint32
	ToSerial   uint32
	Removed    []*tapir.RpzName
	Added      []*tapir.RpzName
}

// ZoneSnapshot is the compiled RPZ zone exactly as served. It is built by the
// RefreshEngine and, once published via PopData.snapshot.Store, is NEVER
// mutated. Every served field is bundled here so a single atomic pointer load
// yields a mutually-consistent view. The IXFR FROM/TO inner SOAs are derived
// from this single SOA (copying it and overriding .Serial), so there is now
// exactly one authoritative SOA — no dual-SOA drift.
type ZoneSnapshot struct {
	ZoneName  string
	Serial    uint32
	SOA       dns.SOA
	NSrrs     []dns.RR
	Data      map[string]*tapir.RpzName // fresh map per publish
	IxfrChain []RpzIxfr                 // fresh slice per publish; newest LAST; bounded
}

// maxIxfrChain bounds the in-memory IXFR delta chain. A downstream further
// behind than this is served a full AXFR instead. Prevents a slow/dead/spoofed
// downstream from pinning unbounded memory.
const maxIxfrChain = 1000

// downstreamTracker records the latest SOA serial each downstream claims to
// hold. It is written from DNS handler goroutines (so it has its own mutex —
// it is the one piece of shared state not owned by the engine goroutine) and
// read by the engine when pruning the IXFR chain.
type downstreamTracker struct {
	mu      sync.Mutex
	serials map[string]uint32
}

func newDownstreamTracker() *downstreamTracker {
	return &downstreamTracker{serials: map[string]uint32{}}
}

func (d *downstreamTracker) record(ip string, serial uint32) {
	d.mu.Lock()
	d.serials[ip] = serial
	d.mu.Unlock()
}

// lowest returns the smallest serial any tracked downstream claims, and whether
// there were any downstreams at all. Used to decide how far the IXFR chain can
// be pruned (we must keep deltas back to the slowest downstream).
func (d *downstreamTracker) lowest() (uint32, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.serials) == 0 {
		return 0, false
	}
	var low uint32 = ^uint32(0)
	for _, s := range d.serials {
		if s < low {
			low = s
		}
	}
	return low, true
}

type PopPolicy struct {
	Logger          *log.Logger
	AllowlistAction tapir.Action
	DenylistAction  tapir.Action
	Doubtlist       DoubtlistPolicy
}

type DoubtlistPolicy struct {
	NumSources         int
	NumSourcesAction   tapir.Action
	NumTapirTags       int
	NumTapirTagsAction tapir.Action
	DenyTapirTags      tapir.TagMask
	DenyTapirAction    tapir.Action
}

// type WBGC map[string]*tapir.WBGlist

type SrcFoo struct {
	Src struct {
		Style string `yaml:"style"`
	} `yaml:"src"`
	Sources map[string]SourceConf `yaml:"sources"`
}
