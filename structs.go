/*
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
 * Copyright (c) DNS TAPIR
 */
package main

import (
	"log"
	"sync"
	"time"

	"github.com/dnstapir/tapir"
	"github.com/miekg/dns"
)

type TemData struct {
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
	BlacklistedNames  map[string]bool
	GreylistedNames   map[string]*tapir.TapirName
	Policy            TemPolicy
	Rpz               RpzData
	RpzSources        map[string]*tapir.ZoneData
	Downstreams       map[string]RpzDownstream // map[ipaddr]RpzDownstream
	DownstreamSerials map[string]uint32        // New map to track SOA serials by address
	ReaperInterval    time.Duration
	MqttEngine        *tapir.MqttEngine
	Verbose           bool
	Debug             bool
}

type RpzDownstream struct {
	Address string
	Port    int
	// Serial      uint32 // The serial that the downstream says that it already has in the latest IXFR request
	// Downstreams []string
}

type RpzData struct {
	CurrentSerial uint32
	ZoneName      string
	Axfr          RpzAxfr
	IxfrChain     []RpzIxfr // NOTE: the IxfrChain is in reverse order, newest first!
	// RpzZone       *tapir.ZoneData
	// RpzMap map[string]*tapir.RpzName
}

type RpzIxfr struct {
	FromSerial uint32
	ToSerial   uint32
	Removed    []*tapir.RpzName
	Added      []*tapir.RpzName
}

type RpzAxfr struct {
	Serial   uint32
	SOA      dns.SOA
	NSrrs    []dns.RR
	Data     map[string]*tapir.RpzName
	ZoneData *tapir.ZoneData
}

type TemPolicy struct {
	Logger          *log.Logger
	WhitelistAction tapir.Action
	BlacklistAction tapir.Action
	Greylist        GreylistPolicy
}

type GreylistPolicy struct {
	NumSources         int
	NumSourcesAction   tapir.Action
	NumTapirTags       int
	NumTapirTagsAction tapir.Action
	BlackTapirTags     tapir.TagMask
	BlackTapirAction   tapir.Action
}

// type WBGC map[string]*tapir.WBGlist

type SrcFoo struct {
	Src struct {
		Style string `yaml:"style"`
	} `yaml:"src"`
	Sources map[string]SourceConf `yaml:"sources"`
}
