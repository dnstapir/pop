/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dnstapir/tapir"
	"github.com/miekg/dns"
	"github.com/smhanov/dawg"
	"github.com/spf13/viper"

	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"
)

func NewPopData(conf *Config, lg *log.Logger) (*PopData, error) {
	rpzdata := RpzData{
		CurrentSerial: 1,
		ZoneName:      viper.GetString("services.rpz.zonename"),
	}

	repint := viper.GetInt("services.reaper.interval")
	if repint == 0 {
		repint = 60
	}

	pd := PopData{
		Lists:             map[string]map[string]*tapir.WBGlist{},
		Logger:            lg,
		MqttLogger:        conf.Loggers.Mqtt,
		RpzRefreshCh:      make(chan RpzRefresh, 10),
		RpzCommandCh:      make(chan RpzCmdData, 10),
		ComponentStatusCh: conf.Internal.ComponentStatusCh,
		Rpz:               rpzdata,
		ReaperInterval:    time.Duration(repint) * time.Second,
		Verbose:           viper.GetBool("log.verbose"),
		Debug:             viper.GetBool("log.debug"),
	}

	pd.Lists["allowlist"] = make(map[string]*tapir.WBGlist, 3)
	pd.Lists["doubtlist"] = make(map[string]*tapir.WBGlist, 3)
	pd.Lists["denylist"] = make(map[string]*tapir.WBGlist, 3)
	pd.Downstreams = map[string]RpzDownstream{}
	pd.downstreamSerials = newDownstreamTracker()

	err := pd.ParseOutputs()
	if err != nil {
		POPExiter("NewPopData: Error from ParseOutputs(): %v", err)
	}

	//	pd.Rpz.IxfrChain = map[uint32]RpzIxfr{}
	pd.RpzSources = map[string]*tapir.ZoneData{}

	err = pd.BootstrapRpzOutput()
	if err != nil {
		pd.Logger.Printf("Error from BootstrapRpzOutput(): %v", err)
	}

	pd.Policy.Logger = conf.Loggers.Policy
	pd.Policy.AllowlistAction, err = tapir.StringToAction(viper.GetString("policy.allowlist.action"))
	if err != nil {
		POPExiter("Error parsing allowlist policy: %v", err)
	}
	pd.Policy.DenylistAction, err = tapir.StringToAction(viper.GetString("policy.denylist.action"))
	if err != nil {
		POPExiter("Error parsing denylist policy: %v", err)
	}
	pd.Policy.Doubtlist.NumSources = viper.GetInt("policy.doubtlist.numsources.limit")
	if pd.Policy.Doubtlist.NumSources == 0 {
		//nolint:typecheck
		POPExiter("Error parsing policy: doubtlist.numsources.limit cannot be 0")
	}
	pd.Policy.Doubtlist.NumSourcesAction, err =
		tapir.StringToAction(viper.GetString("policy.doubtlist.numsources.action"))
	if err != nil {
		POPExiter("Error parsing policy: %v", err)
	}

	pd.Policy.Doubtlist.NumTapirTags = viper.GetInt("policy.doubtlist.numtapirtags.limit")
	if pd.Policy.Doubtlist.NumTapirTags == 0 {
		POPExiter("Error parsing policy: doubtlist.numtapirtags.limit cannot be 0")
	}
	pd.Policy.Doubtlist.NumTapirTagsAction, err =
		tapir.StringToAction(viper.GetString("policy.doubtlist.numtapirtags.action"))
	if err != nil {
		POPExiter("Error parsing policy: %v", err)
	}

	tmp := viper.GetStringSlice("policy.doubtlist.denytapir.tags")
	pd.Policy.Doubtlist.DenyTapirTags, err = tapir.StringsToTagMask(tmp)
	if err != nil {
		POPExiter("Error parsing policy: %v", err)
	}
	pd.Policy.Doubtlist.DenyTapirAction, err =
		tapir.StringToAction(viper.GetString("policy.doubtlist.denytapir.action"))
	if err != nil {
		POPExiter("Error parsing policy: %v", err)
	}

	// Note: We can not parse data sources here, as RefreshEngine has not yet started.
	conf.PopData = &pd
	return &pd, nil
}

func (pd *PopData) ParseSourcesNG() error {
	var srcfoo SrcFoo
	configFile := filepath.Clean(tapir.PopSourcesCfgFile)
	data, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("error reading config file: %v", err)
	}

	err = yaml.Unmarshal(data, &srcfoo)
	if err != nil {
		return fmt.Errorf("error unmarshalling YAML data: %v", err)
	}
	//	log.Printf("ParseSourcesNG: Defined policy sources:\n")
	//	for name, src := range srcfoo.Sources {
	//		log.Printf("  %s: %s", name, src.Description)
	//	}

	pd.mu.Lock()
	pd.Lists["allowlist"]["allow_catchall"] =
		&tapir.WBGlist{
			Name:        "allow_catchall",
			Description: "Allowlist consisting of allow names found in deny- or doubtlist sources",
			Type:        "allowlist",
			SrcFormat:   "none",
			Format:      "map",
			Datasource:  "Data misplaced in other sources",
			Names:       map[string]tapir.TapirName{},
			ReaperData:  map[time.Time]map[string]bool{},
		}
	pd.Lists["doubtlist"]["doubt_catchall"] =
		&tapir.WBGlist{
			Name:        "doubt_catchall",
			Description: "Doubtlist consisting of doubt names found in allowlist sources",
			Type:        "doubtlist",
			SrcFormat:   "none",
			Format:      "map",
			Datasource:  "Data misplaced in other sources",
			Names:       map[string]tapir.TapirName{},
			ReaperData:  map[time.Time]map[string]bool{},
		}
	pd.mu.Unlock()

	srcs := srcfoo.Sources
	pd.Logger.Printf("*** ParseSourcesNG: there are %d sources defined in config", len(srcs))

	// Each active source is parsed in its own goroutine. We use an errgroup
	// rather than a hand-rolled WaitGroup/counter+channel: a source completes
	// when its closure *returns*, so there is no separate "signal done" step
	// to forget (the old code deadlocked when a source type was unhandled and
	// never signalled its completion channel). g.Wait() also collects the
	// first error for free.
	var g errgroup.Group

	for name, src := range srcs {
		if !*src.Active {
			pd.Logger.Printf("*** ParseSourcesNG: Source \"%s\" is not active. Ignored.", name)
			continue
		}
		if pd.Debug {
			pd.Logger.Printf("=== ParseSourcesNG: Source: %s (%s) will be used (list type %s)", name, src.Name, src.Type)
		}

		name, src := name, src // capture range vars for the closure

		g.Go(func() error {
			pd.Logger.Printf("--> parsing source \"%s\" (source %s)", name, src.Source)

			newsource := tapir.WBGlist{
				Name:        src.Name,
				Description: src.Description,
				Type:        src.Type,
				SrcFormat:   src.Format,
				Datasource:  src.Source,
				Names:       map[string]tapir.TapirName{},
				ReaperData:  map[time.Time]map[string]bool{},
				Filename:    src.Filename,
				RpzUpstream: src.Upstream,
				RpzZoneName: dns.Fqdn(src.Zone),
			}

			switch src.Source {
			case "mqtt":
				if pd.Debug {
					pd.Logger.Printf("ParseSourcesNG: Fetching MQTT validator key for topic %s", src.Topic)
				}

				// With MQTT ignored there is no engine to subscribe to. The
				// source is still registered, so it shows up in status output
				// as present-but-empty rather than vanishing without trace.
				if pd.MqttEngine == nil {
					pd.Logger.Printf("WARNING: MQTT source %s (topic %s) not subscribed: MQTT is not enabled (tapir.mqtt.mode)",
						src.Name, src.Topic)
				} else {
					pd.Logger.Printf("ParseSourcesNG: Adding topic '%s' to MQTT Engine", src.Topic)
					err := pd.MqttEngine.SubToTopic(src.Topic, pd.TapirObservations, "struct", true) // XXX: Brr. kludge.
					if err != nil {
						POPExiter("Error adding topic %s to MQTT Engine: %v", src.Topic, err)
					}
				}
				pd.Logger.Printf("ParseSourcesNG: Topic data for topic %s", src.Topic)

				mqttDetails := tapir.MqttDetails{
					Topics:       []string{src.Topic},
					Bootstrap:    src.Bootstrap,
					BootstrapUrl: src.BootstrapUrl,
					BootstrapKey: src.BootstrapKey,
				}
				newsource.MqttDetails = &mqttDetails
				newsource.Immutable = src.Immutable

				newsource.Format = "map" // for now
				if len(src.Bootstrap) > 0 {
					pd.Logger.Printf("ParseSourcesNG: The %s MQTT source has %d bootstrap servers: %v", src.Name, len(src.Bootstrap), src.Bootstrap)
					tmp, err := pd.BootstrapMqttSource(src)
					if err != nil {
						pd.Logger.Printf("Error bootstrapping MQTT source %s: %v", src.Name, err)
					} else {
						newsource = *tmp
					}
				}
				pd.mu.Lock()
				pd.Lists["doubtlist"][newsource.Name] = &newsource
				pd.Logger.Printf("Created list [doubtlist][%s]", newsource.Name)
				pd.mu.Unlock()
				pd.Logger.Printf("*** MQTT sources are only managed via RefreshEngine.")
				return nil
			case "file":
				return pd.ParseLocalFile(name, &newsource)
			case "xfr":
				err := pd.ParseRpzFeed(name, &newsource)
				pd.Logger.Printf("source \"%s\" now returned from ParseRpzFeed().", name)
				return err
			default:
				return fmt.Errorf("unhandled source type %q for source %q", src.Source, name)
			}
		})
	}

	// Source-parse failures are NON-FATAL by design: a single bad/unreachable
	// feed is logged and the remaining sources are kept, rather than aborting
	// startup of a daemon that may serve several feeds (this matches the
	// pre-errgroup log-and-continue behaviour). g.Wait() blocks until every
	// source goroutine has returned. We deliberately do NOT propagate this
	// error: ParseSourcesNG returns nil so the caller does not treat a single
	// failed feed as fatal. (Whether some classes of source failure SHOULD be
	// fatal is the broader fatal-vs-degrade question tracked in #154.)
	if err := g.Wait(); err != nil {
		log.Printf("ParseSourcesNG: at least one source failed to parse (non-fatal, continuing): %v", err)
	}
	pd.Logger.Printf("ParseSources: all sources done.")

	if pd.MqttEngine != nil && !pd.TapirMqttEngineRunning {
		mode, merr := mqttMode()
		if merr != nil {
			POPExiter("%v", merr)
		}
		if err := pd.StartMqttEngine(pd.MqttEngine, mode, Gconfig.Internal.ComponentStatusCh); err != nil {
			POPExiter("%v", err)
		}
	}

	pd.Logger.Printf("ParseSources: static sources done.")

	err = pd.GenerateRpzAxfr()
	if err != nil {
		pd.Logger.Printf("ParseSources: Error from GenerateRpzAxfr(): %v", err)
	}

	return nil
}

func (pd *PopData) ParseLocalFile(sourceid string, s *tapir.WBGlist) error {
	pd.Logger.Printf("ParseLocalFile: %s (%s)", sourceid, s.Type)
	var df dawg.Finder
	var err error

	s.Filename = viper.GetString(fmt.Sprintf("sources.%s.filename", sourceid))
	if s.Filename == "" {
		POPExiter("ParseLocalFile: source %s of type file has undefined filename",
			sourceid)
	}

	switch s.SrcFormat {
	case "domains":
		s.Names = map[string]tapir.TapirName{}
		s.Format = "map"
		_, err := tapir.ParseText(s.Filename, s.Names, true)
		if err != nil {
			if os.IsNotExist(err) {
				POPExiter("ParseLocalFile: source %s (type file: %s) does not exist",
					sourceid, s.Filename)
			}
			POPExiter("ParseLocalFile: error parsing file %s: %v", s.Filename, err)
		}

	case "csv":
		s.Names = map[string]tapir.TapirName{}
		s.Format = "map"
		_, err := tapir.ParseCSV(s.Filename, s.Names, true)
		if err != nil {
			if os.IsNotExist(err) {
				POPExiter("ParseLocalFile: source %s (type file: %s) does not exist",
					sourceid, s.Filename)
			}
			POPExiter("ParseLocalFile: error parsing file %s: %v", s.Filename, err)
		}

	case "dawg":
		if s.Type != "allowlist" {
			POPExiter("Error: source %s (file %s): DAWG is only defined for allowlists.",
				sourceid, s.Filename)
		}
		pd.Logger.Printf("ParseLocalFile: loading DAWG: %s", s.Filename)
		df, err = dawg.Load(s.Filename)
		if err != nil {
			POPExiter("Error from dawg.Load(%s): %v", s.Filename, err)
		}
		pd.Logger.Printf("ParseLocalFile: DAWG loaded")
		s.Format = "dawg"
		s.Dawgf = df

	default:
		POPExiter("ParseLocalFile: SrcFormat \"%s\" is unknown.", s.SrcFormat)
	}

	pd.mu.Lock()
	pd.Lists[s.Type][s.Name] = s
	pd.mu.Unlock()

	return nil
}

func (pd *PopData) ParseRpzFeed(sourceid string, s *tapir.WBGlist) error {
	//	zone := viper.GetString(fmt.Sprintf("sources.%s.zone", sourceid)) // XXX: not the way to do it
	//	if zone == "" {
	//		return fmt.Errorf("Unable to load RPZ source %s, upstream zone not specified.",
	//			sourceid)
	//	}
	//	pd.Logger.Printf("ParseRpzFeed: zone: %s params[zone]: %s", zone, s.Zone)

	upstream := viper.GetString(fmt.Sprintf("sources.%s.upstream", sourceid))
	if upstream == "" {
		return fmt.Errorf("unable to load RPZ source %s, upstream address not specified", sourceid)
	}

	s.Names = map[string]tapir.TapirName{} // must initialize
	s.Format = "map"
	//	s.RpzZoneName = dns.Fqdn(zone)
	//	s.RpzUpstream = upstream
	pd.Logger.Printf("---> SetupRPZFeed: about to transfer zone %s from %s", s.RpzZoneName, s.RpzUpstream)

	// The ingest travels with the refresh request: the engine needs it to turn
	// each later transfer into a delta (#197), not just to parse RRs.
	ingest := pd.newRpzFeedIngest(s)

	var reRpt = make(chan RpzRefreshResult, 1)
	pd.RpzRefreshCh <- RpzRefresh{
		Name:        s.RpzZoneName,
		Upstream:    s.RpzUpstream,
		RRParseFunc: ingest.ParseFunc(),
		Ingest:      ingest,
		ZoneType:    tapir.RpzZone,
		Resp:        reRpt,
	}

	<-reRpt

	pd.mu.Lock()
	pd.Lists[s.Type][s.Name] = s
	pd.mu.Unlock()
	pd.Logger.Printf("ParseRpzFeed: parsing RPZ %s complete", s.RpzZoneName)

	return nil
}

// stage records one name from the transfer currently being parsed.
func (ing *rpzFeedIngest) stage(name string, tn tapir.TapirName) {
	ing.mu.Lock()
	defer ing.mu.Unlock()
	ing.names[name] = tn
}

// rpzFeedIngest stages one zone transfer's worth of an RPZ source.
//
// The parse function used to write straight into s.Names, which only ever
// grows: a name dropped upstream stayed in pop's list forever (#197). It now
// accumulates here instead, and Commit turns the accumulated set into a DELTA
// against what the source already held.
//
// A delta rather than a wholesale replacement, deliberately. Inbound IXFR will
// deliver adds and deletes directly off the wire, and that delta can be applied
// by the same Commit path without materialising the whole zone. Replacing
// s.Names outright would work for AXFR and would have to be rewritten for IXFR.
//
// LIMITATION: the parse function also spills misplaced rules into the shared
// doubt_catchall / allow_catchall buckets -- an allowlist rule in a denylist
// feed, and so on. Those buckets are shared by every source and carry no record
// of which source contributed what, so a per-source diff cannot be applied to
// them and they still only grow. Narrower than the bug fixed here, on a path
// that only a misconfigured upstream reaches, and it needs per-source
// provenance to fix properly.
type rpzFeedIngest struct {
	pd  *PopData
	src *tapir.WBGlist

	mu    sync.Mutex
	names map[string]tapir.TapirName // what THIS transfer carried
}

func (pd *PopData) newRpzFeedIngest(s *tapir.WBGlist) *rpzFeedIngest {
	return &rpzFeedIngest{pd: pd, src: s, names: map[string]tapir.TapirName{}}
}

// Discard throws away a partial transfer, so a failed one cannot leak entries
// into the next transfer's delta.
func (ing *rpzFeedIngest) Discard() {
	ing.mu.Lock()
	defer ing.mu.Unlock()
	ing.names = map[string]tapir.TapirName{}
}

// Commit diffs what the transfer carried against what the source held, applies
// the difference to the source, and returns it.
//
// The staging map is cleared here rather than at the start of a transfer. That
// is what makes "no transfer happened" indistinguishable from "an empty
// transfer": if the upstream serial did not move, the parse function was never
// called, the staging map is still empty, and the caller does not call Commit
// at all. Resetting at transfer start would need the parse function to
// recognise transfer boundaries from the RR stream, which is guesswork.
func (ing *rpzFeedIngest) Commit() (added, removed []tapir.Domain) {
	ing.mu.Lock()
	fresh := ing.names
	ing.names = map[string]tapir.TapirName{}
	ing.mu.Unlock()

	ing.pd.mu.Lock()
	defer ing.pd.mu.Unlock()

	for name, tn := range fresh {
		if _, had := ing.src.Names[name]; !had {
			added = append(added, tapir.Domain{Name: name})
		}
		ing.src.Names[name] = tn
	}
	for name := range ing.src.Names {
		if _, still := fresh[name]; !still {
			removed = append(removed, tapir.Domain{Name: name})
		}
	}
	for _, d := range removed {
		delete(ing.src.Names, d.Name)
	}
	return added, removed
}

// ParseFunc is what the transfer machinery calls for each RR.
//
// It parses the CNAME (in the shape of a dns.RR) found in the RPZ and sorts the data into the
// appropriate list in PopData. Note that there are two special cases:
//  1. If a "allowlist" RPZ source has a rule with an action other than "rpz-passthru." then that rule doesn't
//     really belong in a "allowlist" source. So we take that rule an put it in the doubt_catchall bucket instead.
//  2. If a "{doubt|deny}list" RPZ source has a rule with an "rpz-passthru." (i.e. allowlist) action then that
//     rule doesn't really belong in a "{doubt|deny}list" source. So we take that rule an put it in the
//     allow_catchall bucket instead.
func (ing *rpzFeedIngest) ParseFunc() func(*dns.RR, *tapir.ZoneData) bool {
	pd := ing.pd
	s := ing.src
	return func(rr *dns.RR, zd *tapir.ZoneData) bool {
		var action tapir.Action
		name := strings.TrimSuffix((*rr).Header().Name, zd.ZoneName)
		switch (*rr).Header().Rrtype {
		case dns.TypeSOA, dns.TypeNS:
			if tapir.GlobalCF.Debug {
				pd.Logger.Printf("ParseFunc: RPZ %s: looking at %s", zd.ZoneName,
					dns.TypeToString[(*rr).Header().Rrtype])
			}
			return true
		case dns.TypeCNAME:
			switch (*rr).(*dns.CNAME).Target {
			case ".":
				action = tapir.NXDOMAIN
			case "*.":
				action = tapir.NODATA
			case "rpz-drop.":
				action = tapir.DROP
			case "rpz-passthru.":
				action = tapir.ALLOWLIST
			default:
				pd.Logger.Printf("UNKNOWN RPZ action: \"%s\" (src: %s)", (*rr).(*dns.CNAME).Target, s.Name)
				action = tapir.UnknownAction
			}
			if tapir.GlobalCF.Debug {
				pd.Logger.Printf("ParseFunc: zone %s: name %s action: %v", zd.ZoneName,
					name, action)
			}
			switch s.Type {
			case "allowlist":
				if action == tapir.ALLOWLIST {
					ing.stage(name, tapir.TapirName{Name: name}) // drop all other actions
				} else {
					pd.Logger.Printf("Warning: allowlist RPZ source %s has denylisted name: %s",
						s.RpzZoneName, name)
					pd.mu.Lock()
					pd.Lists["doubtlist"]["doubt_catchall"].Names[name] =
						tapir.TapirName{
							Name:   name,
							Action: action,
						} // drop all other actions
					pd.mu.Unlock()
				}
			case "denylist":
				if action != tapir.ALLOWLIST {
					ing.stage(name, tapir.TapirName{Name: name, Action: action})
				} else {
					pd.Logger.Printf("Warning: denylist RPZ source %s has allowlisted name: %s",
						s.RpzZoneName, name)
					pd.mu.Lock()
					pd.Lists["allowlist"]["allow_catchall"].Names[name] = tapir.TapirName{Name: name}
					pd.mu.Unlock()
				}
			case "doubtlist":
				if action != tapir.ALLOWLIST {
					ing.stage(name, tapir.TapirName{Name: name, Action: action})
				} else {
					pd.Logger.Printf("Warning: doubtlist RPZ source %s has allowlisted name: %s",
						s.RpzZoneName, name)
					pd.mu.Lock()
					pd.Lists["allowlist"]["allow_catchall"].Names[name] = tapir.TapirName{Name: name}
					pd.mu.Unlock()
				}
			}
		}
		return true
	}
}
