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

				pd.Logger.Printf("ParseSourcesNG: Adding topic '%s' to MQTT Engine", src.Topic)
				err := pd.MqttEngine.SubToTopic(src.Topic, pd.TapirObservations, "struct", true) // XXX: Brr. kludge.
				if err != nil {
					POPExiter("Error adding topic %s to MQTT Engine: %v", src.Topic, err)
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
		err := pd.StartMqttEngine(pd.MqttEngine)
		if err != nil {
			POPExiter("Error starting MQTT Engine: %v", err)
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

	var reRpt = make(chan RpzRefreshResult, 1)
	pd.RpzRefreshCh <- RpzRefresh{
		Name:        s.RpzZoneName,
		Upstream:    s.RpzUpstream,
		RRParseFunc: pd.RpzParseFuncFactory(s),
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

// Parse the CNAME (in the shape of a dns.RR) that is found in the RPZ and sort the data into the
// appropriate list in PopData. Note that there are two special cases:
//  1. If a "allowlist" RPZ source has a rule with an action other than "rpz-passthru." then that rule doesn't
//     really belong in a "allowlist" source. So we take that rule an put it in the doubt_catchall bucket instead.
//  2. If a "{doubt|deny}list" RPZ source has a rule with an "rpz-passthru." (i.e. allowlist) action then that
//     rule doesn't really belong in a "{doubt|deny}list" source. So we take that rule an put it in the
//     allow_catchall bucket instead.
func (pd *PopData) RpzParseFuncFactory(s *tapir.WBGlist) func(*dns.RR, *tapir.ZoneData) bool {
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
					s.Names[name] = tapir.TapirName{Name: name} // drop all other actions
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
					s.Names[name] = tapir.TapirName{Name: name, Action: action}
				} else {
					pd.Logger.Printf("Warning: denylist RPZ source %s has allowlisted name: %s",
						s.RpzZoneName, name)
					pd.mu.Lock()
					pd.Lists["allowlist"]["allow_catchall"].Names[name] = tapir.TapirName{Name: name}
					pd.mu.Unlock()
				}
			case "doubtlist":
				if action != tapir.ALLOWLIST {
					s.Names[name] = tapir.TapirName{Name: name, Action: action}
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
