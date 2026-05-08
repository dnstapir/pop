/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package pop

import (
	"errors"
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
	"gopkg.in/yaml.v3"
)

func NewPopData(conf *Config, lg *log.Logger) (*PopData, error) {
	rpzdata := RpzData{
		CurrentSerial: 1,
		ZoneName:      viper.GetString("services.rpz.zonename"),
		IxfrChain:     []RpzIxfr{},
		Axfr: RpzAxfr{
			Data: map[string]*tapir.RpzName{},
		},
		// RpzMap: map[string]*tapir.RpzName{},
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
	pd.DownstreamSerials = map[string]uint32{}

	err := pd.ParseOutputs()
	if err != nil {
		return nil, fmt.Errorf("ParseOutputs: %w", err)
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
		return nil, fmt.Errorf("error parsing allowlist policy: %w", err)
	}
	pd.Policy.DenylistAction, err = tapir.StringToAction(viper.GetString("policy.denylist.action"))
	if err != nil {
		return nil, fmt.Errorf("error parsing denylist policy: %w", err)
	}
	pd.Policy.Doubtlist.NumSources = viper.GetInt("policy.doubtlist.numsources.limit")
	if pd.Policy.Doubtlist.NumSources == 0 {
		return nil, fmt.Errorf("error parsing policy: doubtlist.numsources.limit cannot be 0")
	}
	pd.Policy.Doubtlist.NumSourcesAction, err =
		tapir.StringToAction(viper.GetString("policy.doubtlist.numsources.action"))
	if err != nil {
		return nil, fmt.Errorf("error parsing policy: %w", err)
	}

	pd.Policy.Doubtlist.NumTapirTags = viper.GetInt("policy.doubtlist.numtapirtags.limit")
	if pd.Policy.Doubtlist.NumTapirTags == 0 {
		return nil, fmt.Errorf("error parsing policy: doubtlist.numtapirtags.limit cannot be 0")
	}
	pd.Policy.Doubtlist.NumTapirTagsAction, err =
		tapir.StringToAction(viper.GetString("policy.doubtlist.numtapirtags.action"))
	if err != nil {
		return nil, fmt.Errorf("error parsing policy: %w", err)
	}

	tmp := viper.GetStringSlice("policy.doubtlist.denytapir.tags")
	pd.Policy.Doubtlist.DenyTapirTags, err = tapir.StringsToTagMask(tmp)
	if err != nil {
		return nil, fmt.Errorf("error parsing policy: %w", err)
	}
	pd.Policy.Doubtlist.DenyTapirAction, err =
		tapir.StringToAction(viper.GetString("policy.doubtlist.denytapir.action"))
	if err != nil {
		return nil, fmt.Errorf("error parsing policy: %w", err)
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

	threads := 0

	type sourceResult struct {
		name string
		err  error
	}
	resultCh := make(chan sourceResult, len(srcs))

	for name, src := range srcs {
		if !*src.Active {
			pd.Logger.Printf("*** ParseSourcesNG: Source \"%s\" is not active. Ignored.", name)
			continue
		}
		if pd.Debug {
			pd.Logger.Printf("=== ParseSourcesNG: Source: %s (%s) will be used (list type %s)", name, src.Name, src.Type)
		}
		threads++

		go func(name string, src SourceConf, thread int) {
			var err error
			defer func() {
				resultCh <- sourceResult{name: name, err: err}
			}()
			pd.Logger.Printf("-->Thread %d: parsing source \"%s\" (source %s)", thread, name, src.Source)

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

			pd.Logger.Printf("ParseSourcesNG: thread %d working on source \"%s\" (%s)", thread, name, src.Source)
			switch src.Source {
			case "mqtt":
				if pd.MqttEngine == nil {
					err = fmt.Errorf("MQTT Engine not configured")
					return
				}
				if pd.Debug {
					pd.Logger.Printf("ParseSourcesNG: Fetching MQTT validator key for topic %s", src.Topic)
				}

				pd.Logger.Printf("ParseSourcesNG: Adding topic '%s' to MQTT Engine", src.Topic)
				err = pd.MqttEngine.SubToTopic(src.Topic, pd.TapirObservations, "struct", true) // XXX: Brr. kludge.
				if err != nil {
					err = fmt.Errorf("error adding topic %s to MQTT Engine: %w", src.Topic, err)
					return
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
			case "file":
				err = pd.ParseLocalFile(name, &newsource)
			case "xfr":
				err = pd.ParseRpzFeed(name, &newsource)
				pd.Logger.Printf("Thread %d: source \"%s\" now returned from ParseRpzFeed(). %d remaining", thread, name, threads)
			default:
				err = fmt.Errorf("unhandled source type %s", src.Source)
			}
			if err != nil {
				log.Printf("Error parsing source %s (datasource %s): %v",
					name, src.Source, err)
			}
		}(name, src, threads)
	}

	var errs []error
	for threads > 0 {
		result := <-resultCh
		threads--
		if result.err != nil {
			errs = append(errs, fmt.Errorf("source %s: %w", result.name, result.err))
		}
		pd.Logger.Printf("ParseSources: source \"%s\" is now complete. %d remaining", result.name, threads)
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	if pd.MqttEngine != nil && !pd.TapirMqttEngineRunning {
		err := pd.StartMqttEngine(pd.MqttEngine)
		if err != nil {
			return fmt.Errorf("error starting MQTT Engine: %w", err)
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
		return fmt.Errorf("source %s of type file has undefined filename", sourceid)
	}

	switch s.SrcFormat {
	case "domains":
		s.Names = map[string]tapir.TapirName{}
		s.Format = "map"
		_, err := tapir.ParseText(s.Filename, s.Names, true)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("source %s (type file: %s) does not exist", sourceid, s.Filename)
			}
			return fmt.Errorf("error parsing file %s: %w", s.Filename, err)
		}

	case "csv":
		s.Names = map[string]tapir.TapirName{}
		s.Format = "map"
		_, err := tapir.ParseCSV(s.Filename, s.Names, true)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("source %s (type file: %s) does not exist", sourceid, s.Filename)
			}
			return fmt.Errorf("error parsing file %s: %w", s.Filename, err)
		}

	case "dawg":
		if s.Type != "allowlist" {
			return fmt.Errorf("source %s (file %s): DAWG is only defined for allowlists", sourceid, s.Filename)
		}
		pd.Logger.Printf("ParseLocalFile: loading DAWG: %s", s.Filename)
		df, err = dawg.Load(s.Filename)
		if err != nil {
			return fmt.Errorf("dawg.Load(%s): %w", s.Filename, err)
		}
		pd.Logger.Printf("ParseLocalFile: DAWG loaded")
		s.Format = "dawg"
		s.Dawgf = df

	default:
		return fmt.Errorf("SrcFormat %q is unknown", s.SrcFormat)
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

	result := <-reRpt
	if result.Error {
		return fmt.Errorf("refreshing RPZ source %s: %s", sourceid, result.ErrorMsg)
	}

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
