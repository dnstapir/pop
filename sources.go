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

	pd.Lists["whitelist"] = make(map[string]*tapir.WBGlist, 3)
	pd.Lists["greylist"] = make(map[string]*tapir.WBGlist, 3)
	pd.Lists["blacklist"] = make(map[string]*tapir.WBGlist, 3)
	pd.Downstreams = map[string]RpzDownstream{}
	pd.DownstreamSerials = map[string]uint32{}

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
	pd.Policy.WhitelistAction, err = tapir.StringToAction(viper.GetString("policy.whitelist.action"))
	if err != nil {
		POPExiter("Error parsing whitelist policy: %v", err)
	}
	pd.Policy.BlacklistAction, err = tapir.StringToAction(viper.GetString("policy.blacklist.action"))
	if err != nil {
		POPExiter("Error parsing blacklist policy: %v", err)
	}
	pd.Policy.Greylist.NumSources = viper.GetInt("policy.greylist.numsources.limit")
	if pd.Policy.Greylist.NumSources == 0 {
		//nolint:typecheck
		POPExiter("Error parsing policy: greylist.numsources.limit cannot be 0")
	}
	pd.Policy.Greylist.NumSourcesAction, err =
		tapir.StringToAction(viper.GetString("policy.greylist.numsources.action"))
	if err != nil {
		POPExiter("Error parsing policy: %v", err)
	}

	pd.Policy.Greylist.NumTapirTags = viper.GetInt("policy.greylist.numtapirtags.limit")
	if pd.Policy.Greylist.NumTapirTags == 0 {
		POPExiter("Error parsing policy: greylist.numtapirtags.limit cannot be 0")
	}
	pd.Policy.Greylist.NumTapirTagsAction, err =
		tapir.StringToAction(viper.GetString("policy.greylist.numtapirtags.action"))
	if err != nil {
		POPExiter("Error parsing policy: %v", err)
	}

	tmp := viper.GetStringSlice("policy.greylist.blacktapir.tags")
	pd.Policy.Greylist.BlackTapirTags, err = tapir.StringsToTagMask(tmp)
	if err != nil {
		POPExiter("Error parsing policy: %v", err)
	}
	pd.Policy.Greylist.BlackTapirAction, err =
		tapir.StringToAction(viper.GetString("policy.greylist.blacktapir.action"))
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
	pd.Lists["whitelist"]["white_catchall"] =
		&tapir.WBGlist{
			Name:        "white_catchall",
			Description: "Whitelist consisting of white names found in black- or greylist sources",
			Type:        "whitelist",
			SrcFormat:   "none",
			Format:      "map",
			Datasource:  "Data misplaced in other sources",
			Names:       map[string]tapir.TapirName{},
			ReaperData:  map[time.Time]map[string]bool{},
		}
	pd.Lists["greylist"]["grey_catchall"] =
		&tapir.WBGlist{
			Name:        "grey_catchall",
			Description: "Greylist consisting of grey names found in whitelist sources",
			Type:        "greylist",
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

	var rptchan = make(chan string, 5)

	for name, src := range srcs {
		if !*src.Active {
			pd.Logger.Printf("*** ParseSourcesNG: Source \"%s\" is not active. Ignored.", name)
			continue
		}
		if pd.Debug {
			pd.Logger.Printf("=== ParseSourcesNG: Source: %s (%s) will be used (list type %s)", name, src.Name, src.Type)
		}

		var err error

		threads++

		go func(name string, src SourceConf, thread int) {
			//			defer func() {
			//pd.Logger.Printf("<--Thread %d: source \"%s\" (%s) is now complete. %d remaining", thread, name, src.Source, threads)
			// }()
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
				if pd.Debug {
					pd.Logger.Printf("ParseSourcesNG: Fetching MQTT validator key for topic %s", src.Topic)
				}
				valkey, err := tapir.FetchMqttValidatorKey(src.Topic, src.ValidatorKey)
				if err != nil {
					pd.Logger.Printf("ParseSources: Error fetching MQTT validator key for topic %s: %v", src.Topic, err)
				}

				pd.Logger.Printf("ParseSourcesNG: Adding topic '%s' to MQTT Engine", src.Topic)
				topicdata, err := pd.MqttEngine.SubToTopic(src.Topic, valkey, pd.TapirObservations, "struct", true) // XXX: Brr. kludge.
				if err != nil {
					POPExiter("Error adding topic %s to MQTT Engine: %v", src.Topic, err)
				}
				pd.Logger.Printf("ParseSourcesNG: Topic data for topic %s: %+v", src.Topic, topicdata)

				newsource.Format = "map" // for now
				if len(src.Bootstrap) > 0 {
					pd.Logger.Printf("ParseSourcesNG: The %s MQTT source has %d bootstrap servers: %v", src.Name, len(src.Bootstrap), src.Bootstrap)
					tmp, err := pd.BootstrapMqttSource(&newsource, src)
					if err != nil {
						pd.Logger.Printf("Error bootstrapping MQTT source %s: %v", src.Name, err)
					} else {
						newsource = *tmp
					}
				}
				pd.mu.Lock()
				pd.Lists["greylist"][newsource.Name] = &newsource
				pd.Logger.Printf("Created list [greylist][%s]", newsource.Name)
				pd.mu.Unlock()
				pd.Logger.Printf("*** MQTT sources are only managed via RefreshEngine.")
				rptchan <- name
			case "file":
				err = pd.ParseLocalFile(name, &newsource, rptchan)
			case "xfr":
				err = pd.ParseRpzFeed(name, &newsource, rptchan)
				pd.Logger.Printf("Thread %d: source \"%s\" now returned from ParseRpzFeed(). %d remaining", thread, name, threads)
			default:
				pd.Logger.Printf("*** ParseSourcesNG: Error: unhandled source type %s", src.Source)
			}
			if err != nil {
				log.Printf("Error parsing source %s (datasource %s): %v",
					name, src.Source, err)
			}
		}(name, src, threads)
	}

	for {
		if threads == 0 {
			break
		}
		tmp := <-rptchan
		threads--
		pd.Logger.Printf("ParseSources: source \"%s\" is now complete. %d remaining", tmp, threads)
	}

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

func (pd *PopData) ParseLocalFile(sourceid string, s *tapir.WBGlist, rpt chan string) error {
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
		if s.Type != "whitelist" {
			POPExiter("Error: source %s (file %s): DAWG is only defined for whitelists.",
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
	rpt <- sourceid

	return nil
}

func (pd *PopData) ParseRpzFeed(sourceid string, s *tapir.WBGlist, rpt chan string) error {
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
	rpt <- sourceid
	pd.Logger.Printf("ParseRpzFeed: parsing RPZ %s complete", s.RpzZoneName)

	return nil
}

// Parse the CNAME (in the shape of a dns.RR) that is found in the RPZ and sort the data into the
// appropriate list in PopData. Note that there are two special cases:
//  1. If a "whitelist" RPZ source has a rule with an action other than "rpz-passthru." then that rule doesn't
//     really belong in a "whitelist" source. So we take that rule an put it in the grey_catchall bucket instead.
//  2. If a "{grey|black}list" RPZ source has a rule with an "rpz-passthru." (i.e. whitelist) action then that
//     rule doesn't really belong in a "{grey|black}list" source. So we take that rule an put it in the
//     white_catchall bucket instead.
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
				action = tapir.WHITELIST
			default:
				pd.Logger.Printf("UNKNOWN RPZ action: \"%s\" (src: %s)", (*rr).(*dns.CNAME).Target, s.Name)
				action = tapir.UnknownAction
			}
			if tapir.GlobalCF.Debug {
				pd.Logger.Printf("ParseFunc: zone %s: name %s action: %v", zd.ZoneName,
					name, action)
			}
			switch s.Type {
			case "whitelist":
				if action == tapir.WHITELIST {
					s.Names[name] = tapir.TapirName{Name: name} // drop all other actions
				} else {
					pd.Logger.Printf("Warning: whitelist RPZ source %s has blacklisted name: %s",
						s.RpzZoneName, name)
					pd.mu.Lock()
					pd.Lists["greylist"]["grey_catchall"].Names[name] =
						tapir.TapirName{
							Name:   name,
							Action: action,
						} // drop all other actions
					pd.mu.Unlock()
				}
			case "blacklist":
				if action != tapir.WHITELIST {
					s.Names[name] = tapir.TapirName{Name: name, Action: action}
				} else {
					pd.Logger.Printf("Warning: blacklist RPZ source %s has whitelisted name: %s",
						s.RpzZoneName, name)
					pd.mu.Lock()
					pd.Lists["whitelist"]["white_catchall"].Names[name] = tapir.TapirName{Name: name}
					pd.mu.Unlock()
				}
			case "greylist":
				if action != tapir.WHITELIST {
					s.Names[name] = tapir.TapirName{Name: name, Action: action}
				} else {
					pd.Logger.Printf("Warning: greylist RPZ source %s has whitelisted name: %s",
						s.RpzZoneName, name)
					pd.mu.Lock()
					pd.Lists["whitelist"]["white_catchall"].Names[name] = tapir.TapirName{Name: name}
					pd.mu.Unlock()
				}
			}
		}
		return true
	}
}
