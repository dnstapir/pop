/*
 * Copyright (c) DNS TAPIR
 */
package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/dnstapir/tapir"
	"github.com/miekg/dns"
	"github.com/smhanov/dawg"
	"github.com/spf13/viper"
)

type TemData struct {
	Blacklists             map[string]*tapir.WBGlist
	Whitelists             map[string]*tapir.WBGlist
	Greylists              map[string]*tapir.WBGlist
	RpzRefreshCh           chan RpzRefresh
	RpzCommandCh           chan RpzCmdData
	TapirMqttEngineRunning bool
	TapirMqttCmdCh         chan tapir.MqttEngineCmd
	TapirMqttSubCh         chan tapir.MqttPkg
	TapirMqttPubCh         chan tapir.MqttPkg // not used ATM
	Logger                 *log.Logger
	Output                 *tapir.ZoneData
}

func NewTemData(conf *Config, lg *log.Logger) (*TemData, error) {
	td := TemData{
	        Whitelists:	make(map[string]*tapir.WBGlist, 1000),
	        Blacklists:	make(map[string]*tapir.WBGlist, 1000),
	        Greylists:	make(map[string]*tapir.WBGlist, 1000),
		Logger:       lg,
		RpzRefreshCh: make(chan RpzRefresh, 10),
		RpzCommandCh: make(chan RpzCmdData, 10),
	}
	// Note: We can not parse data sources here, as RefreshEngine has not yet started.
	conf.TemData = &td
	return &td, nil
}

func (td *TemData) ParseSources() error {
	sources := viper.GetStringSlice("sources.active")
	log.Printf("Defined policy sources: %v", sources)

	for _, sourceid := range sources {
		listtype := viper.GetString(fmt.Sprintf("sources.%s.type", sourceid))
		if listtype == "" {
			TEMExiter("ParseSources: source %s has no list type", sourceid)
		}

		datasource := viper.GetString(fmt.Sprintf("sources.%s.source", sourceid))
		if datasource == "" {
			TEMExiter("ParseSources: source %s has no data source", sourceid)
		}

		name := viper.GetString(fmt.Sprintf("sources.%s.name", sourceid))
		if datasource == "" {
			TEMExiter("ParseSources: source %s has no name", sourceid)
		}

		desc := viper.GetString(fmt.Sprintf("sources.%s.description", sourceid))
		if desc == "" {
			TEMExiter("ParseSources: source %s has no description", sourceid)
		}

		format := viper.GetString(fmt.Sprintf("sources.%s.format", sourceid))
		if desc == "" {
			TEMExiter("ParseSources: source %s has no format description", sourceid)
		}

		td.Logger.Printf("Found source: %s (list type %s)", sourceid, listtype)

		newsource := tapir.WBGlist{
			Name:        name,
			Description: desc,
			Type:        listtype,
			SrcFormat:      format,
			Datasource:  datasource,
		}

		td.Logger.Printf("---> parsing source %s (datasource %s)", sourceid, datasource)

		var err error

		switch datasource {
		case "mqtt":
			if !td.TapirMqttEngineRunning {
				err := td.StartMqttEngine()
				if err != nil {
					TEMExiter("Error starting MQTT Engine: %v", err)
				}
			}
			td.Logger.Printf("*** MQTT sources are only managed via RefreshEngine.")
		case "file":
			err = td.ParseLocalFile(sourceid, &newsource)
		case "xfr":
			err = td.ParseRpzFeed(sourceid, &newsource)
		}
		if err != nil {
			log.Printf("Error parsing source %s (datasource %s): %v",
				sourceid, datasource, err)
		}
	}

	return nil
}

func (td *TemData) ParseLocalFile(sourceid string, s *tapir.WBGlist) error {
	td.Logger.Printf("ParseLocalFile: %s (%s)", sourceid, s.Type)
	var df dawg.Finder
	var err error

	s.Filename = viper.GetString(fmt.Sprintf("sources.%s.filename", sourceid))
	if s.Filename == "" {
		TEMExiter("ParseLocalFile: source %s of type file has undefined filename",
			sourceid)
	}

	switch s.SrcFormat {
	case "domains":
		names, err := tapir.ParseText(s.Filename)
		if err != nil {
		   if os.IsNotExist(err) {
		      TEMExiter("ParseLocalFile: source %s (type file: %s) does not exist",
		      				 sourceid, s.Filename)
	           }
		   TEMExiter("ParseLocalFile: error parsing file %s: %v", s.Filename, err)
		}

		s.Names = map[string]tapir.TapirName{}
		s.Format = "map"
		for _, name := range names {
		    s.Names[name] = tapir.TapirName{ Name: name }
		}

	case "dawg":
		if s.Type != "whitelist" {
			TEMExiter("Error: source %s (file %s): DAWG is only defined for whitelists.", sourceid, s.Filename)
		}
		td.Logger.Printf("ParseLocalFile: loading DAWG: %s", s.Filename)
		df, err = dawg.Load(s.Filename)
		if err != nil {
			TEMExiter("Error from dawg.Load(%s): %v", s.Filename, err)
		}
		td.Logger.Printf("ParseLocalFile: DAWG loaded")
		s.Dawgf = df

	default:
		TEMExiter("ParseLocalFile: SrcFormat \"%s\" is unknown.", s.SrcFormat)
	}

	switch s.Type {
	case "whitelist":
		td.Whitelists[s.Name] = s
	case "blacklist":
		td.Blacklists[s.Name] = s
	case "greylist":
		td.Greylists[s.Name] = s
	}

	return nil
}

func (td *TemData) ParseRpzFeed(sourceid string, s *tapir.WBGlist) error {
	zone := viper.GetString(fmt.Sprintf("sources.%s.zone", sourceid))
	if zone == "" {
		return fmt.Errorf("Unable to load RPZ source %s, upstream zone not specified.",
			sourceid)
	}

	upstream := viper.GetString(fmt.Sprintf("sources.%s.upstream", sourceid))
	if upstream == "" {
		return fmt.Errorf("Unable to load RPZ source %s, upstream address not specified.",
			sourceid)
	}

	s.Names = map[string]tapir.TapirName{}	// must initialize
	s.Format = "map"
	s.RpzZoneName = dns.Fqdn(zone)
	s.RpzUpstream = upstream
	td.Logger.Printf("---> SetupRPZFeed: about to transfer zone %s from %s", zone, upstream)
	td.RpzRefreshCh <- RpzRefresh{
		Name:        dns.Fqdn(zone),
		Upstream:    upstream,
		RRKeepFunc:  RpzKeepFunc,
		RRParseFunc: td.RpzParseFuncFactory(s),
		ZoneType:    3,
	}
	switch s.Type {
	case "whitelist":
		td.Whitelists[s.Name] = s
	case "blacklist":
		td.Blacklists[s.Name] = s
	case "greylist":
		td.Greylists[s.Name] = s
	}
	return nil
}

func RpzKeepFunc(rrtype uint16) bool {
	switch rrtype {
	case dns.TypeSOA, dns.TypeNS, dns.TypeCNAME:
		return true
	}
	return false
}

func (td *TemData) RpzParseFuncFactory(s *tapir.WBGlist) func(*dns.RR, *tapir.ZoneData) bool {
	return func(rr *dns.RR, zd *tapir.ZoneData) bool {
		var action string
		name := strings.TrimSuffix((*rr).Header().Name, zd.ZoneName)
		switch (*rr).Header().Rrtype {
		case dns.TypeSOA, dns.TypeNS:
			log.Printf("ParseFunc: zone %s: looking at %s", zd.ZoneName,
					       dns.TypeToString[(*rr).Header().Rrtype])
			return true
		case dns.TypeCNAME:
			switch (*rr).(*dns.CNAME).Target {
			case ".":
				action = "NXDOMAIN"
			case "*.":
				action = "NODATA"
			case "rpz-passthru.":
				action = "WHITELIST"
				if s.Type != "whitelist" {
					log.Printf("Name %s is whitelisted, but this is not a whitelist RPZ, adding to local", (*rr).Header().Name)
				}
			case "rpz-drop.":
				action = "DROP"
			default:
				action = fmt.Sprintf("UNKNOWN target: \"%s\"", (*rr).(*dns.CNAME).Target)
			}
			log.Printf("ParseFunc: zone %s: name %s action: %s", zd.ZoneName,
					       (*rr).Header().Name, action)
			switch s.Type {
			case "whitelist":
				if action == "WHITELIST" {
					zd.RpzData[name] = "x" // drop all other actions
					s.Names[name] = tapir.TapirName{ Name: name } // drop all other actions
				}
			case "blacklist":
				if action != "WHITELIST" {
					zd.RpzData[name] = "x" // drop all other actions
					s.Names[name] = tapir.TapirName{ Name: name } // drop all other actions
				} else {
					log.Printf("Warning: blacklist RPZ source %s has whitelisted name: %s",
							     s.RpzZoneName, name)
				}
			case "greylist":
				if action != "WHITELIST" {
					zd.RpzData[name] = action
					s.Names[name] = tapir.TapirName{ Name: name, Action: action }
				} else {
					log.Printf("Warning: greylist RPZ source %s has whitelisted name: %s",
							     s.RpzZoneName, name)
				}
			}
		}
		return true
	}
}
