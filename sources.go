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
        Lists		       map[string]map[string]*tapir.WBGlist
//	Blacklists             map[string]*tapir.WBGlist
//	Whitelists             map[string]*tapir.WBGlist
//	Greylists              map[string]*tapir.WBGlist
	RpzRefreshCh           chan RpzRefresh
	RpzCommandCh           chan RpzCmdData
	TapirMqttEngineRunning bool
	TapirMqttCmdCh         chan tapir.MqttEngineCmd
	TapirMqttSubCh         chan tapir.MqttPkg
	TapirMqttPubCh         chan tapir.MqttPkg // not used ATM
	Logger                 *log.Logger
	BlacklistedNames       map[string]bool
	GreylistedNames        map[string]*tapir.TapirName
	RpzZone		       *tapir.ZoneData
	RpzOutput              []dns.RR
	RpzZones	       map[string]*tapir.ZoneData
}

type WBGC map[string]*tapir.WBGlist

func NewTemData(conf *Config, lg *log.Logger) (*TemData, error) {
	td := TemData{
	        Lists:		map[string]map[string]*tapir.WBGlist{},
//	        Whitelists:	make(map[string]*tapir.WBGlist, 1000),
//	        Blacklists:	make(map[string]*tapir.WBGlist, 1000),
//	        Greylists:	make(map[string]*tapir.WBGlist, 1000),
		Logger:		lg,
		RpzRefreshCh:	make(chan RpzRefresh, 10),
		RpzCommandCh:	make(chan RpzCmdData, 10),
	}

	td.Lists["whitelist"] = make(map[string]*tapir.WBGlist, 1000)
	td.Lists["greylist"] = make(map[string]*tapir.WBGlist, 1000)
	td.Lists["blacklist"] = make(map[string]*tapir.WBGlist, 1000)

	td.RpzZones = map[string]*tapir.ZoneData{}

	err := td.BootstrapRpzOutput()
	if err != nil {
	   td.Logger.Printf("Error from BootstrapRpzOutput(): %v", err)
	}

	// Note: We can not parse data sources here, as RefreshEngine has not yet started.
	conf.TemData = &td
	return &td, nil
}

func (td *TemData) ParseSources() error {
	sources := viper.GetStringSlice("sources.active")
	log.Printf("Defined policy sources: %v", sources)

	td.Lists["whitelist"]["white_catchall"] = 
		&tapir.WBGlist{
			Name:        "white_catchall",
			Description: "Whitelist consisting of white names found in black- or greylist sources",
			Type:        "whitelist",
			SrcFormat:   "none",
			Format:	     "map",
			Datasource:  "Data misplaced in other sources",
			Names:	     map[string]tapir.TapirName{},
		}
	td.Lists["greylist"]["grey_catchall"] =
		&tapir.WBGlist{
			Name:        "grey_catchall",
			Description: "Greylist consisting of grey names found in whitelist sources",
			Type:        "greylist",
			SrcFormat:   "none",
			Format:      "map",
			Datasource:  "Data misplaced in other sources",
			Names:	     map[string]tapir.TapirName{},
		}

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
			Names:	     map[string]tapir.TapirName{},
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
			newsource.Format = "map" // for now
			// td.Greylists[newsource.Name] = &newsource
			td.Lists["greylist"][newsource.Name] = &newsource
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
		s.Format = "dawg"
		s.Dawgf = df

	default:
		TEMExiter("ParseLocalFile: SrcFormat \"%s\" is unknown.", s.SrcFormat)
	}

//	switch s.Type {
// 	case "whitelist":
// 		td.Whitelists[s.Name] = s
// 	case "blacklist":
// 		td.Blacklists[s.Name] = s
// 	case "greylist":
// 		td.Greylists[s.Name] = s
// 	}
	td.Lists[s.Type][s.Name] = s

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
		ZoneType:    tapir.RpzZone,
	}
// 	switch s.Type {
// 	case "whitelist":
// 		td.Whitelists[s.Name] = s
// 	case "blacklist":
// 		td.Blacklists[s.Name] = s
// 	case "greylist":
// 		td.Greylists[s.Name] = s
// 	}
	td.Lists[s.Type][s.Name] = s

	return nil
}

func RpzKeepFunc(rrtype uint16) bool {
	switch rrtype {
	case dns.TypeSOA, dns.TypeNS, dns.TypeCNAME:
		return true
	}
	return false
}

// Parse the CNAME (in the shape of a dns.RR) that is found in the RPZ and sort the data into the
// appropriate list in TemData. Note that there are two special cases:
// 1. If a "whitelist" RPZ source has a rule with an action other than "rpz-passthru." then that rule doesn't
//    really belong in a "whitelist" source. So we take that rule an put it in the grey_catchall bucket instead.
// 2. If a "{grey|black}list" RPZ source has a rule with an "rpz-passthru." (i.e. whitelist) action then that
//    rule doesn't really belong in a "{grey|black}list" source. So we take that rule an put it in the
//    white_catchall bucket instead.
//
func (td *TemData) RpzParseFuncFactory(s *tapir.WBGlist) func(*dns.RR, *tapir.ZoneData) bool {
	return func(rr *dns.RR, zd *tapir.ZoneData) bool {
		var action tapir.Action
		name := strings.TrimSuffix((*rr).Header().Name, zd.ZoneName)
		switch (*rr).Header().Rrtype {
		case dns.TypeSOA, dns.TypeNS:
		     if tapir.GlobalCF.Debug {
			td.Logger.Printf("ParseFunc: zone %s: looking at %s", zd.ZoneName,
					       dns.TypeToString[(*rr).Header().Rrtype])
		     }
			return true
		case dns.TypeCNAME:
			switch (*rr).(*dns.CNAME).Target {
			case ".":
//				action = "NXDOMAIN"
				action = tapir.NXDOMAIN
			case "*.":
//				action = "NODATA"
				action = tapir.NODATA
			case "rpz-drop.":
//				action = "DROP"
				action = tapir.DROP
			case "rpz-passthru.":
				action = tapir.WHITELIST
//				if s.Type != "whitelist" {
// 					td.Logger.Printf("Name %s is whitelisted, but this is not a whitelist RPZ, adding to local", (*rr).Header().Name)
// 					td.Lists["whitelist"]["white_catchall"].Names[name] = tapir.TapirName{ Name: name }
// 				} else {
// 					s.Names[name] = tapir.TapirName{ Name: name } // drop all other actions
// 				}
// 				return true
			default:
				td.Logger.Printf("UNKNOWN RPZ action: \"%s\"", (*rr).(*dns.CNAME).Target)
				action = tapir.UnknownAction
			}
			if tapir.GlobalCF.Debug {
			   td.Logger.Printf("ParseFunc: zone %s: name %s action: %s", zd.ZoneName,
					       name, action)
			}
			switch s.Type {
			case "whitelist":
				if action == tapir.WHITELIST {
					s.Names[name] = tapir.TapirName{ Name: name } // drop all other actions
				} else {
					td.Logger.Printf("Warning: whitelist RPZ source %s has blacklisted name: %s",
							     s.RpzZoneName, name)
					td.Lists["greylist"]["grey_catchall"].Names[name] =
								tapir.TapirName{ Name: 	 name,
										 Action: action,
								} // drop all other actions
				}
			case "blacklist":
				if action != tapir.WHITELIST {
					s.Names[name] = tapir.TapirName{ Name: name, Action: action }
				} else {
					td.Logger.Printf("Warning: blacklist RPZ source %s has whitelisted name: %s",
							     s.RpzZoneName, name)
					td.Lists["whitelist"]["white_catchall"].Names[name] = tapir.TapirName{ Name: name }
				}
			case "greylist":
				if action != tapir.WHITELIST {
					s.Names[name] = tapir.TapirName{ Name: name, Action: action }
				} else {
					td.Logger.Printf("Warning: greylist RPZ source %s has whitelisted name: %s",
							     s.RpzZoneName, name)
					td.Lists["whitelist"]["white_catchall"].Names[name] = tapir.TapirName{ Name: name }
				}
			}
		}
		return true
	}
}

// Generate the RPZ output based on the currently loaded sources.
// The output is a tapir.ZoneData, but with only the RRs (i.e. a []dns.RR) populated.
// Output should consist of:
// 1. Walk all blacklists:
//    a) remove any whitelisted names
//    b) rest goes straight into output
// 2. Walk all greylists:
//    a) collect complete grey data on each name
//    b) remove any whitelisted name
//    c) evalutate the grey data to make a decision on inclusion or not

// func (td *TemData) xxxGenerateRpzOutput() {
// 
//      var res = make(map[string]bool, 10000)
//      
//      for bname, blist := range td.Blacklists {
// 		switch blist.Format {
// 		case "dawg":
// 		     td.Logger.Printf("Cannot list DAWG lists. Ignoring blacklist %s.", bname)
// 		case "map":
// 		     for k, _ := range blist.Names {
// 		     	 td.Logger.Printf("Adding name %s from blacklist %s to tentative output.", k, bname)
// 			 if td.Whitelisted(k) {
// 			    td.Logger.Printf("Blacklisted name %s is also whitelisted. Dropped from output.", k)
// 			 } else {
// 			    td.Logger.Printf("Blacklisted name %s is not whitelisted. Added to output.", k)
// 			   res[k] = true
// 			 }
// 		     }
// 		}
// 	}
// 	td.BlacklistedNames = res
// 	td.Logger.Printf("Complete set of blacklisted names: %v", res)
// 	
// }