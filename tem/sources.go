/*
 * Johan Stenstam, johani@johani.org
 */
package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/dnstapir/tapir-em/tapir"
	"github.com/miekg/dns"
	"github.com/smhanov/dawg"
	"github.com/spf13/viper"
)

type TemData struct {
	Blacklists             []*WBGlist
	Whitelists             []*WBGlist
	Greylists              []*WBGlist
	RpzRefreshCh           chan RpzRefresh
	RpzCommandCh           chan RpzCmdData
	TapirMqttEngineRunning bool
	TapirMqttCmdCh         chan tapir.MqttEngineCmd
	TapirMqttSubCh         chan tapir.MqttPkg
	TapirMqttPubCh         chan tapir.MqttPkg // not used ATM
	Logger                 *log.Logger
	Output                 *tapir.ZoneData
}

type WBGlist struct {
	Name        string
	Description string
	Type        string // whitelist | blacklist | greylist
	Mutable     bool   // true = is possible to update. Only local text file sources are mutable
	Format      string // dawg | rpz | tapir-mqtt-v1 | ...
	Datasource  string // file | xfr | mqtt | https | api | ...
	Filename    string
	Dawgf       dawg.Finder

	// greylist sources needs more complex stuff here:
	GreyNames   map[string]GreyName
	RpzZoneName string
	RpzUpstream string
	RpzSerial   int
}

type GreyName struct {
	Format string          // "tapir-feed-v1" | ...
	Tags   map[string]bool // XXX: extremely wasteful, a bitfield would be better,
	//      but don't know how many tags there can be
}

func (td *TemData) Whitelisted(name string) bool {
	for _, list := range td.Whitelists {
		td.Logger.Printf("Whitelisted: checking %s in whitelist %s", name, list.Name)
		if list.Dawgf.IndexOf(name) != -1 {
			return true
		}
	}
	return false
}

func (td *TemData) Blacklisted(name string) bool {
	for _, list := range td.Blacklists {
		td.Logger.Printf("Blacklisted: checking %s in blacklist %s", name, list.Name)
		if list.Dawgf.IndexOf(name) != -1 {
			return true
		}
	}
	return false
}

func (td *TemData) GreylistingReport(name string) (bool, string) {
	var report string
	if len(td.Greylists) == 0 {
		return false, fmt.Sprintf("Domain name \"%s\" is not greylisted (there are no active greylists).\n", name)
	}

	for _, list := range td.Greylists {
		td.Logger.Printf("Greylisted: checking %s in greylist %s", name, list.Name)
		report += fmt.Sprintf("Domain name \"%s\" could be present in greylist %s\n", name, list.Name)
	}
	return false, report

}

func NewTemData(conf *Config, lg *log.Logger) (*TemData, error) {
	td := TemData{
		Logger:       lg,
		RpzRefreshCh: make(chan RpzRefresh, 10),
		RpzCommandCh: make(chan RpzCmdData, 10),
	}
	//     err := td.ParseSources()
	//     if err != nil {
	//     	return nil, fmt.Errorf("Error parsing TEM sources: %v", err)
	//     }
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

		newsource := WBGlist{
			Name:        name,
			Description: desc,
			Type:        listtype,
			Format:      format,
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

func (td *TemData) ParseLocalFile(sourceid string, s *WBGlist) error {
	td.Logger.Printf("ParseLocalFile: %s (%s)", sourceid, s.Type)
	var df dawg.Finder
	var err error

	s.Filename = viper.GetString(fmt.Sprintf("sources.%s.filename", sourceid))
	if s.Filename == "" {
		TEMExiter("ParseLocalFile: source %s of type file has undefined filename",
			sourceid)
	}

	switch s.Format {
	case "domains":
		td.Logger.Printf("ParseLocalFile: parsing text file of domain names (NYI)")
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
		TEMExiter("ParseLocalFile: Format \"%s\" is unknown.", s.Format)
	}

	switch s.Type {
	case "whitelist":
		td.Whitelists = append(td.Whitelists, s)
	case "blacklist":
		td.Blacklists = append(td.Blacklists, s)
	case "greylist":
		td.Greylists = append(td.Greylists, s)
	}

	return nil
}

func (td *TemData) ParseLocalBlacklist(sourceid string, s *WBGlist) error {
	td.Logger.Printf("ParseLocalBlacklist: %s", sourceid)
	var df dawg.Finder
	var err error

	switch s.Format {
	case "domains":
		td.Logger.Printf("ParseLocalBlackList: parsing text file of domain names (NYI)")
	case "dawg":
		td.Logger.Printf("ParseLocalBlacklist: loading DAWG: %s", s.Filename)
		df, err = dawg.Load(s.Filename)
		if err != nil {
			TEMExiter("Error from dawg.Load(%s): %v", s.Filename, err)
		}
		td.Logger.Printf("ParseLocalBlacklist: DAWG loaded")
		s.Dawgf = df
		td.Blacklists = append(td.Blacklists, s)

	default:
		TEMExiter("ParseLocalBlacklist: Format \"%s\" is unknown.", s.Format)
	}
	return nil
}

func (td *TemData) ParseGreylist(sourceid string, s *WBGlist) error {
	td.Logger.Printf("ParseGreylist: %s", sourceid)
	switch s.Format {

	default:
		TEMExiter("ParseLocalBlacklist: Format \"%s\" is unknown.", s.Format)
	}
	return nil
}

func (td *TemData) ParseRpzFeed(sourceid string, s *WBGlist) error {
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
		td.Whitelists = append(td.Whitelists, s)
	case "blacklist":
		td.Blacklists = append(td.Blacklists, s)
	case "greylist":
		td.Greylists = append(td.Greylists, s)
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

func (td *TemData) RpzParseFuncFactory(s *WBGlist) func(*dns.RR, *tapir.ZoneData) bool {
	return func(rr *dns.RR, zd *tapir.ZoneData) bool {
		var action string
		name := strings.TrimSuffix((*rr).Header().Name, zd.ZoneName)
		switch (*rr).Header().Rrtype {
		case dns.TypeSOA, dns.TypeNS:
			log.Printf("ParseFunc: zone %s: looking at %s", zd.ZoneName, dns.TypeToString[(*rr).Header().Rrtype])
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
			log.Printf("ParseFunc: zone %s: name %s action: %s", zd.ZoneName, (*rr).Header().Name, action)
			switch s.Type {
			case "whitelist":
				if action == "WHITELIST" {
					zd.RpzData[name] = "x" // drop all other actions
				}
			case "blacklist":
				if action != "WHITELIST" {
					zd.RpzData[name] = "x" // drop all other actions
				} else {
					log.Printf("Warning: blacklist RPZ source %s has whitelisted name: %s", s.RpzZoneName, name)
				}
			case "greylist":
				if action != "WHITELIST" {
					zd.RpzData[name] = action
				} else {
					log.Printf("Warning: greylist RPZ source %s has whitelisted name: %s", s.RpzZoneName, name)
				}
			}
		}
		return true
	}
}
