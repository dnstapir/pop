/*
 * Johan Stenstam, johani@johani.org
 */
package main

import (
        "fmt"
	"log"
	"github.com/spf13/viper"
	"github.com/smhanov/dawg"
	"github.com/miekg/dns"

	"github.com/dnstapir/tapir-em/tapir"
)

type TemData struct {
     Blacklists	    []WBGlist
     Whitelists	    []WBGlist
     Greylists	    []WBGlist
     RpzRefreshCh   chan RpzRefresher
     RpzCommandCh   chan RpzCmdData
     TapirMqttEngineRunning	bool
     TapirMqttCmdCh chan tapir.MqttEngineCmd
     TapirMqttSubCh chan tapir.MqttPkg
     TapirMqttPubCh chan tapir.MqttPkg		// not used ATM
     Logger	    *log.Logger
     Output	    *tapir.ZoneData
}

type WBGlist struct {
     Name		string
     Description	string
     Type		string	// whitelist | blacklist | greylist
     Mutable		bool	// true = is possible to update. Only local text file sources are mutable
     Format		string	// 
     Datasource		string	// file | mqtt | https | api | ...
     Filename		string
     Dawgf   		dawg.Finder

     // greylist sources needs more complex stuff here:
     GreyNames	 	map[string]GreyName
     Zone		string
     Upstream		string
}

type GreyName struct {
     Format   string // "tapir-feed-v1" | ...
     Tags     map[string]bool		// XXX: extremely wasteful, a bitfield would be better,
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
		Logger:	lg,
		RpzRefreshCh:	make(chan RpzRefresher, 10),
		RpzCommandCh:	make(chan RpzCmdData, 10),
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
			Name:		name,
			Description:	desc,
			Type:		listtype,
			Format:		format,
			Datasource:	datasource,
		      }

 	 td.Logger.Printf("---> parsing source %s (datasource %s)", sourceid, datasource)
	 switch datasource {
	 case "mqtt":
	      if !td.TapirMqttEngineRunning {
	      	 err := td.StartMqttEngine()
		 if err != nil {
		    TEMExiter("Error starting MQTT Engine: %v", err)
		 }
	      }
	      td.Logger.Printf("*** Do not yet know how to deal with MQTT sources. Ignoring.")
	 case "file":
	      filename := viper.GetString(fmt.Sprintf("sources.%s.filename", sourceid))
	      if filename == "" {
	      	 TEMExiter("ParseSources: source %s of type file has undefined filename", sourceid)
	      }

	      newsource.Filename = filename

	      switch listtype {
	      case "blacklist":
	      	   err := td.ParseLocalBlacklist(sourceid, &newsource)
	      	   if err != nil {
	      	      td.Logger.Printf("Error from ParseLocalBlacklist: %v", err)
	      	   }
	      case "whitelist":
	      	   err := td.ParseLocalWhitelist(sourceid, &newsource)
	      	   if err != nil {
	      	      td.Logger.Printf("Error from ParseLocalWhitelist: %v", err)
	      	   }
	      case "greylist":
	      	   err := td.ParseGreylist(sourceid, &newsource)
	      	   if err != nil {
	      	      td.Logger.Printf("Error from ParseGreylist: %v", err)
	      	   }
	      }
	 case "axfr":
	      switch listtype {
	      case "blacklist":
	      	      td.Logger.Printf("Error: RPZ is not yet a supported source for blacklists.")

	      case "whitelist":
	      	      td.Logger.Printf("Error: RPZ is not yet a supported source for whitelists.")


	      case "greylist":
	      	   err := td.ParseGreylist(sourceid, &newsource)
	      	   if err != nil {
	      	      td.Logger.Printf("Error from ParseGreylist: %v", err)
	      	   }
	      }
	 }
	 
     }

     return nil
}

func ParseLocalFeed (source, filename string) error {

     return nil
}

func (td *TemData) ParseLocalWhitelist (sourceid string, s *WBGlist) error {
     td.Logger.Printf("ParseLocalWhitelist: %s", sourceid)
     var df dawg.Finder
     var err error
     
     switch s.Format {
     case "domains":
     	  td.Logger.Printf("ParseLocalWhitelist: parsing text file of domain names (NYI)")
     case "dawg":
     	  td.Logger.Printf("ParseLocalWhitelist: loading DAWG: %s", s.Filename)
	  df, err = dawg.Load(s.Filename)
	  if err != nil {
	     TEMExiter("Error from dawg.Load(%s): %v", s.Filename, err)
	  }
     	  td.Logger.Printf("ParseLocalWhitelist: DAWG loaded")
	  s.Dawgf = df
	  td.Whitelists = append(td.Whitelists, *s)
     case "rpz":
     	  _, err := td.SetupRpzFeed(sourceid, s)
	  if err != nil {
	     return err
	  }
	  td.Whitelists = append(td.Whitelists, *s)
	  
     default:
	TEMExiter("ParseLocalWhitelist: Format \"%s\" is unknown.", s.Format)
     }
     return nil
}

func (td *TemData) ParseLocalBlacklist (sourceid string, s *WBGlist) error {
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
	  td.Blacklists = append(td.Blacklists, *s)
     case "rpz":
     	  _, err := td.SetupRpzFeed(sourceid, s)
	  if err != nil {
	     return err
	  }
	  td.Blacklists = append(td.Blacklists, *s)
	  
     default:
	TEMExiter("ParseLocalBlacklist: Format \"%s\" is unknown.", s.Format)
     }
     return nil
}

func (td *TemData) ParseGreylist (sourceid string, s *WBGlist) error {
     td.Logger.Printf("ParseGreylist: %s", sourceid)
     switch s.Format {
     case "rpz":
     	  _, err := td.SetupRpzFeed(sourceid, s)
	  if err != nil {
	     return err
	  }
	  td.Greylists = append(td.Greylists, *s)
	  
     default:
	TEMExiter("ParseLocalBlacklist: Format \"%s\" is unknown.", s.Format)
     }
     return nil
}

func (td *TemData) SetupRpzFeed(sourceid string, s *WBGlist) (string, error) {
     	  zone := viper.GetString(fmt.Sprintf("sources.%s.zone", sourceid))
	  if zone == "" {
	     return "", fmt.Errorf("Unable to load RPZ source %s, upstream zone not specified.", sourceid)
	  }

     	  upstream := viper.GetString(fmt.Sprintf("sources.%s.upstream", sourceid))
	  if upstream == "" {
	     return "", fmt.Errorf("Unable to load RPZ source %s, upstream address not specified.",
	     	    sourceid)
	  }

	  s.Zone = dns.Fqdn(zone)
	  s.Upstream = upstream
	  td.Logger.Printf("---> SetupRPZFeed: about to transfer zone %s from %s", zone, upstream)
	  td.RpzRefreshCh <- RpzRefresher{
				Name:		dns.Fqdn(zone),
				Upstream:	upstream,
				KeepFunc:	RpzKeepFunc,
				ZoneType:	3,
	  		      }
	return "FOO", nil
}

func RpzKeepFunc(rrtype uint16) bool {
	switch rrtype {
	case dns.TypeSOA, dns.TypeNS, dns.TypeCNAME:
		return true
	}
	return false
}