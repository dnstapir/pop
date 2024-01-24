/*
 * Johan Stenstam, johani@johani.org
 */
package main

import (
        "fmt"
	"log"
	"github.com/spf13/viper"
	"github.com/smhanov/dawg"

//	"github.com/dnstapir/tapir-em/tapir"
)

type TemData struct {
     GlobalWL	    dawg.Finder
     LocalWL 	    dawg.Finder
     Logger	    *log.Logger
}

func (td *TemData) Whitelisted(name string) bool {
     if td.GlobalWL != nil && td.GlobalWL.IndexOf(name) != -1 {
     	return true
     }
     if td.LocalWL != nil && td.LocalWL.IndexOf(name) != -1 {
     	return true
     }
     return false
}

func NewTemData(lg *log.Logger) (*TemData, error) {
     td := TemData{
		Logger:	lg,
	   }
     err := td.ParseSources()
     if err != nil {
     	return nil, fmt.Errorf("Error parsing TEM sources: %v", err)
     }
     return &td, nil
}

func (td *TemData) ParseSources() error {
     sources := viper.GetStringSlice("sources.active")
     log.Printf("Defined policy sources: %v", sources)

     for _, source := range sources {
         stype := viper.GetString(fmt.Sprintf("sources.%s.type", source))
	 if stype == "" {
	    TEMExiter("ParseSources: source %d has no type", source)
	 }
         scontent := viper.GetString(fmt.Sprintf("sources.%s.content", source))
	 if scontent == "" {
	    TEMExiter("ParseSources: source %d has undefined content", source)
	 }

	 log.Printf("Found source: %s (type %s, content %s)", source, stype, scontent)
	 switch stype {
	 case "mqtt":
	      log.Printf("*** Do not yet know how to deal with MQTT sources. Ignoring.")
	 case "file":
	      filename := viper.GetString(fmt.Sprintf("sources.%s.filename", source))
	      if filename == "" {
	      	 TEMExiter("ParseSources: source %s of type file has undefined filename", source)
	      }

	      switch scontent {
	      case "intelligence":
	      	   err := ParseLocalFeed(source, filename)
	      	   if err != nil {
	      	      log.Printf("Error from ParseLocalFeed: %v", err)
	      	   }
	      case "whitelist":
	      	   err := td.ParseLocalWhiteList(source, filename)
	      	   if err != nil {
	      	      log.Printf("Error from ParseLocalWhiteList: %v", err)
	      	   }
	      }
	 }
	 
     }

     return nil
}

func ParseLocalFeed (source, filename string) error {

     return nil
}

func (td *TemData) ParseLocalWhiteList (source, filename string) error {
     format := viper.GetString(fmt.Sprintf("sources.%s.format", source))
     switch format {
     case "domains":
     	  log.Printf("ParseLocalWhiteList: parsing text file of domain names (NYI)")
     case "dawg":
     	  log.Printf("ParseLocalWhiteList: loading DAWG: %s", filename)
	  df, err := dawg.Load(filename)
	  if err != nil {
	     TEMExiter("Error from dawg.Load(%s): %v", filename, err)
	  }
     	  log.Printf("ParseLocalWhiteList: DAWG loaded")
	  td.LocalWL = df
	  
     default:
	TEMExiter("ParseLocalWhiteList: Format \"%s\" is unknown.", format)
     }
     return nil
}