/*
 * Copyright (c) DNS TAPIR
 */

package main

import (
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/dnstapir/tapir"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

type TemOutput struct {
	Active      bool
	Name        string
	Description string
	Type        string // listtype, usually "greylist"
	Format      string // i.e. rpz, etc
	Downstream  string
}

type TemOutputs struct {
	Outputs map[string]TemOutput
}

func (td *TemData) ParseOutputs() error {
	td.Logger.Printf("ParseOutputs: reading outputs from %s", tapir.TemOutputsCfgFile)
	cfgdata, err := os.ReadFile(tapir.TemOutputsCfgFile)
	if err != nil {
		log.Fatalf("Error from ReadFile(%s): %v", tapir.TemOutputsCfgFile, err)
	}

	var oconf = TemOutputs{
		Outputs: make(map[string]TemOutput),
	}

	// td.Logger.Printf("ParseOutputs: config read: %s", cfgdata)
	err = yaml.Unmarshal(cfgdata, &oconf)
	if err != nil {
		log.Fatalf("Error from yaml.Unmarshal(OutputsConfig): %v", err)
	}

	td.Logger.Printf("ParseOutputs: found %d outputs", len(oconf.Outputs))
	for name, v := range oconf.Outputs {
		td.Logger.Printf("ParseOutputs: output %s: type %s, format %s, downstream %s",
			name, v.Type, v.Format, v.Downstream)
	}

	for name, output := range oconf.Outputs {
		if output.Active && strings.ToLower(output.Format) == "rpz" {
			td.Logger.Printf("Output %s: Adding RPZ downstream %s to list of Notify receivers", name, output.Downstream)
			addr, port, err := net.SplitHostPort(output.Downstream)
			if err != nil {
				td.Logger.Printf("Invalid downstream address %s: %v", output.Downstream, err)
				continue
			}
			if net.ParseIP(addr) == nil {
				td.Logger.Printf("Invalid IP address %s", addr)
				continue
			}
			portInt, err := strconv.Atoi(port)
			if err != nil {
				td.Logger.Printf("Invalid port %s: %v", port, err)
				continue
			}
			td.Downstreams[addr] = RpzDownstream{Address: addr, Port: portInt}
		}
	}
	// Read the current value of td.Downstreams.Serial from a text file
	serialFile := viper.GetString("output.rpz.serialcache")

	if serialFile != "" {
		serialFile = filepath.Clean(serialFile)
		serialData, err := os.ReadFile(serialFile)
		if err != nil {
			td.Logger.Printf("Error reading serial from file %s: %v", serialFile, err)
			td.Rpz.CurrentSerial = 1
		} else {
			var serialYaml struct {
				CurrentSerial uint32 `yaml:"current_serial"`
			}
			err = yaml.Unmarshal(serialData, &serialYaml)
			if err != nil {
				td.Logger.Printf("Error unmarshalling YAML serial data: %v", err)
				td.Rpz.CurrentSerial = 1
			} else {
				td.Rpz.CurrentSerial = serialYaml.CurrentSerial
				td.Logger.Printf("Loaded serial %d from file %s", td.Rpz.CurrentSerial, serialFile)
			}
		}
	} else {
		td.Logger.Printf("No serial cache file specified, starting serial at 1")
		td.Rpz.CurrentSerial = 1
	}
	// td.Rpz.CurrentSerial = td.Downstreams.Serial
	return nil
}

// Note: we onlygethere when we know that this name is only greylisted
// so no need tocheckfor white- or blacklisting
func (td *TemData) ComputeRpzGreylistAction(name string) tapir.Action {

	var greyHits = map[string]*tapir.TapirName{}
	for listname, list := range td.Lists["greylist"] {
		switch list.Format {
		case "map":
			if v, exists := list.Names[name]; exists {
				// td.Logger.Printf("ComputeRpzGreylistAction: found %s in greylist %s (%d names)",
				// 	name, listname, len(list.Names))
				greyHits[listname] = &v
			}
			//		case "trie":
			//			if list.Trie.Search(name) != nil {
			//				greyHits = append(greyHits, v)
			//			}
		default:
			TEMExiter("Unknown greylist format %s", list.Format)
		}
	}
	if len(greyHits) >= td.Policy.Greylist.NumSources {
		td.Policy.Logger.Printf("ComputeRpzGreylistAction: name %s is in %d or more sources, action is %s",
			name, td.Policy.Greylist.NumSources, tapir.ActionToString[td.Policy.Greylist.NumSourcesAction])
		return td.Policy.Greylist.NumSourcesAction
	}
	td.Policy.Logger.Printf("ComputeRpzGreylistAction: name %s is in %d sources, not enough for action", name, len(greyHits))

	if _, exists := greyHits["dns-tapir"]; exists {
		numtapirtags := greyHits["dns-tapir"].TagMask.NumTags()
		if numtapirtags >= td.Policy.Greylist.NumTapirTags {
			td.Policy.Logger.Printf("ComputeRpzGreylistAction: name %s has more than %d tapir tags, action is %s",
				name, td.Policy.Greylist.NumTapirTags, tapir.ActionToString[td.Policy.Greylist.NumTapirTagsAction])
			return td.Policy.Greylist.NumTapirTagsAction
		}
		td.Policy.Logger.Printf("ComputeRpzGreylistAction: name %s has %d tapir tags, not enough for action", name, numtapirtags)
	}
	td.Policy.Logger.Printf("ComputeRpzGreylistAction: name %s is present in %d greylists, but does not trigger any action",
		name, len(greyHits))
	return td.Policy.WhitelistAction
}

// Decision to block a greylisted name:
// 1. More than N tags present
// 2. Name is present in more than M sources
// 3. Name

func ApplyGreyPolicy(name string, v *tapir.TapirName) string {
	var rpzaction string
	if v.HasAction(tapir.NXDOMAIN) {
		rpzaction = "."
	} else if v.HasAction(tapir.NODATA) {
		rpzaction = "*."
	} else if v.HasAction(tapir.DROP) {
		rpzaction = "rpz-drop."
	} else if v.TagMask != 0 {
		log.Printf("there are tags")
		rpzaction = "rpz-drop."
	}

	return rpzaction
}

func (td *TemData) ComputeRpzAction(name string) tapir.Action {
	if td.Whitelisted(name) {
		if td.Debug {
			td.Policy.Logger.Printf("ComputeRpzAction: name %s is whitelisted, action is %s", name, tapir.ActionToString[td.Policy.WhitelistAction])
		}
		return td.Policy.WhitelistAction
	} else if td.Blacklisted(name) {
		if td.Debug {
			td.Policy.Logger.Printf("ComputeRpzAction: name %s is blacklisted, action is %s", name, tapir.ActionToString[td.Policy.BlacklistAction])
		}
		return td.Policy.BlacklistAction
	} else if td.Greylisted(name) {
		if td.Debug {
			td.Policy.Logger.Printf("ComputeRpzAction: name %s is greylisted, needs further evaluation to determine action", name)
		}
		return td.ComputeRpzGreylistAction(name) // This is not complete, only a placeholder for now.
	}
	return tapir.WHITELIST
}
