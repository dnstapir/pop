/*
 * Copyright (c) 2024 Johan Stenstam, joahn.stenstam@internetstiftelsen.se
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

type PopOutput struct {
	Active      bool
	Name        string
	Description string
	Type        string // listtype, usually "doubtlist"
	Format      string // i.e. rpz, etc
	Downstream  string
}

type PopOutputs struct {
	Outputs map[string]PopOutput
}

func (pd *PopData) ParseOutputs() error {
	pd.Logger.Printf("ParseOutputs: reading outputs from %s", tapir.PopOutputsCfgFile)
	cfgdata, err := os.ReadFile(tapir.PopOutputsCfgFile)
	if err != nil {
		log.Fatalf("Error from ReadFile(%s): %v", tapir.PopOutputsCfgFile, err)
	}

	var oconf = PopOutputs{
		Outputs: make(map[string]PopOutput),
	}

	// pd.Logger.Printf("ParseOutputs: config read: %s", cfgdata)
	err = yaml.Unmarshal(cfgdata, &oconf)
	if err != nil {
		log.Fatalf("Error from yaml.Unmarshal(OutputsConfig): %v", err)
	}

	pd.Logger.Printf("ParseOutputs: found %d outputs", len(oconf.Outputs))
	for name, v := range oconf.Outputs {
		pd.Logger.Printf("ParseOutputs: output %s: type %s, format %s, downstream %s",
			name, v.Type, v.Format, v.Downstream)
	}

	for name, output := range oconf.Outputs {
		if output.Active && strings.ToLower(output.Format) == "rpz" {
			pd.Logger.Printf("Output %s: Adding RPZ downstream %s to list of Notify receivers", name, output.Downstream)
			addr, port, err := net.SplitHostPort(output.Downstream)
			if err != nil {
				pd.Logger.Printf("Invalid downstream address %s: %v", output.Downstream, err)
				continue
			}
			if net.ParseIP(addr) == nil {
				pd.Logger.Printf("Invalid IP address %s", addr)
				continue
			}
			portInt, err := strconv.Atoi(port)
			if err != nil {
				pd.Logger.Printf("Invalid port %s: %v", port, err)
				continue
			}
			pd.Downstreams[addr] = RpzDownstream{Address: addr, Port: portInt}
		}
	}
	// Read the current value of pd.Downstreams.Serial from a text file
	serialFile := viper.GetString("services.rpz.serialcache")

	if serialFile != "" {
		serialFile = filepath.Clean(serialFile)
		serialData, err := os.ReadFile(serialFile)
		if err != nil {
			pd.Logger.Printf("Error reading serial from file %s: %v", serialFile, err)
			pd.Rpz.CurrentSerial = 1
		} else {
			var serialYaml struct {
				CurrentSerial uint32 `yaml:"current_serial"`
			}
			err = yaml.Unmarshal(serialData, &serialYaml)
			if err != nil {
				pd.Logger.Printf("Error unmarshalling YAML serial data: %v", err)
				pd.Rpz.CurrentSerial = 1
			} else {
				pd.Rpz.CurrentSerial = serialYaml.CurrentSerial
				pd.Logger.Printf("Loaded serial %d from file %s", pd.Rpz.CurrentSerial, serialFile)
			}
		}
	} else {
		pd.Logger.Printf("No serial cache file specified, starting serial at 1")
		pd.Rpz.CurrentSerial = 1
	}
	// pd.Rpz.CurrentSerial = pd.Downstreams.Serial
	return nil
}

// Note: we onlygethere when we know that this name is only doubtlisted
// so no need tocheckfor allow- or denylisting
func (pd *PopData) ComputeRpzDoubtlistAction(name string) tapir.Action {

	var doubtHits = map[string]*tapir.TapirName{}
	for listname, list := range pd.Lists["doubtlist"] {
		switch list.Format {
		case "map":
			if v, exists := list.Names[name]; exists {
				// pd.Logger.Printf("ComputeRpzDoubtlistAction: found %s in doubtlist %s (%d names)",
				// 	name, listname, len(list.Names))
				doubtHits[listname] = &v
			}
			//		case "trie":
			//			if list.Trie.Search(name) != nil {
			//				doubtHits = append(doubtHits, v)
			//			}
		default:
			POPExiter("Unknown doubtlist format %s", list.Format)
		}
	}
	if len(doubtHits) >= pd.Policy.Doubtlist.NumSources {
		pd.Policy.Logger.Printf("ComputeRpzDoubtlistAction: name %s is in %d or more sources, action is %s",
			name, pd.Policy.Doubtlist.NumSources, tapir.ActionToString[pd.Policy.Doubtlist.NumSourcesAction])
		return pd.Policy.Doubtlist.NumSourcesAction
	}
	pd.Policy.Logger.Printf("ComputeRpzDoubtlistAction: name %s is in %d sources, not enough for action", name, len(doubtHits))

	if _, exists := doubtHits["dns-tapir"]; exists {
		numtapirtags := doubtHits["dns-tapir"].TagMask.NumTags()
		if numtapirtags >= pd.Policy.Doubtlist.NumTapirTags {
			pd.Policy.Logger.Printf("ComputeRpzDoubtlistAction: name %s has more than %d tapir tags, action is %s",
				name, pd.Policy.Doubtlist.NumTapirTags, tapir.ActionToString[pd.Policy.Doubtlist.NumTapirTagsAction])
			return pd.Policy.Doubtlist.NumTapirTagsAction
		}
		pd.Policy.Logger.Printf("ComputeRpzDoubtlistAction: name %s has %d tapir tags, not enough for action", name, numtapirtags)
	}
	pd.Policy.Logger.Printf("ComputeRpzDoubtlistAction: name %s is present in %d doubtlists, but does not trigger any action",
		name, len(doubtHits))
	return pd.Policy.AllowlistAction
}

// Decision to block a doubtlisted name:
// 1. More than N tags present
// 2. Name is present in more than M sources
// 3. Name

func ApplyDoubtPolicy(name string, v *tapir.TapirName) string {
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

func (pd *PopData) ComputeRpzAction(name string) tapir.Action {
	if pd.Allowlisted(name) {
		if pd.Debug {
			pd.Policy.Logger.Printf("ComputeRpzAction: name %s is doubtlisted, action is %s", name, tapir.ActionToString[pd.Policy.AllowlistAction])
		}
		return pd.Policy.AllowlistAction
	} else if pd.Denylisted(name) {
		if pd.Debug {
			pd.Policy.Logger.Printf("ComputeRpzAction: name %s is denylisted, action is %s", name, tapir.ActionToString[pd.Policy.DenylistAction])
		}
		return pd.Policy.DenylistAction
	} else if pd.Doubtlisted(name) {
		if pd.Debug {
			pd.Policy.Logger.Printf("ComputeRpzAction: name %s is doubtlisted, needs further evaluation to determine action", name)
		}
		return pd.ComputeRpzDoubtlistAction(name) // This is not complete, only a placeholder for now.
	}
	return tapir.ALLOWLIST
}
