/*
 * Copyright (c) DNS TAPIR
 */

package main

import (
	"fmt"
	"log"

	"github.com/dnstapir/tapir"
	"github.com/spf13/viper"
)

func (td *TemData) StartMqttEngine() error {
	if td.TapirMqttEngineRunning {
		return nil

	}

	clientid := viper.GetString("mqtt.clientid")
	if clientid == "" {
		TEMExiter("Error starting MQTT Engine: clientid not specified in config")
	}
	meng, err := tapir.NewMqttEngine(clientid, tapir.TapirSub) // sub, but no pub
	if err != nil {
		TEMExiter("Error from NewMqttEngine: %v\n", err)
	}

	cmnder, _, inbox, err := meng.StartEngine()
	if err != nil {
		log.Fatalf("Error from StartEngine(): %v", err)
	}
	td.TapirMqttCmdCh = cmnder
	td.TapirMqttSubCh = inbox
	td.TapirMqttEngineRunning = true

	meng.SetupInterruptHandler()
	return nil
}

// Evaluating an update consists of two steps:
// 1. Iterate through the update, adding and/or removing the data in the update to the correct list(s).
//
// 2. Iterate through the update a second time:
//    - fetch the current output for each name
//    - recompute the output for that name, given new data
//    - if different, add the diff (DEL+ADD) to a growing "IXFR" describing the consequences of the update.
//

func (td *TemData) ProcessTapirUpdate(tpkg tapir.MqttPkg) (bool, error) {
	if td.Debug {
		td.Logger.Printf("ProcessTapirUpdate: update of MQTT source %s contains %d adds and %d removes",
			tpkg.Data.SrcName, len(tpkg.Data.Added), len(tpkg.Data.Removed))
		tapir.PrintTapirMqttPkg(tpkg, td.Logger)
	}

	var wbgl *tapir.WBGlist
	var exists bool

	td.Logger.Printf("ProcessTapirUpdate: looking up list [%s][%s]", tpkg.Data.ListType, tpkg.Data.SrcName)

	switch tpkg.Data.ListType {
	case "whitelist", "greylist", "blacklist":
		wbgl, exists = td.Lists[tpkg.Data.ListType][tpkg.Data.SrcName]
	default:
		td.Logger.Printf("TapirUpdate for unknown listtype from source \"%s\" rejected.", tpkg.Data.SrcName)
		return false, fmt.Errorf("MQTT ListType %s is unknown, update rejected", tpkg.Data.ListType)
	}

	if !exists {
		td.Logger.Printf("TapirUpdate for unknown source \"%s\" rejected.", tpkg.Data.SrcName)
		return false, fmt.Errorf("MQTT Source %s is unknown, update rejected", tpkg.Data.SrcName)
	}

	for _, name := range tpkg.Data.Added {
		tmp := tapir.TapirName{
			Name:      name.Name,
			TimeAdded: name.TimeAdded,
			TTL:       name.TTL,
			TagMask:   name.TagMask,
		}
		wbgl.Names[name.Name] = &tmp

		td.Logger.Printf("ProcessTapirUpdate: adding name %s to %s (TimeAdded: %s ttl: %v)",
			name.Name, wbgl.Name, name.TimeAdded.Format(tapir.TimeLayout), name.TTL)

		// Time that the name will be removed from the list
		reptime := name.TimeAdded.Add(name.TTL).Truncate(td.ReaperInterval)

		// Ensure that there are no prior removal events for this name
		for reaperTime, namesMap := range wbgl.ReaperData {
			if reaperTime.Before(reptime) {
				if _, exists := namesMap[name.Name]; exists {
					delete(namesMap, name.Name)
					if len(namesMap) == 0 {
						delete(wbgl.ReaperData, reaperTime)
					}
				}
			}
		}

		// Add the name to the removal list for the time it will be removed
		if wbgl.ReaperData[reptime] == nil {
			wbgl.ReaperData[reptime] = make(map[string]*tapir.TapirName)
		}
		wbgl.ReaperData[reptime][name.Name] = &tmp
	}

	td.Logger.Printf("ProcessTapirUpdate: current state of %s %s ReaperData:",
		tpkg.Data.ListType, wbgl.Name)
	for t, v := range wbgl.ReaperData {
		td.Logger.Printf("== At time %s the following names will be removed from the dns-tapir list:", t.Format(tapir.TimeLayout))
		for _, item := range v {
			td.Logger.Printf("  %s", item.Name)
		}
	}

	for _, name := range tpkg.Data.Removed {
		delete(wbgl.Names, name.Name)
	}

	ixfr, err := td.GenerateRpzIxfr(&tpkg.Data)
	if err != nil {
		return false, err
	}
	err = td.ProcessIxfrIntoAxfr(ixfr)
	return true, err
}

func (td *TemData) ProcessIxfrIntoAxfr(ixfr RpzIxfr) error {
	for _, tn := range ixfr.Removed {
		delete(td.Rpz.Axfr.Data, tn.Name)
		if td.Debug {
			td.Logger.Printf("PIIA: Deleting domain %s", tn.Name)
		}
	}
	for _, tn := range ixfr.Added {
		if _, exist := td.Rpz.Axfr.Data[tn.Name]; exist {
			// XXX: this should not happen.
			td.Logger.Printf("Error: ProcessIxfrIntoAxfr: domain %s already exists. This should not happen.",
				tn.Name)
		} else {
			td.Rpz.Axfr.Data[tn.Name] = tn
			if td.Debug {
				td.Logger.Printf("PIIA: Adding domain %s", tn.Name)
			}
		}
	}
	return nil
}
