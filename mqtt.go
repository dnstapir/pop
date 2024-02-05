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
	td.Logger.Printf("ProcessTapirUpdate: update of MQTT source %s contains %d adds and %d removes",
		tpkg.Data.SrcName, len(tpkg.Data.Added), len(tpkg.Data.Removed))

	var wbgl *tapir.WBGlist
	var exists bool

	switch tpkg.Data.ListType {
	case "whitelist", "greylist", "blacklist":
		wbgl, exists = td.Lists[tpkg.Data.ListType][tpkg.Data.SrcName]
	default:
 	   td.Logger.Printf("TapirUpdate for unknown source \"%s\" rejected.", tpkg.Data.SrcName)
 	   return false, fmt.Errorf("MQTT ListType %s is unknown, update rejected", tpkg.Data.ListType)
	}

// 	switch tpkg.Data.ListType {
// 	case "greylist":
// 	     wbgl, exists = td.Greylists[tpkg.Data.SrcName]
// 	case "whitelist":
// 	     wbgl, exists = td.Whitelists[tpkg.Data.SrcName]
// 	case "blacklist":
// 	     wbgl, exists = td.Blacklists[tpkg.Data.SrcName]
// 	default:
// 	   td.Logger.Printf("TapirUpdate for unknown source \"%s\" rejected.", tpkg.Data.SrcName)
// 	   return false, fmt.Errorf("MQTT ListType %s is unknown, update rejected", tpkg.Data.ListType)
// 	}
	if !exists {
	   td.Logger.Printf("TapirUpdate for unknown source \"%s\" rejected.", tpkg.Data.SrcName)
	   return false, fmt.Errorf("MQTT Source %s is unknown, update rejected", tpkg.Data.SrcName)
	}

	for _, name := range tpkg.Data.Added {
	    wbgl.Names[name.Name] = tapir.TapirName{
					Name:	 name.Name,
					Tags:	 name.Tags,
					Tagmask: name.Tagmask,
				    }
	}

	for _, name := range tpkg.Data.Removed {
	    delete(wbgl.Names, name.Name)
	}
	return true, nil
}

// func (td *TemData) UpdateOutboundRpz()
// 		if td.Whitelisted(add.Name) {
// 			td.Logger.Printf("EvaluateTapirUpdate: name %s is whitelisted, update ignored.", add.Name)
// //			return false, nil // rejected
// 		} else {
// 			td.Logger.Printf("EvaluateTapirUpdate: name %s is NOT whitelisted, update accepted.", add.Name)
// 		}
// 
// 		//     if td.Greylisted(name) {
// 		//     	return true, nil
// 		//     }
// 	}
// 
// 	for _, rem := range tpkg.Data.Removed {
// 		td.Logger.Printf("EvaluateTapirUpdate: name %s is removed from tapir greylist", rem.Name)
// //		return true, nil // rejected
// 	}
// 
// 	return true, nil
// }
