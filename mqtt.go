/*
 * Copyright (c) DNS TAPIR
 */

package main

import (
	"fmt"
	"log"
	"time"

	"github.com/dnstapir/tapir"
	"github.com/miekg/dns"
)

func (td *TemData) CreateMqttEngine(clientid string, statusch chan tapir.ComponentStatusUpdate, lg *log.Logger) error {
	if clientid == "" {
		TEMExiter("Error starting MQTT Engine: clientid not specified in config")
	}
	var err error
	td.Logger.Printf("Creating MQTT Engine with clientid %s", clientid)
	td.MqttEngine, err = tapir.NewMqttEngine("tapir-pop", clientid, tapir.TapirSub, statusch, lg) // sub, but no pub
	if err != nil {
		TEMExiter("Error from NewMqttEngine: %v\n", err)
	}
	return nil
}

func (td *TemData) StartMqttEngine(meng *tapir.MqttEngine) error {
	if td.TapirMqttEngineRunning {
		return nil
	}

	//	clientid := viper.GetString("mqtt.clientid")
	// if clientid == "" {
	//		TEMExiter("Error starting MQTT Engine: clientid not specified in config")
	//}
	//meng, err := tapir.NewMqttEngine(clientid, tapir.TapirSub) // sub, but no pub
	//if err != nil {
	//TEMExiter("Error from NewMqttEngine: %v\n", err)
	//}

	cmnder, outbox, inbox, err := meng.StartEngine()
	if err != nil {
		log.Fatalf("Error from StartEngine(): %v", err)
	}
	td.TapirMqttCmdCh = cmnder
	td.TapirMqttPubCh = outbox
	td.TapirObservations = inbox
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

// func (td *TemData) ProcessTapirUpdate(tpkg tapir.MqttPkgIn) (bool, error) {
func (td *TemData) ProcessTapirUpdate(tm tapir.TapirMsg) (bool, error) {
	//	tm := tapir.TapirMsg{}
	//	err := json.Unmarshal(tpkg.Payload, &tm)
	//	if err != nil {
	//		fmt.Printf("MQTT: failed to decode json: %v", err)
	//		return false, fmt.Errorf("MQTT: failed to decode json: %v", err)
	//	}

	if td.Debug {
		td.Logger.Printf("ProcessTapirUpdate: update of MQTT source %s contains %d adds and %d removes",
			tm.SrcName, len(tm.Added), len(tm.Removed))
		tapir.PrintTapirMsg(tm, td.Logger)
	}

	var wbgl *tapir.WBGlist
	var exists bool

	td.Logger.Printf("ProcessTapirUpdate: looking up list [%s][%s]", tm.ListType, tm.SrcName)

	switch tm.ListType {
	case "whitelist", "greylist", "blacklist":
		wbgl, exists = td.Lists[tm.ListType][tm.SrcName]
	default:
		td.Logger.Printf("TapirUpdate for unknown listtype from source \"%s\" rejected.", tm.SrcName)
		return false, fmt.Errorf("MQTT ListType %s is unknown, update rejected", tm.ListType)
	}

	if !exists {
		td.Logger.Printf("TapirUpdate for unknown source \"%s\" rejected.", tm.SrcName)
		return false, fmt.Errorf("MQTT Source %s is unknown, update rejected", tm.SrcName)
	}

	for _, tname := range tm.Added {
		ttl := time.Duration(tname.TTL) * time.Second
		tmp := tapir.TapirName{
			Name:      dns.Fqdn(tname.Name),
			TimeAdded: tname.TimeAdded,
			TTL:       ttl,
			TagMask:   tname.TagMask,
		}
		wbgl.Names[tname.Name] = tmp

		td.Logger.Printf("ProcessTapirUpdate: adding name %s to %s (TimeAdded: %s ttl: %v)",
			tname.Name, wbgl.Name, tname.TimeAdded.Format(tapir.TimeLayout), tname.TTL)

		// Time that the name will be removed from the list
		// must ensure that reapertime is at least ReaperInterval into the future
		reptime := tname.TimeAdded.Add(ttl).Truncate(td.ReaperInterval).Add(td.ReaperInterval)

		// Ensure that there are no prior removal events for this name
		for reaperTime, namesMap := range wbgl.ReaperData {
			if reaperTime.Before(reptime) {
				if _, exists := namesMap[tname.Name]; exists {
					delete(namesMap, tname.Name)
					if len(namesMap) == 0 {
						delete(wbgl.ReaperData, reaperTime)
					}
				}
			}
		}

		// Add the name to the removal list for the time it will be removed
		if wbgl.ReaperData[reptime] == nil {
			wbgl.ReaperData[reptime] = make(map[string]bool)
		}
		wbgl.ReaperData[reptime][tname.Name] = true
	}

	td.Logger.Printf("ProcessTapirUpdate: current state of %s %s ReaperData:", tm.ListType, wbgl.Name)
	for t, v := range wbgl.ReaperData {
		if len(v) > 0 {
			td.Logger.Printf("== At time %s the following names will be removed from the dns-tapir list:", t.Format(tapir.TimeLayout))
			for name := range v {
				td.Logger.Printf("  %s", name)
			}
		} else {
			td.Logger.Printf("ReaperData: timekey %s is empty, deleting", t.Format(tapir.TimeLayout))
			delete(wbgl.ReaperData, t)
		}
	}

	for _, tname := range tm.Removed {
		delete(wbgl.Names, dns.Fqdn(tname.Name))
	}

	ixfr, err := td.GenerateRpzIxfr(&tm)
	if err != nil {
		return false, err
	}
	err = td.ProcessIxfrIntoAxfr(ixfr)
	return true, err // return to RefreshEngine
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

	//	td.Logger.Printf("PIIA Notifying %d downstreams for RPZ zone %s", len(td.RpzDownstreams), td.Rpz.ZoneName)
	err := td.NotifyDownstreams()
	return err
}
