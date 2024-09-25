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

func (pd *PopData) CreateMqttEngine(clientid string, statusch chan tapir.ComponentStatusUpdate, lg *log.Logger) error {
	if clientid == "" {
		POPExiter("Error starting MQTT Engine: clientid not specified in config")
	}
	var err error
	pd.Logger.Printf("Creating MQTT Engine with clientid %s", clientid)
	pd.MqttEngine, err = tapir.NewMqttEngine("tapir-pop", clientid, tapir.TapirSub, statusch, lg) // sub, but no pub
	if err != nil {
		POPExiter("Error from NewMqttEngine: %v\n", err)
	}
	return nil
}

func (pd *PopData) StartMqttEngine(meng *tapir.MqttEngine) error {
	if pd.TapirMqttEngineRunning {
		return nil
	}

	cmnder, outbox, inbox, err := meng.StartEngine()
	if err != nil {
		log.Fatalf("Error from StartEngine(): %v", err)
	}
	pd.TapirMqttCmdCh = cmnder
	pd.TapirMqttPubCh = outbox
	pd.TapirObservations = inbox
	pd.TapirMqttEngineRunning = true

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

// func (pd *PopData) ProcessTapirUpdate(tpkg tapir.MqttPkgIn) (bool, error) {
func (pd *PopData) ProcessTapirUpdate(tm tapir.TapirMsg) (bool, error) {
	//	tm := tapir.TapirMsg{}
	//	err := json.Unmarshal(tpkg.Payload, &tm)
	//	if err != nil {
	//		fmt.Printf("MQTT: failed to decode json: %v", err)
	//		return false, fmt.Errorf("MQTT: failed to decode json: %v", err)
	//	}

	if pd.Debug {
		pd.Logger.Printf("ProcessTapirUpdate: update of MQTT source %s contains %d adds and %d removes",
			tm.SrcName, len(tm.Added), len(tm.Removed))
		tapir.PrintTapirMsg(tm, pd.Logger)
	}

	var wbgl *tapir.WBGlist
	var exists bool

	pd.Logger.Printf("ProcessTapirUpdate: looking up list [%s][%s]", tm.ListType, tm.SrcName)

	switch tm.ListType {
	case "whitelist", "greylist", "blacklist":
		wbgl, exists = pd.Lists[tm.ListType][tm.SrcName]
	default:
		pd.Logger.Printf("TapirUpdate for unknown listtype from source \"%s\" rejected.", tm.SrcName)
		return false, fmt.Errorf("MQTT ListType %s is unknown, update rejected", tm.ListType)
	}

	if !exists {
		pd.Logger.Printf("TapirUpdate for unknown source \"%s\" rejected.", tm.SrcName)
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

		pd.Logger.Printf("ProcessTapirUpdate: adding name %s to %s (TimeAdded: %s ttl: %v)",
			tname.Name, wbgl.Name, tname.TimeAdded.Format(tapir.TimeLayout), tname.TTL)

		// Time that the name will be removed from the list
		// must ensure that reapertime is at least ReaperInterval into the future
		reptime := tname.TimeAdded.Add(ttl).Truncate(pd.ReaperInterval).Add(pd.ReaperInterval)

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

	pd.Logger.Printf("ProcessTapirUpdate: current state of %s %s ReaperData:", tm.ListType, wbgl.Name)
	for t, v := range wbgl.ReaperData {
		if len(v) > 0 {
			pd.Logger.Printf("== At time %s the following names will be removed from the dns-tapir list:", t.Format(tapir.TimeLayout))
			for name := range v {
				pd.Logger.Printf("  %s", name)
			}
		} else {
			pd.Logger.Printf("ReaperData: timekey %s is empty, deleting", t.Format(tapir.TimeLayout))
			delete(wbgl.ReaperData, t)
		}
	}

	for _, tname := range tm.Removed {
		delete(wbgl.Names, dns.Fqdn(tname.Name))
	}

	ixfr, err := pd.GenerateRpzIxfr(&tm)
	if err != nil {
		return false, err
	}
	err = pd.ProcessIxfrIntoAxfr(ixfr)
	return true, err // return to RefreshEngine
}

func (pd *PopData) ProcessIxfrIntoAxfr(ixfr RpzIxfr) error {
	for _, tn := range ixfr.Removed {
		delete(pd.Rpz.Axfr.Data, tn.Name)
		if pd.Debug {
			pd.Logger.Printf("PIIA: Deleting domain %s", tn.Name)
		}
	}
	for _, tn := range ixfr.Added {
		if _, exist := pd.Rpz.Axfr.Data[tn.Name]; exist {
			// XXX: this should not happen.
			pd.Logger.Printf("Error: ProcessIxfrIntoAxfr: domain %s already exists. This should not happen.",
				tn.Name)
		} else {
			pd.Rpz.Axfr.Data[tn.Name] = tn
			if pd.Debug {
				pd.Logger.Printf("PIIA: Adding domain %s", tn.Name)
			}
		}
	}

	//	pd.Logger.Printf("PIIA Notifying %d downstreams for RPZ zone %s", len(pd.RpzDownstreams), pd.Rpz.ZoneName)
	err := pd.NotifyDownstreams()
	return err
}
