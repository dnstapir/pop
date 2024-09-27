/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package main

import (
	"fmt"
	"log"
	"path/filepath"
	"slices"
	"time"

	"github.com/dnstapir/tapir"
	"github.com/spf13/viper"
)

func (pd *PopData) StatusUpdater(conf *Config, stopch chan struct{}) {

	active := viper.GetBool("tapir.status.active")
	if !active {
		pd.Logger.Printf("*** StatusUpdater: not active, will just read status updates from channel and not publish anything")
		for csu := range pd.ComponentStatusCh {
			log.Printf("StatusUpdater: got status update message: %+v", csu)
		}
	}

	var s = tapir.TapirFunctionStatus{
		Function:        "tapir-pop",
		FunctionID:      "random-popper",
		ComponentStatus: make(map[string]tapir.TapirComponentStatus),
	}

	//	me := pd.MqttEngine
	//	if me == nil {
	//		POPExiter("StatusUpdater: MQTT Engine not running")
	//	}

	// Create a new mqtt engine just for the statusupdater.
	//	me, err := tapir.NewMqttEngine("statusupdater", viper.GetString("tapir.mqtt.clientid")+"statusupdates", tapir.TapirPub, pd.ComponentStatusCh, log.Default())
	// if err != nil {
	// 	POPExiter("StatusUpdater: Error creating MQTT Engine: %v", err)
	// }
	me := pd.MqttEngine

	ticker := time.NewTicker(60 * time.Second)

	// var statusch = make(chan tapir.ComponentStatusUpdate, 10)
	// If any status updates arrive, print them out
	// go func() {
	// 	for status := range statusch {
	// 		fmt.Printf("Status update: %+v\n", status)
	// 	}
	// }()

	certCN, _, _, err := tapir.FetchTapirClientCert(log.Default(), pd.ComponentStatusCh)
	if err != nil {
		POPExiter("StatusUpdater: Error fetching client certificate: %v", err)
	}

	statusTopic, err := tapir.MqttTopic(certCN, "tapir.status.topic")
	if err != nil {
		POPExiter("StatusUpdater: MQTT status topic not set")
	}

	keyfile := viper.GetString("tapir.status.signingkey")
	if keyfile == "" {
		POPExiter("StatusUpdater: MQTT status signing key not set")
	}

	keyfile = filepath.Clean(keyfile)
	signkey, err := tapir.FetchMqttSigningKey(statusTopic, keyfile)
	if err != nil {
		POPExiter("StatusUpdater: Error fetching MQTT signing key for topic %s: %v", statusTopic, err)
	}

	pd.Logger.Printf("StatusUpdater: Adding pub topic '%s' to MQTT Engine", statusTopic)
	msg, err := me.PubToTopic(statusTopic, signkey, "struct", true) // XXX: Brr. kludge.
	if err != nil {
		POPExiter("Error adding topic %s to MQTT Engine: %v", statusTopic, err)
	}
	pd.Logger.Printf("StatusUpdater: Topic status for MQTT engine %s: %+v", me.Creator, msg)

	_, outbox, _, err := me.StartEngine()
	if err != nil {
		POPExiter("StatusUpdater: Error starting MQTT Engine: %v", err)
	}

	log.Printf("StatusUpdater: Starting")

	var known_components = []string{"tapir-observation", "mqtt-event", "rpz", "rpz-ixfr", "rpz-inbound", "downstream-notify",
		"downstream-ixfr", "mqtt-config", "mqtt-unknown", "main-boot", "cert-status"}

	var csu tapir.ComponentStatusUpdate
	var dirty bool
	for {
		select {
		case <-ticker.C:
			if dirty {
				pd.Logger.Printf("StatusUpdater: Status is dirty, publishing status update: %+v", s)
				// publish an mqtt status update
				outbox <- tapir.MqttPkgOut{
					Topic:   statusTopic,
					Type:    "raw",
					RawData: s,
				}
				dirty = false
			}
		case csu = <-pd.ComponentStatusCh:
			log.Printf("StatusUpdater: got status update message: %v", csu)
			switch csu.Status {
			case tapir.StatusFail, tapir.StatusWarn, tapir.StatusOK:
				log.Printf("StatusUpdater: status failure: %s", csu.Msg)
				var sur tapir.StatusUpdaterResponse
				switch {
				case slices.Contains(known_components, csu.Component):
					comp := s.ComponentStatus[csu.Component]
					comp.Status = csu.Status
					comp.Msg = csu.Msg
					switch csu.Status {
					case tapir.StatusFail:
						comp.NumFails++
						comp.LastFail = csu.TimeStamp
						comp.ErrorMsg = csu.Msg
					case tapir.StatusWarn:
						comp.NumWarnings++
						comp.LastWarn = csu.TimeStamp
						comp.WarningMsg = csu.Msg
					case tapir.StatusOK:
						comp.NumFails = 0
						comp.NumWarnings = 0
						comp.LastSuccess = csu.TimeStamp
					}
					s.ComponentStatus[csu.Component] = comp
					dirty = true
					sur.Msg = fmt.Sprintf("StatusUpdater: %s report for known component: %s", csu.Status, csu.Component)
				default:
					log.Printf("StatusUpdater: %s report for unknown component: %s", tapir.StatusToString[csu.Status], csu.Component)
					sur.Error = true
					sur.ErrorMsg = fmt.Sprintf("StatusUpdater: %s report for unknown component: %s", tapir.StatusToString[csu.Status], csu.Component)
					sur.Msg = fmt.Sprintf("StatusUpdater: known components are: %v", known_components)
				}

				if csu.Response != nil {
					csu.Response <- sur
				}

			case tapir.StatusReport:
				log.Printf("StatusUpdater: request for status report. Response: %v", csu.Response)
				if csu.Response != nil {
					csu.Response <- tapir.StatusUpdaterResponse{
						FunctionStatus:  s,
						KnownComponents: known_components,
					}
					log.Printf("StatusUpdater: request for status report sent")
				} else {
					log.Printf("StatusUpdater: request for status report ignored due to lack of a response channel")
				}

			default:
				log.Printf("StatusUpdater: Unknown status: %s", csu.Status)
			}
		case <-stopch:
			log.Printf("StatusUpdater: stopping")
			return
		}
	}
}
