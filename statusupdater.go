/*
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package main

import (
	"log"
	"path/filepath"
	"time"

	"github.com/dnstapir/tapir"
	"github.com/spf13/viper"
)

func (td *TemData) StatusUpdater(conf *Config, stopch chan struct{}) {

	var s = tapir.TemStatus{
		ComponentStatus: make(map[string]string),
		TimeStamps:      make(map[string]time.Time),
		Counters:        make(map[string]int),
		ErrorMsgs:       make(map[string]string),
	}

	me := td.MqttEngine
	if me == nil {
		TEMExiter("StatusUpdater: MQTT Engine not running")
	}

	var TemStatusCh = make(chan tapir.TemStatusUpdate, 100)
	conf.Internal.TemStatusCh = TemStatusCh

	ticker := time.NewTicker(60 * time.Second)

	statusTopic := viper.GetString("tapir.status.topic")
	if statusTopic == "" {
		TEMExiter("StatusUpdater: MQTT status topic not set")
	}
	keyfile := viper.GetString("tapir.status.signingkey")
	if keyfile == "" {
		TEMExiter("StatusUpdater: MQTT status signing key not set")
	}
	keyfile = filepath.Clean(keyfile)
	signkey, err := tapir.FetchMqttSigningKey(statusTopic, keyfile)
	if err != nil {
		TEMExiter("StatusUpdater: Error fetching MQTT signing key for topic %s: %v", statusTopic, err)
	}

	td.Logger.Printf("StatusUpdater: Adding topic '%s' to MQTT Engine", statusTopic)
	err = me.PubSubToTopic(statusTopic, signkey, nil, nil)
	if err != nil {
		TEMExiter("Error adding topic %s to MQTT Engine: %v", statusTopic, err)
	}

	log.Printf("StatusUpdater: Starting")

	var tsu tapir.TemStatusUpdate
	var dirty bool
	for {
		select {
		case <-ticker.C:
			if dirty {
				// publish an mqtt status update
				me.PublishChan <- tapir.MqttPkg{
					Topic:     statusTopic,
					TemStatus: s,
				}
				dirty = false
			}
		case tsu = <-TemStatusCh:
			log.Printf("StatusUpdater: got status update message: %v", tsu)
			switch tsu.Status {
			case "failure":
				log.Printf("StatusUpdater: status failure: %s", tsu.Msg)
				switch tsu.Component {
				case "tapir-observation", "mqtt-event", "rpz", "downstream-notify", "downstream-ixfr", "mqtt-config", "mqtt-unknown":
					s.ErrorMsgs[tsu.Component] = tsu.Msg
					s.ComponentStatus[tsu.Component] = "failure"
					s.TimeStamps[tsu.Component] = time.Now()
					s.Counters[tsu.Component]++
					s.NumFailures++
					s.LastFailure = time.Now()
					dirty = true
				default:
					log.Printf("StatusUpdater: Failure report for unknown component: %s", tsu.Component)
				}

			case "success":
				log.Printf("StatusUpdater: status success: %s", tsu.Msg)
				switch tsu.Component {
				case "tapir-observation", "mqtt-event", "rpz", "downstream-notify", "downstream-ixfr", "mqtt-config", "mqtt-unknown":
					s.TimeStamps[tsu.Component] = time.Now()
					s.Counters[tsu.Component]++
					s.ComponentStatus[tsu.Component] = "ok"
					delete(s.ErrorMsgs, tsu.Component)
					// tapir-observations do not make the status dirty
					if tsu.Component != "tapir-observation" && tsu.Component != "mqtt-event" {
						dirty = true
					}

				default:
					log.Printf("StatusUpdater: Success report for unknown component: %s", tsu.Component)
				}

			case "status":
				log.Printf("StatusUpdater: request for status report. Response: %v", tsu.Response)
				if tsu.Response != nil {
					tsu.Response <- s
					log.Printf("StatusUpdater: request for status report sent")
				} else {
					log.Printf("StatusUpdater: request for status report ignored due to lack of a response channel")
				}

			default:
				log.Printf("StatusUpdater: Unknown status: %s", tsu.Status)
			}
		case <-stopch:
			log.Printf("StatusUpdater: stopping")
			return
		}
	}
}
