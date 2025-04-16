/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package main

import (
	"encoding/json"
	"log"

	"github.com/dnstapir/tapir"
	"github.com/spf13/viper"
)

func (pd *PopData) ConfigUpdater(conf *Config, stopch chan struct{}) {

	active := viper.GetBool("tapir.config.active")
	if !active {
		pd.Logger.Printf("*** ConfigUpdater: not active, skipping")
		return
	}

	// Create a new mqtt engine just for the statusupdater.
	me := pd.MqttEngine
	if me == nil {
		POPExiter("ConfigUpdater: MQTT Engine not running")
	}

	ConfigChan := make(chan tapir.MqttPkgIn, 5)

	configTopic := viper.GetString("tapir.config.topic")
	if configTopic == "" {
		POPExiter("ConfigUpdater: MQTT config topic not set")
	}

	pd.Logger.Printf("ConfigUpdater: Adding sub topic '%s' to MQTT Engine", configTopic)
	msg, err := me.SubToTopic(configTopic, ConfigChan, "struct", true) // XXX: Brr. kludge.
	if err != nil {
		POPExiter("ConfigUpdater: Error adding topic %s to MQTT Engine: %v", configTopic, err)
	}
	pd.Logger.Printf("ConfigUpdater: Topic status for MQTT engine %s: %+v", me.Creator, msg)

	log.Printf("ConfigUpdater: Starting")

	for inbox := range ConfigChan {
		log.Printf("ConfigUpdater: got config update message on topic %s: %v", inbox.Topic)
		var gconfig tapir.GlobalConfig
		err = json.Unmarshal(inbox.Payload, &gconfig)
		if err != nil {
			log.Printf("ConfigUpdater: error unmarshalling config update message: %v", err)
			continue
		}
		pd.ProcessTapirGlobalConfig(gconfig)
		if err != nil {
			log.Printf("ConfigUpdater: error processing config update message: %v", err)
		}
	}
}

func (pd *PopData) ProcessTapirGlobalConfig(gconfig tapir.GlobalConfig) {
    log.Printf("TapirProcessGlobalConfig: %+v", gconfig)

    // Assume there is only one topic and that it is the one we want
    // TODO maybe sanitize or sanity check or something
    newTopic := gconfig.ObservationTopics[0]
    bootstrapServers := gconfig.Bootstrap.Servers
    bootstrapUrl := gconfig.Bootstrap.BaseUrl
    bootstrapKey := gconfig.Bootstrap.ApiToken

	//for _, listtype := range []string{"allowlist", "denylist", "doubtlist"} {
	for _, wbgl := range pd.Lists["doubtlist"] {
        if  wbgl.Immutable || wbgl.Datasource != "mqtt" {
            continue
        }

        for topic := range wbgl.MqttDetails.ValidatorKeys {
            pd.MqttEngine.RemoveTopic(topic)
            break // Only one topic
        }

		pd.mu.Lock()
        wbgl.MqttDetails.ValidatorKeys[newTopic.Topic] = "" // Value is not used ;)
        wbgl.MqttDetails.Bootstrap = bootstrapServers
        wbgl.MqttDetails.BootstrapUrl = bootstrapUrl
        wbgl.MqttDetails.BootstrapKey = bootstrapKey
		pd.mu.Unlock()

        _, err := pd.MqttEngine.SubToTopic(newTopic.Topic, pd.TapirObservations, "struct", true) // XXX: Brr. kludge.
        if err != nil {
            POPExiter("ProcessTapirGlobalConfig: Error adding topic %s: %v", newTopic, err)
        }

        src := SourceConf{
            Bootstrap:    wbgl.MqttDetails.Bootstrap,
            BootstrapUrl: wbgl.MqttDetails.BootstrapUrl,
            BootstrapKey: wbgl.MqttDetails.BootstrapKey,
            Name:         wbgl.Name,
            Format:       wbgl.Format,
        }

        if len(gconfig.Bootstrap.Servers) > 0 {
            pd.Logger.Printf("ProcessTapirGlobalConfig: %d bootstrap servers advertised: %v", wbgl.Name, len(src.Bootstrap), src.Bootstrap)
            tmp, err := pd.BootstrapMqttSource(src)
            if err != nil {
                pd.Logger.Printf("ProcessTapirGlobalConfig: Error bootstrapping MQTT source %s: %v", wbgl.Name, err)
            } else {
		        pd.mu.Lock()
                *wbgl = *tmp
		        pd.mu.Unlock()
            }
        }

		pd.Logger.Printf("*** DONE Processing global config")
    }
}
