/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package main

import (
	"encoding/json"
	"log"
	"path/filepath"

	"github.com/dnstapir/tapir"
	"github.com/spf13/viper"
)

func (td *TemData) ConfigUpdater(conf *Config, stopch chan struct{}) {

	active := viper.GetBool("tapir.config.active")
	if !active {
		td.Logger.Printf("*** ConfigUpdater: not active, skipping")
		return
	}

	// Create a new mqtt engine just for the statusupdater.
	me := td.MqttEngine
	if me == nil {
		TEMExiter("ConfigUpdater: MQTT Engine not running")
	}

	ConfigChan := make(chan tapir.MqttPkgIn, 5)

	configTopic := viper.GetString("tapir.config.topic")
	if configTopic == "" {
		TEMExiter("ConfigUpdater: MQTT config topic not set")
	}
	keyfile := viper.GetString("tapir.config.validatorkey")
	if keyfile == "" {
		TEMExiter("ConfigUpdater: MQTT validator key not set for topic %s", configTopic)
	}
	keyfile = filepath.Clean(keyfile)
	validatorkey, err := tapir.FetchMqttValidatorKey(configTopic, keyfile)
	if err != nil {
		TEMExiter("ConfigUpdater: Error fetching MQTT validator key for topic %s: %v", configTopic, err)
	}

	td.Logger.Printf("ConfigUpdater: Adding sub topic '%s' to MQTT Engine", configTopic)
	msg, err := me.SubToTopic(configTopic, validatorkey, ConfigChan, "struct", true) // XXX: Brr. kludge.
	if err != nil {
		TEMExiter("ConfigUpdater: Error adding topic %s to MQTT Engine: %v", configTopic, err)
	}
	td.Logger.Printf("ConfigUpdater: Topic status for MQTT engine %s: %+v", me.Creator, msg)

	log.Printf("ConfigUpdater: Starting")

	for inbox := range ConfigChan {
		log.Printf("ConfigUpdater: got config update message on topic %s: %v", inbox.Topic)
		var gconfig tapir.GlobalConfig
		err = json.Unmarshal(inbox.Payload, &gconfig)
		if err != nil {
			log.Printf("ConfigUpdater: error unmarshalling config update message: %v", err)
			continue
		}
		td.ProcessTapirGlobalConfig(gconfig)
		if err != nil {
			log.Printf("ConfigUpdater: error processing config update message: %v", err)
		}
	}
}

func (td *TemData) ProcessTapirGlobalConfig(gconfig tapir.GlobalConfig) {
	log.Printf("TapirProcessGlobalConfig: %+v", gconfig)
}
