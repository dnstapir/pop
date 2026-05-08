/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package pop

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/dnstapir/tapir"
	"github.com/spf13/viper"
)

func (pd *PopData) ConfigUpdater(ctx context.Context, conf *Config) error {

	active := viper.GetBool("tapir.config.active")
	if !active {
		pd.Logger.Printf("*** ConfigUpdater: not active, skipping")
		return nil
	}

	// Create a new mqtt engine just for the statusupdater.
	me := pd.MqttEngine
	if me == nil {
		return fmt.Errorf("MQTT Engine not running")
	}

	ConfigChan := make(chan tapir.MqttPkgIn, 5)

	configTopic := viper.GetString("tapir.config.topic")
	if configTopic == "" {
		return fmt.Errorf("MQTT config topic not set")
	}

	pd.Logger.Printf("ConfigUpdater: Adding sub topic '%s' to MQTT Engine", configTopic)
	err := me.SubToTopic(configTopic, ConfigChan, "struct", true) // XXX: Brr. kludge.
	if err != nil {
		return fmt.Errorf("error adding topic %s to MQTT Engine: %w", configTopic, err)
	}
	pd.Logger.Printf("ConfigUpdater: Topic status for MQTT engine %s", me.Creator)

	log.Printf("ConfigUpdater: Starting")

	for {
		select {
		case <-ctx.Done():
			log.Printf("ConfigUpdater: stopping")
			return nil
		case inbox := <-ConfigChan:
			log.Printf("ConfigUpdater: got config update message on topic %s", inbox.Topic)
			var gconfig tapir.GlobalConfig
			err = json.Unmarshal(inbox.Payload, &gconfig)
			if err != nil {
				log.Printf("ConfigUpdater: error unmarshalling config update message: %v", err)
				continue
			}
			err = pd.ProcessTapirGlobalConfig(gconfig)
			if err != nil {
				log.Printf("ConfigUpdater: error processing config update message: %v", err)
			}
		}
	}
}

func (pd *PopData) ProcessTapirGlobalConfig(gconfig tapir.GlobalConfig) error {
	log.Printf("TapirProcessGlobalConfig: %+v", gconfig)
	if len(gconfig.ObservationTopics) == 0 {
		return fmt.Errorf("global config has no observation topics")
	}
	if pd.MqttEngine == nil {
		return fmt.Errorf("MQTT Engine not running")
	}

	// Assume there is only one topic and that it is the one we want
	// TODO maybe sanitize or sanity check or something
	newTopic := gconfig.ObservationTopics[0]
	bootstrapServers := gconfig.Bootstrap.Servers
	bootstrapUrl := gconfig.Bootstrap.BaseUrl
	bootstrapKey := gconfig.Bootstrap.ApiToken

	//for _, listtype := range []string{"allowlist", "denylist", "doubtlist"} {
	for _, wbgl := range pd.Lists["doubtlist"] {
		if wbgl.Immutable || wbgl.Datasource != "mqtt" {
			continue
		}

		if len(wbgl.MqttDetails.Topics) > 0 {
			topic := wbgl.MqttDetails.Topics[0]
			if err := pd.MqttEngine.RemoveTopic(topic); err != nil {
				pd.Logger.Printf("ProcessTapirGlobalConfig: error removing previous MQTT topic %q: %v", topic, err)
			}
		}

		pd.mu.Lock()
		wbgl.MqttDetails.Topics = append(wbgl.MqttDetails.Topics, newTopic.Topic)
		wbgl.MqttDetails.Bootstrap = bootstrapServers
		wbgl.MqttDetails.BootstrapUrl = bootstrapUrl
		wbgl.MqttDetails.BootstrapKey = bootstrapKey
		pd.mu.Unlock()

		err := pd.MqttEngine.SubToTopic(newTopic.Topic, pd.TapirObservations, "struct", true) // XXX: Brr. kludge.
		if err != nil {
			return fmt.Errorf("error adding topic %s: %w", newTopic.Topic, err)
		}

		src := SourceConf{
			Bootstrap:    wbgl.MqttDetails.Bootstrap,
			BootstrapUrl: wbgl.MqttDetails.BootstrapUrl,
			BootstrapKey: wbgl.MqttDetails.BootstrapKey,
			Name:         wbgl.Name,
			Format:       wbgl.Format,
		}

		if len(gconfig.Bootstrap.Servers) > 0 {
			pd.Logger.Printf("ProcessTapirGlobalConfig: %s: %d bootstrap servers advertised: %v", wbgl.Name, len(src.Bootstrap), src.Bootstrap)
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
	return nil
}
