/*
 * Copyright (c) DNS TAPIR
 */
package main

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dnstapir/tapir"
	"github.com/ryanuber/columnize"
	"github.com/spf13/viper"
)

func (td *TemData) BootstrapMqttSource(s *tapir.WBGlist, src SourceConf) (*tapir.WBGlist, error) {
	// Initialize the API client
	api := &tapir.ApiClient{
		BaseUrl:    fmt.Sprintf(src.BootstrapUrl, src.Bootstrap[0]), // Must specify a valid BaseUrl
		ApiKey:     src.BootstrapKey,
		AuthMethod: "X-API-Key",
	}

	cd := viper.GetString("certs.certdir")
	if cd == "" {
		log.Fatalf("Error: missing config key: certs.certdir")
	}
	// cert := cd + "/" + certname
	cert := cd + "/" + "tem"
	tlsConfig, err := tapir.NewClientConfig(viper.GetString("certs.cacertfile"), cert+".key", cert+".crt")
	if err != nil {
		TEMExiter("BootstrapMqttSource: Error: Could not set up TLS: %v", err)
	}
	// XXX: Need to verify that the server cert is valid for the bootstrap server
	tlsConfig.InsecureSkipVerify = true
	err = api.SetupTLS(tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("error setting up TLS for the API client: %v", err)
	}

	bootstrapaddrs := viper.GetStringSlice("bootstrapserver.addresses")
	tlsbootstrapaddrs := viper.GetStringSlice("bootstrapserver.tlsaddresses")
	bootstrapaddrs = append(bootstrapaddrs, tlsbootstrapaddrs...)

	// Iterate over the bootstrap servers
	for _, server := range src.Bootstrap {
		// Is this myself?
		for _, bs := range bootstrapaddrs {
			if bs == server {
				td.Logger.Printf("MQTT bootstrap server %s is myself, skipping", server)
				continue
			}
		}

		api.BaseUrl = fmt.Sprintf(src.BootstrapUrl, server)

		// Send an API ping command
		pr, err := api.SendPing(0, false)
		if err != nil {
			td.Logger.Printf("Ping to MQTT bootstrap server %s failed: %v", server, err)
			continue
		}

		uptime := time.Since(pr.BootTime).Round(time.Second)
		td.Logger.Printf("MQTT bootstrap server %s uptime: %v. It has processed %d MQTT messages", server, uptime, 17)

		status, buf, err := api.RequestNG(http.MethodPost, "/bootstrap", tapir.BootstrapPost{
			Command:  "greylist-status",
			ListName: src.Name,
			Encoding: "json", // XXX: This is our default, but we'll test other encodings later
		}, true)
		if err != nil {
			fmt.Printf("Error from RequestNG: %v\n", err)
			continue
		}

		var br tapir.BootstrapResponse
		err = json.Unmarshal(buf, &br)
		if err != nil {
			td.Logger.Printf("Error decoding greylist-status response from %s: %v. Giving up.\n", server, err)
			continue
		}
		if br.Error {
			td.Logger.Printf("Bootstrap server %s responded with error: %s (instead of greylist status)", server, br.ErrorMsg)
		}
		if len(br.Msg) != 0 {
			td.Logger.Printf("Bootstrap server %s responded: %s", server, br.Msg)
		}

		td.Logger.Printf("MQTT bootstrap server %s uptime: %v. It has processed %d MQTT messages on the %s topic (last msg arrived at %s), ", server, uptime, br.MsgCounters["greylist"], src.Name, br.MsgTimeStamps["greylist"].Format(time.RFC3339))

		status, buf, err = api.RequestNG(http.MethodPost, "/bootstrap", tapir.BootstrapPost{
			Command:  "export-greylist",
			ListName: src.Name,
			Encoding: "gob", // XXX: This is our default, but we'll test other encodings later
		}, true)
		if err != nil {
			fmt.Printf("Error from RequestNG: %v\n", err)
			continue
		}

		if status != http.StatusOK {
			td.Logger.Printf("HTTP Error: %s\n", buf)
			continue
		}

		var greylist tapir.WBGlist
		decoder := gob.NewDecoder(bytes.NewReader(buf))
		err = decoder.Decode(&greylist)
		if err != nil {
			// fmt.Printf("Error decoding greylist data: %v\n", err)
			// If decoding the gob failed, perhaps we received a tapir.BootstrapResponse instead?
			var br tapir.BootstrapResponse
			err = json.Unmarshal(buf, &br)
			if err != nil {
				td.Logger.Printf("Error decoding bootstrap response from %s: %v. Giving up.\n", server, err)
				continue
			}
			if br.Error {
				td.Logger.Printf("Bootstrap server %s responded with error: %s (instead of GOB blob)", server, br.ErrorMsg)
			}
			if len(br.Msg) != 0 {
				td.Logger.Printf("Bootstrap server %s responded: %s (instead of GOB blob)", server, br.Msg)
			}
			// return nil, fmt.Errorf("Command Error: %s", br.ErrorMsg)
			continue
		}

		if td.Debug {
			td.Logger.Printf("%v", greylist)
			td.Logger.Printf("Names present in greylist %s:", src.Name)
			out := []string{"Name|Time added|TTL|Tags"}
			for _, n := range greylist.Names {
				out = append(out, fmt.Sprintf("%s|%v|%v|%v", n.Name, n.TimeAdded.Format(tapir.TimeLayout), n.TTL, n.TagMask))
			}
			td.Logger.Printf("%s", columnize.SimpleFormat(out))
		}

		// Successfully received and decoded bootstrap data
		return &greylist, nil
	}

	// If no bootstrap server succeeded
	return nil, fmt.Errorf("all bootstrap servers failed")
}
