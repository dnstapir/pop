/*
 * Copyright (c) DNS TAPIR
 */

package main

import (
        "fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/dnstapir/tapir-em/tapir"
	"github.com/spf13/viper"
)

func (td *TemData) StartMqttEngine() error {
     clientid := viper.GetString("mqtt.clientid")
     if clientid == "" {
     	TEMExiter("Error starting MQTT Engine: clientid not specified in config")
     }
     meng, err := tapir.NewMqttEngine(clientid, false, true)	// sub, but no pub
		if err != nil {
			TEMExiter("Error from NewMqttEngine: %v\n", err)
		}

		cmnder, _, inbox, err := meng.StartEngine()
		if err != nil {
			log.Fatalf("Error from StartEngine(): %v", err)
		}
		td.TapirMqttCmdCh = cmnder
		td.TapirMqttSubCh = inbox

		respch := make(chan tapir.MqttEngineResponse, 2)

		ic := make(chan os.Signal, 1)
		signal.Notify(ic, os.Interrupt, syscall.SIGTERM)
		go func() {
			for {
				select {

				case <-ic:
					fmt.Println("SIGTERM interrupt received, sending stop signal to MQTT Engine")
					cmnder <- tapir.MqttEngineCmd{Cmd: "stop", Resp: respch}
					r := <-respch
					if r.Error {
					   fmt.Printf("Error: %s\n", r.ErrorMsg)
					} else {
					   fmt.Printf("MQTT Engine: %s\n", r.Status)
					}
					os.Exit(1)
				}
			}
		}()

// 		go func() {
// 			var pkg tapir.MqttPkg
// 			for {
// 				select {
// 
// 				case pkg = <-inbox:
// 					// fmt.Printf("sub data received from MQTT Engine: %v\n", pkg)
// 					fmt.Printf("TAPIR Message: %s\n", pkg.Data)
// 				}
// 			}
// 		}()


     return nil
}
