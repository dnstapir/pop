/*
 * Copyright (c) DNS TAPIR
 */

package main

import (
	//        "fmt"
	"log"
	//	"os"
	//	"os/signal"
	//	"syscall"

	"github.com/dnstapir/tapir-em/tapir"
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
	meng, err := tapir.NewMqttEngine(clientid, false, true) // sub, but no pub
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

	// 		respch := make(chan tapir.MqttEngineResponse, 2)
	//
	// 		ic := make(chan os.Signal, 1)
	// 		signal.Notify(ic, os.Interrupt, syscall.SIGTERM)
	// 		go func() {
	// 			for {
	// 				select {
	//
	// 				case <-ic:
	// 					fmt.Println("SIGTERM interrupt received, sending stop signal to MQTT Engine")
	// 					cmnder <- tapir.MqttEngineCmd{Cmd: "stop", Resp: respch}
	// 					r := <-respch
	// 					if r.Error {
	// 					   fmt.Printf("Error: %s\n", r.ErrorMsg)
	// 					} else {
	// 					   fmt.Printf("MQTT Engine: %s\n", r.Status)
	// 					}
	// 					os.Exit(1)
	// 				}
	// 			}
	// 		}()

	return nil
}

// Evaluating an update consists of two steps:
// 1. Add the data to the correct list.
// 2. Check the name against complete current data to decide whether it should change the output

// XXX: This code does not yet reflect this.

func (td *TemData) EvaluateTapirUpdate(tpkg tapir.MqttPkg) (bool, error) {
	td.Logger.Printf("EvaluateTapirUpdate: update contains %d adds and %d removes",
		len(tpkg.Data.Added), len(tpkg.Data.Removed))

	for _, add := range tpkg.Data.Added {
		if td.Whitelisted(add.Name) {
			td.Logger.Printf("EvaluateTapirUpdate: name %s is whitelisted, update ignored.", add.Name)
//			return false, nil // rejected
		} else {
			td.Logger.Printf("EvaluateTapirUpdate: name %s is NOT whitelisted, update accepted.", add.Name)
		}

		//     if td.Greylisted(name) {
		//     	return true, nil
		//     }
	}

	for _, rem := range tpkg.Data.Removed {
		td.Logger.Printf("EvaluateTapirUpdate: name %s is removed from tapir greylist", rem.Name)
//		return true, nil // rejected
	}

	return true, nil
}
