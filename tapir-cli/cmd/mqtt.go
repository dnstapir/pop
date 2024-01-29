/*
 * Copyright (c) DNS TAPIR
 */
package cmd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/dnstapir/tapir-em/tapir"
	"github.com/spf13/cobra"
)

var mqttclientid string

var testMsg = tapir.TapirMsg{
	Type: "intel-update",
	Added: []tapir.Domain{
		tapir.Domain{
			Name: "frobozz.com.",
			Tags: []string{"new", "high-volume", "bad-ip"},
		},
		tapir.Domain{
			Name: "johani.org.",
			Tags: []string{"old", "low-volume", "good-ip"},
		},
	},
	Removed: []tapir.Domain{
		tapir.Domain{
			Name: "dnstapir.se.",
		},
	},
}

var mqttCmd = &cobra.Command{
	Use:   "mqtt",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example: to quickly create a Cobra application.`,
}

var mqttEngineCmd = &cobra.Command{
	Use:   "engine",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example: to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		meng, err := tapir.NewMqttEngine(mqttclientid)
		if err != nil {
			fmt.Printf("Error from NewMqttEngine: %v\n", err)
			os.Exit(1)
		}

		cmnder, outbox, inbox, err := meng.StartEngine()
		if err != nil {
			log.Fatalf("Error from StartEngine(): %v", err)
		}

		stdin := bufio.NewReader(os.Stdin)
		count := 0
		buf := new(bytes.Buffer)
		jenc := json.NewEncoder(buf)

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

		go func() {
			var pkg tapir.MqttPkg
			for {
				select {

				case pkg = <-inbox:
					fmt.Printf("sub data received from MQTT Engine: %v", pkg)
				}
			}
		}()

		var r tapir.MqttEngineResponse

		for {
			count++
			msg, err := stdin.ReadString('\n')
			if err == io.EOF {
				os.Exit(0)
			}
			fmt.Printf("Read: %s", msg)
			msg = tapir.Chomp(msg)
			if len(msg) == 0 {
				fmt.Printf("Empty message ignored.\n")
				continue
			}
			if strings.ToUpper(msg) == "QUIT" {
			   break
			}

			buf.Reset()
			jenc.Encode(tapir.TapirMsg{Type: "message", Msg: msg, TimeStamp: time.Now()})
			outbox <- tapir.MqttPkg{Type: "text", Msg: string(buf.String())}

			testMsg.TimeStamp = time.Now()
			testMsg.Msg = fmt.Sprintf("This is the %d message", count)

			meng.PublishChan <- tapir.MqttPkg{Type: "data", Data: testMsg}
		}

		meng.CmdChan <- tapir.MqttEngineCmd{Cmd: "stop", Resp: respch}
		r = <-respch
		fmt.Printf("Response from MQTT Engine: %v", r)
		fmt.Printf("Done.\n")
	},
}

func init() {
	rootCmd.AddCommand(mqttCmd)
	mqttCmd.AddCommand(mqttEngineCmd)

	mqttCmd.PersistentFlags().StringVarP(&mqttclientid, "clientid", "", "", "MQTT client id, must be unique")
}
