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

var mqttPublishCmd = &cobra.Command{
	Use:   "publish",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example: to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		mp, err := tapir.NewMqttPublisher(mqttclientid)
		if err != nil {
			fmt.Printf("Error from NewMqttPublisher: %v\n", err)
			os.Exit(1)
		}

		cmder, messenger, err := mp.StartEngine()
		if err != nil {
			log.Fatalf("Error from RunPublisher(): %v", err)
		}

		stdin := bufio.NewReader(os.Stdin)
		count := 0
		buf := new(bytes.Buffer)
		jenc := json.NewEncoder(buf)

		respch := make(chan tapir.MqttPubSubResponse, 2)

		ic := make(chan os.Signal, 1)
		signal.Notify(ic, os.Interrupt, syscall.SIGTERM)
		go func() {
			for {
				select {

				case <-ic:
					fmt.Println("SIGTERM interrupt received, sending stop signal to MQTT Publisher")
					cmder <- tapir.MqttPubSubCmd{Cmd: "stop", Resp: respch}
					// mp.CmdChan <- tapir.MqttPubSubCmd{Cmd: "stop", Resp: respch}
					r := <-respch
					fmt.Printf("Response from MQTT Publisher: %v", r)
				}
			}
		}()

		var r tapir.MqttPubSubResponse

		// cmder <- tapir.MqttPubSubCmd{Cmd: "start", Resp: respch}
//		mp.CmdChan <- tapir.MqttPubSubCmd{Cmd: "start", Resp: respch}
//		r = <-respch
//		fmt.Printf("Response from MQTT Publisher: %v", r)
//		if r.Error {
//		   log.Fatalf("Error from publisher: %v", r.ErrorMsg)
//		}
//		fmt.Printf("Publisher status: %s\n", r.Status)

		for {
			count++
			msg, err := stdin.ReadString('\n')
			if err == io.EOF {
				os.Exit(0)
			}
			fmt.Printf("Read: %s", msg)
			msg = tapir.Chomp(msg)

			buf.Reset()
			jenc.Encode(tapir.TapirMsg{Type: "message", Msg: msg, Time: time.Now()})
			messenger <- tapir.MqttPublish{Type: "text", Msg: string(buf.String())}
			fmt.Printf("Msg sent to publisher\n")

			testMsg.Time = time.Now()
			testMsg.Msg = fmt.Sprintf("This is the %d message", count)

//			json.NewEncoder(buf).Encode(testMsg)
//			mp.PublishChan <- tapir.MqttPublish{Msg: string(buf.String())}
			mp.PublishChan <- tapir.MqttPublish{ Type: "data", Data: testMsg }
			fmt.Printf("Struct sent to publisher\n")
		}

		mp.CmdChan <- tapir.MqttPubSubCmd{Cmd: "stop", Resp: respch}
		r = <-respch
		fmt.Printf("Response from MQTT Publisher: %v", r)

		fmt.Printf("Done.\n")
	},
}

var mqttSubscribeCmd = &cobra.Command{
	Use:   "subscribe",
	Short: "Subscribe to messages on the topic specified in config",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example: to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		mp, err := tapir.NewMqttSubscriber(mqttclientid)
		if err != nil {
			fmt.Printf("Error from NewMqttSubscriber: %v\n", err)
			os.Exit(1)
		}

		mp.RunSubscriber()
		fmt.Printf("Done.\n")
	},
}

func init() {
	rootCmd.AddCommand(mqttCmd)
	mqttCmd.AddCommand(mqttPublishCmd, mqttSubscribeCmd)

	mqttCmd.PersistentFlags().StringVarP(&mqttclientid, "clientid", "", "", "MQTT client id, must be unique")
}
