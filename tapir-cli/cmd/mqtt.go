/*
 * Copyright (c) DNS TAPIR
 */
package cmd

import (
	"bufio"
	"bytes"
	//	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/dnstapir/tapir-em/tapir"
	"github.com/spf13/cobra"
	"github.com/miekg/dns"
)

var mqttclientid string
var mqttpub, mqttsub bool

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
		var wg sync.WaitGroup

		meng, err := tapir.NewMqttEngine(mqttclientid, mqttpub, mqttsub)
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

		SetupInterruptHandler(cmnder)

		if mqttsub {
			wg.Add(1)
			SetupSubPrinter(inbox)
		}

		var r tapir.MqttEngineResponse

		if mqttpub {
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
					wg.Done()
					break
				}

				buf.Reset()
				outbox <- tapir.MqttPkg{
					Type: "data",
					Data: tapir.TapirMsg{
						Msg:       msg,
						TimeStamp: time.Now(),
					},
				}
			}
			respch := make(chan tapir.MqttEngineResponse, 2)
			meng.CmdChan <- tapir.MqttEngineCmd{Cmd: "stop", Resp: respch}
			r = <-respch
			fmt.Printf("Response from MQTT Engine: %v\n", r)
		}
		wg.Wait()
	},
}

var mqttIntelUpdateCmd = &cobra.Command{
	Use:   "intel-update",
	Short: "Send intel updates in TapirMsg form to the tapir intel MQTT topic (debug tool)",
	Long: `Will query for operation (add|del), domain name and tags.
Will end the loop on the operation (or domain name) "QUIT"`,
	Run: func(cmd *cobra.Command, args []string) {
		meng, err := tapir.NewMqttEngine(mqttclientid, true, false)
		if err != nil {
			fmt.Printf("Error from NewMqttEngine: %v\n", err)
			os.Exit(1)
		}

		cmnder, outbox, _, err := meng.StartEngine()
		if err != nil {
			log.Fatalf("Error from StartEngine(): %v", err)
		}

		count := 0
//		buf := new(bytes.Buffer)

		SetupInterruptHandler(cmnder)

		var addop, names, tags string
		var td tapir.Domain
		var tmsg tapir.TapirMsg
		var snames, stags []string
		
		fmt.Printf("Exit query loop by using the domain name \"QUIT\"\n")

		for {
			count++
			addop = TtyYesNo("Operation is \"Add domain names\"", addop)
			names = TtyQuestion("Domain names", names, false)
			snames = strings.Fields(names)
			if len(snames) > 0 && strings.ToUpper(snames[0]) == "QUIT" {
				break
			}

			var tds []tapir.Domain
			if addop == "yes" {
			   tags = TtyQuestion("Tags", tags, false)
			   stags = strings.Fields(tags)
			
			   for _, name := range snames {
			       tds = append(tds, tapir.Domain{ Name: dns.Fqdn(name), Tags: stags })
			   }
			   tmsg = tapir.TapirMsg{
					Added:		tds,
					Msg:		"it is greater to give than to take",
					TimeStamp:	time.Now(),
			   	  }
			} else {
			   for _, name := range snames {
			       tds = append(tds, tapir.Domain{ Name: dns.Fqdn(name) })
			   }
			   tmsg = tapir.TapirMsg{
					Removed:	[]tapir.Domain{ td },
					Msg:		"happiness is a negative diff",
					TimeStamp:	time.Now(),
			   	  }
			}

//			buf.Reset()
			outbox <- tapir.MqttPkg{
				Type: "data",
				Data: tmsg,
			}
		}
		respch := make(chan tapir.MqttEngineResponse, 2)
		meng.CmdChan <- tapir.MqttEngineCmd{Cmd: "stop", Resp: respch}
		r := <-respch
		fmt.Printf("Response from MQTT Engine: %v\n", r)
	},
}

func init() {
	rootCmd.AddCommand(mqttCmd)
	mqttCmd.AddCommand(mqttEngineCmd, mqttIntelUpdateCmd)

	mqttCmd.PersistentFlags().StringVarP(&mqttclientid, "clientid", "", "",
		"MQTT client id, must be unique")
	mqttEngineCmd.Flags().BoolVarP(&mqttpub, "pub", "", false, "Enable pub support")
	mqttEngineCmd.Flags().BoolVarP(&mqttsub, "sub", "", false, "Enable sub support")
}

func SetupSubPrinter(inbox chan tapir.MqttPkg) {
	go func() {
		var pkg tapir.MqttPkg
		for {
			select {
			case pkg = <-inbox:
				fmt.Printf("Received TAPIR MQTT Message: %s\n", pkg.Data)
			}
		}
	}()
}

func SetupInterruptHandler(cmnder chan tapir.MqttEngineCmd) {
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
}

func TtyQuestion(query, oldval string, force bool) string {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("%s [%s]: ", query, oldval)
		text, _ := reader.ReadString('\n')
		if text == "\n" {
			fmt.Printf("[empty response, keeping previous value]\n")
			if oldval != "" {
				return oldval // all ok
			} else if force {
				fmt.Printf("[error: previous value was empty string, not allowed]\n")
				continue
			}
			return oldval
		} else {
			// regardless of force we accept non-empty response
			return strings.TrimSuffix(text, "\n")
		}
	}
}

func TtyYesNo(query, defval string) string {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("%s [%s]: ", query, defval)
		text, _ := reader.ReadString('\n')
		if text == "\n" {
			if defval != "" {
				fmt.Printf("[empty response, using default value]\n")
				return defval // all ok
			}
			fmt.Printf("[error: default value is empty string, not allowed]\n")
			continue
		} else {
			val := strings.ToLower(strings.TrimSuffix(text, "\n"))
			if (val == "yes") || (val == "no") {
				return val
			}
			fmt.Printf("Answer '%s' not accepted. Only yes or no.\n", val)
		}
	}
}
