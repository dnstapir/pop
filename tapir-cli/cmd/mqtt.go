/*
 * Copyright (c) DNS TAPIR
 */
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/dnstapir/tapir-em/tapir"
)

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
		mp, err := tapir.NewMqttPublisher()
		if err != nil {
		   fmt.Printf("Error from NewMqttPublisher: %v\n", err)
		   os.Exit(1)
		}

		mp.RunPublisher()
		fmt.Printf("Done.\n")
	},
}

var mqttSubscribeCmd = &cobra.Command{
	Use:   "subscribe",
	Short: "Subscribe to messages on the topic specified in config",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example: to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		mp, err := tapir.NewMqttSubscriber()
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
}
