/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/dnstapir/tapir"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

var BumpCmd = &cobra.Command{
	Use:   "bump",
	Short: "Instruct TEM to bump the SOA serial of the RPZ zone",
	Run: func(cmd *cobra.Command, args []string) {
		resp := SendCommandCmd(tapir.CommandPost{
			Command: "bump",
			Zone:    dns.Fqdn(tapir.GlobalCF.Zone),
		})
		if resp.Error {
			fmt.Printf("%s\n", resp.ErrorMsg)
		}

		fmt.Printf("%s\n", resp.Msg)
	},
}

func init() {
	rootCmd.AddCommand(BumpCmd)

	BumpCmd.Flags().StringVarP(&tapir.GlobalCF.Zone, "zone", "z", "", "Zone name")
}

func SendCommandCmd(data tapir.CommandPost) tapir.CommandResponse {
	_, buf, _ := api.RequestNG(http.MethodPost, "/command", data, true)

	var cr tapir.CommandResponse

	err := json.Unmarshal(buf, &cr)
	if err != nil {
		log.Fatalf("Error from json.Unmarshal: %v\n", err)
	}
	return cr
}
