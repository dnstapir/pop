/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/miekg/dns"
	"github.com/dnstapir/tapir-em/tapir"
	"github.com/spf13/cobra"
)

var debugcmdCmd = &cobra.Command{
	Use:   "debugcmd",
	Short: "A brief description of your command",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("debugcmd called")
	},
}

// var debugDelFDmapCmd = &cobra.Command{
// 	Use:   "delfdmap",
// 	Short: "Return the global map DelFDmap from server",
// 	Long: `Return the global map DelFDmap from server
// (mostly useful with -d JSON prettyprinter).`,
// 	Run: func(cmd *cobra.Command, args []string) {
// 		resp := SendDebugCmd(tapir.DebugPost{
// 			Command: "delfdmap",
// 		})
// 		if resp.Error {
// 			fmt.Printf("%s\n", resp.ErrorMsg)
// 		}
// 		var pretty bytes.Buffer
// 		err := json.Indent(&pretty, resp.Data.([]byte), "", "   ")
// 		if err != nil {
// 			fmt.Printf("JSON parse error: %v", err)
// 		}
// 		fmt.Printf("Received %d bytes of data: %v\n", len(resp.Msg), pretty.String())
// 	},
// }

var debugZoneDataCmd = &cobra.Command{
 	Use:   "zonedata",
 	Short: "Return the ZoneData struct for the specified zone from server",
 	Long: `Return the ZoneData struct from server
 (mostly useful with -d JSON prettyprinter).`,
 	Run: func(cmd *cobra.Command, args []string) {
 		resp := SendDebugCmd(tapir.DebugPost{
 			Command: "zonedata",
			Zone:	 dns.Fqdn(tapir.GlobalCF.Zone),
 		})
 		if resp.Error {
 			fmt.Printf("%s\n", resp.ErrorMsg)
 		}

		zd := resp.ZoneData

 		fmt.Printf("Received %d bytes of data\n", len(resp.Msg))
		fmt.Printf("Zone %s: RRs: %d Owners: %d\n", tapir.GlobalCF.Zone,
				 len(zd.RRs), len(zd.Owners))
 	},
}

var zonefile string

var debugSyncZoneCmd = &cobra.Command{
	Use:   "synczone",
	Short: "A brief description of your command",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("synczone called")

		if tapir.GlobalCF.Zone == "" {
			fmt.Printf("Zone name not specified.\n")
			os.Exit(1)
		}

		if zonefile == "" {
			fmt.Printf("Zone file not specified.\n")
			os.Exit(1)
		}

		zd := tapir.ZoneData{
			ZoneType: 3,	// zonetype=3 keeps RRs in a []OwnerData, with an OwnerIndex map[string]int to locate stuff
			ZoneName: tapir.GlobalCF.Zone,
			KeepFunc: func(uint16) bool { return true },
			Logger:   log.Default(),
		}

		_, err := zd.ReadZoneFile(zonefile)
		if err != nil {
			log.Fatalf("ReloadAuthZones: Error from ReadZoneFile(%s): %v", zonefile, err)
		}

		zd.ZONEMDHashAlgs = []uint8{1, 2}

		// XXX: This will be wrong for zonetype=3 (which we're using)
		fmt.Printf("----- zd.FilteredRRs: ----\n")
		tapir.PrintRRs(zd.FilteredRRs)
		fmt.Printf("----- zd.RRs (pre-sync): ----\n")
		tapir.PrintRRs(zd.RRs)
		zd.Sync()
		fmt.Printf("----- zd.RRs (post-sync): ----\n")
		tapir.PrintRRs(zd.RRs)
//		zd.Digest()
//		fmt.Printf("----- zd.ZONEMDrrs (post-sync): ----\n")
//		tapir.PrintRRs(zd.ZONEMDrrs)
//		zd.SOA.Serial = 8914
		zd.Sync()
		fmt.Printf("----- zd.RRs (post-sync): ----\n")
		tapir.PrintRRs(zd.RRs)
		fmt.Printf("----- zd.FilteredRRs: ----\n")
		tapir.PrintRRs(zd.FilteredRRs)
	},
}

func init() {
	rootCmd.AddCommand(debugcmdCmd)
	debugcmdCmd.AddCommand(debugSyncZoneCmd, debugZoneDataCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// debugcmdCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	debugSyncZoneCmd.Flags().StringVarP(&tapir.GlobalCF.Zone, "zone", "z", "", "Zone name")
	debugZoneDataCmd.Flags().StringVarP(&tapir.GlobalCF.Zone, "zone", "z", "", "Zone name")
	debugSyncZoneCmd.Flags().StringVarP(&zonefile, "file", "f", "", "Zone file")
}

type DebugResponse struct {
	Msg      string
	Data     interface{}
	Error    bool
	ErrorMsg string
}

func SendDebugCmd(data tapir.DebugPost) tapir.DebugResponse {
	_, buf, _ := api.RequestNG(http.MethodPost, "/debug", data, true)

	var dr tapir.DebugResponse

	var pretty bytes.Buffer
	err := json.Indent(&pretty, buf, "", "   ")
	if err != nil {
		fmt.Printf("JSON parse error: %v", err)
	}
	fmt.Printf("Received %d bytes of data: %v\n", len(buf), pretty.String())
	os.Exit(1)

	err = json.Unmarshal(buf, &dr)
	if err != nil {
		log.Fatalf("Error from json.Unmarshal: %v\n", err)
	}
	return dr
}
