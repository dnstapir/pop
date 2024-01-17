/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cmd

import (
	"fmt"
	"os"

	"github.com/miekg/dns"
	"github.com/dnstapir/tapir-em/tapir"
	"github.com/spf13/cobra"
)

var rpzname, rpzaction string

var RpzCmd = &cobra.Command{
 	Use:   "rpz",
 	Short: "Instruct TEM to modify the RPZ zone; must use sub-command",
	Long:  `Known actions are:
drop	       send no response at all
nxdomain       return an NXDOMAIN response
nodata	       return a NODATA response`,
}

var RpzAddCmd = &cobra.Command{
 	Use:   "add",
 	Short: "Instruct TEM to add a new rule to the RPZ zone",
 	Run: func(cmd *cobra.Command, args []string) {
	        if rpzname == "" {
		   fmt.Printf("Error: domain name for which to add new RPZ rule for not specified.\n")
		   os.Exit(1)
		}

	        if rpzaction == "" {
		   fmt.Printf("Error: desired RPZ action for domain name \"%s\" not specified.\n", rpzname)
		   os.Exit(1)
		}

 		resp := SendCommandCmd(tapir.CommandPost{
 			Command: "rpz-add",
			Name:	 rpzname,
			Action:	 rpzaction,
			Zone:	 dns.Fqdn(tapir.GlobalCF.Zone),
 		})
 		if resp.Error {
 			fmt.Printf("%s\n", resp.ErrorMsg)
 		}

		fmt.Printf("%s\n", resp.Msg)
 	},
}

var RpzRemoveCmd = &cobra.Command{
 	Use:   "remove",
 	Short: "Instruct TEM to remove a rule from the RPZ zone",
 	Run: func(cmd *cobra.Command, args []string) {
	        if rpzname == "" {
		   fmt.Printf("Error: domain name to add rule for not specified.\n")
		   os.Exit(1)
		}

 		resp := SendCommandCmd(tapir.CommandPost{
 			Command: "rpz-remove",
			Name:	 rpzname,
			Zone:	 dns.Fqdn(tapir.GlobalCF.Zone),
 		})
 		if resp.Error {
 			fmt.Printf("%s\n", resp.ErrorMsg)
 		}

		fmt.Printf("%s\n", resp.Msg)
 	},
}

func init() {
	rootCmd.AddCommand(RpzCmd)
	RpzCmd.AddCommand(RpzAddCmd, RpzRemoveCmd)

	RpzAddCmd.Flags().StringVarP(&rpzname, "name", "", "", "Domain name to add rule for")
	RpzAddCmd.Flags().StringVarP(&rpzaction, "action", "", "", "Desired action")
}

