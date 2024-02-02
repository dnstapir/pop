/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cmd

import (
	"fmt"
	"os"

	"github.com/dnstapir/tapir"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

var rpzname, rpztype, rpzaction, rpzpolicy string

var RpzCmd = &cobra.Command{
	Use:   "rpz",
	Short: "Instruct TEM to modify the RPZ zone; must use sub-command",
	Long: `Known actions are:
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

		if rpztype == "" {
			fmt.Printf("Error: RPZ list type for domain name \"%s\" not specified.\n", rpzname)
			fmt.Printf("Error: must be one of: whitelist, greylist or blacklist.\n")
			os.Exit(1)
		}

		if rpzpolicy == "" {
			fmt.Printf("Error: desired RPZ policy for domain name \"%s\" not specified.\n", rpzname)
			os.Exit(1)
		}

		//	        if rpzaction == "" {
		//		   fmt.Printf("Error: desired RPZ action for domain name \"%s\" not specified.\n", rpzname)
		//		   os.Exit(1)
		//		}

		resp := SendCommandCmd(tapir.CommandPost{
			Command:  "rpz-add",
			Name:     dns.Fqdn(rpzname),
			ListType: rpztype,
			Action:   rpzaction,
			Policy:   rpzpolicy,
			Zone:     dns.Fqdn(tapir.GlobalCF.Zone),
		})
		if resp.Error {
			fmt.Printf("%s\n", resp.ErrorMsg)
		}

		if resp.Msg != "" {
			fmt.Printf("%s\n", resp.Msg)
		}
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
			Name:    dns.Fqdn(rpzname),
			Zone:    dns.Fqdn(tapir.GlobalCF.Zone),
		})
		if resp.Error {
			fmt.Printf("%s\n", resp.ErrorMsg)
		}

		fmt.Printf("%s\n", resp.Msg)
	},
}

var RpzLookupCmd = &cobra.Command{
	Use:   "lookup",
	Short: "Instruct TEM to remove a rule from the RPZ zone",
	Run: func(cmd *cobra.Command, args []string) {
		if rpzname == "" {
			fmt.Printf("Error: domain name look up not specified.\n")
			os.Exit(1)
		}

		resp := SendCommandCmd(tapir.CommandPost{
			Command: "rpz-lookup",
			Name:    dns.Fqdn(rpzname),
			Zone:    dns.Fqdn(tapir.GlobalCF.Zone),
		})
		if resp.Error {
			fmt.Printf("%s\n", resp.ErrorMsg)
		}

		fmt.Printf("%s\n", resp.Msg)
	},
}

var RpzListCmd = &cobra.Command{
	Use:   "list",
	Short: "Instruct TEM to remove a rule from the RPZ zone",
	Run: func(cmd *cobra.Command, args []string) {

		resp := SendCommandCmd(tapir.CommandPost{
			Command: "rpz-list-sources",
		})
		if resp.Error {
			fmt.Printf("%s\n", resp.ErrorMsg)
		}

		fmt.Printf("%s\n", resp.Msg)
	},
}

func init() {
	rootCmd.AddCommand(RpzCmd)
	RpzCmd.AddCommand(RpzAddCmd, RpzRemoveCmd, RpzLookupCmd, RpzListCmd)

	RpzAddCmd.Flags().StringVarP(&rpzname, "name", "", "", "Domain name to add rule for")
	RpzLookupCmd.Flags().StringVarP(&rpzname, "name", "", "", "Domain name to look up")
	RpzAddCmd.Flags().StringVarP(&rpztype, "type", "", "", "One of: whitelist, greylist or blacklist")
	RpzAddCmd.Flags().StringVarP(&rpzaction, "action", "", "", "Desired action")
	RpzAddCmd.Flags().StringVarP(&rpzpolicy, "policy", "", "", "Desired policy for this domain name")
}
