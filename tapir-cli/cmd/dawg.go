/*
 * Copyright (c) DNS TAPIR
 */
package cmd

import (
        "errors"
	"fmt"
	"os"

	"github.com/smhanov/dawg"
	"github.com/spf13/cobra"
	"github.com/dnstapir/tapir-em/tapir"
)

var srcformat, srcfile, outfile, dawgfile, dawgname string

var dawgCmd = &cobra.Command{
	Use:   "dawg",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command.`,
}

var dawgCompileCmd = &cobra.Command{
	Use:   "compile",
	Short: "Compile a new DAWG file from a text source file",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command.`,
	Run: func(cmd *cobra.Command, args []string) {
		if srcfile == "" {
	   	   fmt.Printf("Error: source file not specified.\n")
	   	   os.Exit(1)
		}

		if outfile == "" {
	   	   fmt.Printf("Error: outfile not specified.\n")
	   	   os.Exit(1)
		}

		_, err := os.Stat(srcfile)
		if err != nil {
		   if errors.Is(err, os.ErrNotExist) {
	   	      fmt.Printf("Error: source file \"%s\" does not exist.\n", srcfile)
	   	      os.Exit(1)
		   } else {
		      fmt.Printf("Error: %v\n", err)
		   }
		}

		switch srcformat {
		case "csv":
		     CompileDawgFromCSV(srcfile, outfile)
		case "text":
		     CompileDawgFromText(srcfile, outfile)
		default:
	   	   fmt.Printf("Error: format of source file \"%s\" unknown. Must be either \"csv\" or \"text\".\n",
	   		      	      srcformat)
	   	   os.Exit(1)
		}
	},
}

var dawgLookupCmd = &cobra.Command{
	Use:   "lookup",
	Short: "Look up a name in an existing DAWG file",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command.`,
	Run: func(cmd *cobra.Command, args []string) {
		if dawgfile == "" {
	   	   fmt.Printf("Error: DAWG file not specified.\n")
	   	   os.Exit(1)
		}

		if dawgname == "" {
	   	   fmt.Printf("Error: Name to look up not specified.\n")
	   	   os.Exit(1)
		}

     	  fmt.Printf("Loading DAWG: %s\n", dawgfile)
	  dawgf, err := dawg.Load(dawgfile)
	  if err != nil {
	     fmt.Printf("Error from dawg.Load(%s): %v", dawgfile, err)
	     os.Exit(1)
	  }

	  idx := dawgf.IndexOf(dawgname)

	  switch idx {
	  case -1:
	       fmt.Printf("Name not found\n")
	  default:
		fmt.Printf("Name %s found, index: %d\n", dawgname, idx)
	  }
	},
}


func init() {
	rootCmd.AddCommand(dawgCmd)
	dawgCmd.AddCommand(dawgCompileCmd, dawgLookupCmd)

	dawgCompileCmd.Flags().StringVarP(&srcformat, "format", "", "",
						      "Format of text file, either cvs or text")
	dawgCompileCmd.Flags().StringVarP(&srcfile, "src", "", "",
						      "Name of source text file")
	dawgCompileCmd.Flags().StringVarP(&outfile, "outfile", "", "",
						      "Name of outfile, must end in \".dawg\"")
	dawgLookupCmd.Flags().StringVarP(&dawgfile, "dawg", "", "",
						      "Name of DAWG file")
	dawgLookupCmd.Flags().StringVarP(&dawgname, "name", "", "",
						      "Name to look up")
}

func CompileDawgFromCSV(srcfile, outfile string) {
     ofd, err := os.Create(outfile)
     if err != nil {
     	fmt.Printf("Error creating \"%s\": %v\n", outfile, err)
	os.Exit(1)
     }

     sortednames, err := tapir.ParseCSV(srcfile)
     if err != nil {
     	fmt.Printf("Error parsing CSV source \"%s\": %v\n", srcfile, err)
	os.Exit(1)
     }

     if tapir.GlobalCF.Debug {
         fmt.Print("Sorted list of names:\n")
     	 for _, n := range sortednames {
     	     fmt.Printf("%s\n", n)
     	 }
     }

     err = tapir.CreateDawg(sortednames, outfile)
     if err != nil {
     	fmt.Printf("Error creating DAWG \"%s\" from sorted list of names: %v\n", outfile, err)
	os.Exit(1)
     }

     ofd.Close()
}

func CompileDawgFromText(srcfile, outfile string) {
     ofd, err := os.Create(outfile)
     if err != nil {
     	fmt.Printf("Error creating \"%s\": %v\n", outfile, err)
	os.Exit(1)
     }

     sortednames, err := tapir.ParseText(srcfile)
     if err != nil {
     	fmt.Printf("Error parsing text source \"%s\": %v\n", srcfile, err)
	os.Exit(1)
     }

     if tapir.GlobalCF.Debug {
         fmt.Print("Sorted list of names:\n")
     	 for _, n := range sortednames {
     	     fmt.Printf("%s\n", n)
     	 }
     }

     err = tapir.CreateDawg(sortednames, outfile)
     if err != nil {
     	fmt.Printf("Error creating DAWG \"%s\" from sorted list of names: %v\n", outfile, err)
	os.Exit(1)
     }

     ofd.Close()
}