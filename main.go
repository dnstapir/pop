/*
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package main

import (
	"flag"
	"fmt"
	"log"
	//	"net"
	"os"
	"os/signal"
	//	"strconv"
	//	"strings"
	"sync"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"
	//	"github.com/miekg/dns"
	"github.com/spf13/viper"
	_ "unsafe" // to use constants from linker

	"github.com/dnstapir/tapir"
)

var (
	soreuseport = flag.Int("soreuseport", 0, "use SO_REUSE_PORT")
)

var TEMExiter = func(args ...interface{}) {
	log.Printf("TEMExiter: [placeholderfunction w/o real cleanup]")
	log.Printf("TEMExiter: Exit message: %s", fmt.Sprintf(args[0].(string), args[1:]...))
	os.Exit(1)
}

func mainloop(conf *Config, configfile *string) {
	log.Println("mainloop: enter")
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, syscall.SIGINT, syscall.SIGTERM)
	hupper := make(chan os.Signal, 1)
	signal.Notify(hupper, syscall.SIGHUP)

	TEMExiter = func(args ...interface{}) {
		var msg string
		log.Printf("TEMExiter: will try to clean up.")

		switch args[0].(type) {
		case string:
			msg = fmt.Sprintf("TEMExiter: Exit message: %s",
				fmt.Sprintf(args[0].(string), args[1:]...))
		case error:
			msg = fmt.Sprintf("TEMExiter: Error message: %s", args[0].(error).Error())

		default:
			msg = fmt.Sprintf("TEMExiter: Exit message: %v", args[0])
		}

		fmt.Println(msg)
		log.Printf(msg)

		// var done struct{}
		// apistopper <- done
		os.Exit(1)
	}

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		for {
			// log.Println("mainloop: signal dispatcher")
			select {
			case <-exit:
				log.Println("mainloop: Exit signal received. Cleaning up.")
				// do whatever we need to do to wrap up nicely
				wg.Done()
			case <-hupper:
				// config file to use has already been set in main()
				if err := viper.ReadInConfig(); err == nil {
					fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
				} else {
					TEMExiter("Could not load config %s: Error: %v", viper.ConfigFileUsed(), err)
				}

				log.Println("mainloop: SIGHUP received. Forcing refresh of all configured zones.")
				log.Printf("mainloop: Requesting refresh of all RPZ zones")
				conf.TemData.RpzRefreshCh <- RpzRefresh{Name: ""}
			}
		}
	}()
	wg.Wait()

	log.Println("mainloop: leaving signal dispatcher")
}

func main() {
	var conf Config
	var cfgFileUsed string

	var cfgFile string
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigFile(tapir.DefaultTemCfgFile)
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
		cfgFileUsed = viper.ConfigFileUsed()
	} else {
		TEMExiter("Could not load config %s: Error: %v", tapir.DefaultTemCfgFile, err)
	}
	viper.SetConfigFile(tapir.TemSourcesCfgFile)
	if err := viper.MergeInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
		cfgFileUsed = viper.ConfigFileUsed()
	} else {
		TEMExiter("Could not load config %s: Error: %v", tapir.TemSourcesCfgFile, err)
	}
	viper.SetConfigFile(tapir.TemPolicyCfgFile)
	if err := viper.MergeInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
		cfgFileUsed = viper.ConfigFileUsed()
	} else {
		TEMExiter("Could not load config %s: Error: %v", tapir.TemPolicyCfgFile, err)
	}

	logfile := viper.GetString("log.file")
	tapir.SetupLogging(logfile)
	fmt.Printf("Logging to file: %s\n", logfile)

	ValidateConfig(nil, cfgFileUsed) // will terminate on error

	err := viper.Unmarshal(&conf)
	if err != nil {
		TEMExiter("Error unmarshalling config into struct: %v", err)
	}

	fmt.Printf("TEM (TAPIR Edge Manager) version %s starting.\n", appVersion)

	var stopch = make(chan struct{}, 10)

	td, err := NewTemData(&conf, log.Default())
	if err != nil {
		TEMExiter("Error from NewTemData: %v", err)
	}
	go td.RefreshEngine(&conf, stopch)
	err = td.ParseSources()
	if err != nil {
		TEMExiter("Error from ParseSources: %v", err)
	}

	apistopper := make(chan struct{}) //
	// conf.Internal.APIStopCh = apistopper
	go APIdispatcher(&conf, apistopper)

	go DnsEngine(&conf)
	conf.BootTime = time.Now()

	mainloop(&conf, &cfgFileUsed)
}

// func ParseUpDownStreams(stream string) string {
// 	parts := strings.Split(stream, ":")
// 	if len(parts) > 1 {
// 		portstr := parts[len(parts)-1]
// 		_, err := strconv.Atoi(portstr)
// 		if err != nil {
// 			TEMExiter("Illegal port specification for AXFR src: %s", portstr)
// 		}
// 		if _, ok := dns.IsDomainName(parts[0]); ok {
// 			ips, err := net.LookupHost(parts[0])
// 			if err != nil {
// 				TEMExiter("Error from net.LookupHost(%s): %v", parts[0], err)
// 			}
// 			parts[0] = ips[0]
// 		}
// 		stream = net.JoinHostPort(parts[0], portstr)
// 	} else {
// 		if _, ok := dns.IsDomainName(stream); ok {
// 			ips, err := net.LookupHost(parts[0])
// 			if err != nil {
// 				TEMExiter("Error from net.LookupHost(%s): %v", parts[0], err)
// 			}
// 			parts[0] = ips[0]
// 		}
// 		stream = net.JoinHostPort(parts[0], "53")
// 	}
// 	return stream
// }
