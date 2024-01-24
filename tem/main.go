/*
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"

	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
	_ "unsafe" // to use constants from linker

	"github.com/dnstapir/tapir-em/tapir"
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
				all_zones := viper.GetStringSlice("server.xferzones")
				for _, zone := range all_zones {
					zone = dns.Fqdn(zone)
					log.Printf("mainloop: Requesting refresh of %s", zone)
					conf.Internal.RefreshZoneCh <- ZoneRefresher{Name: zone, ZoneType: 1}
				}
				all_zones = viper.GetStringSlice("server.fullzones")
				for _, zone := range all_zones {
					zone = dns.Fqdn(zone)
					log.Printf("mainloop: Requesting refresh of %s", zone)
					conf.Internal.RefreshZoneCh <- ZoneRefresher{Name: zone, ZoneType: 2}
				}
			}
		}
	}()
	wg.Wait()

	log.Println("mainloop: leaving signal dispatcher")
}

func main() {
	var conf Config
	var cfgFileUsed string

	cfgFile := "/etc/dnstapir/tem.yaml"
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigFile(tapir.DefaultTEMCfgFile)
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
		cfgFileUsed = viper.ConfigFileUsed()
	} else {
		TEMExiter("Could not load config %s: Error: %v", tapir.DefaultTEMCfgFile, err)
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

	td, err := NewTemData(log.Default())
	if err != nil {
	   TEMExiter("Error from NewTemData: %v", err)
	}

	var stopch = make(chan struct{}, 10)
	conf.Internal.RefreshZoneCh = make(chan ZoneRefresher, 10)
	conf.Internal.RpzCmdCh = make(chan RpzCmdData, 10)
	go td.RefreshEngine(&conf, stopch)

	var keepfunc_name = viper.GetString("service.filter")

	var all_zones []string

	// ZoneType=1 (xferzones) are limited to only support ops related to zone transfers
	// i.e. no support for arbitrary queries, dnssec_ok flags, etc.
	for _, zone := range viper.GetStringSlice("server.xferzones") {
		all_zones = append(all_zones, zone)
		conf.Internal.RefreshZoneCh <- ZoneRefresher{
			Name:     dns.Fqdn(zone),
			ZoneType: 1,
		}
	}

	// ZoneType=2 stores the zone data in a map[string]OwnerData.
	for _, zone := range viper.GetStringSlice("server.mapzones") {
		all_zones = append(all_zones, zone)
		conf.Internal.RefreshZoneCh <- ZoneRefresher{
			Name:     dns.Fqdn(zone),
			ZoneType: 2,
		}
	}

	// ZoneType=3 stores the zone data in a []OwnerData with precomputed
	// index entrypoints for different owner names.
	for _, zone := range viper.GetStringSlice("server.slicezones") {
		all_zones = append(all_zones, zone)
		conf.Internal.RefreshZoneCh <- ZoneRefresher{
			Name:     dns.Fqdn(zone),
			ZoneType: 3,
		}
	}

	log.Printf("All configured zones now refreshing (using filter: %s): %v", keepfunc_name, all_zones)

	apistopper := make(chan struct{}) //
	// conf.Internal.APIStopCh = apistopper
	go APIdispatcher(&conf, apistopper)

	//	conf.Internal.ScannerQ = make(chan ScanRequest, 5)
	//	conf.Internal.UpdateQ = make(chan UpdateRequest, 5)

	//	go ScannerEngine(&conf)
	//	go UpdaterEngine(&conf)
	go DnsEngine(&conf)

	for _, n := range []string{ "facebook.com", "facebook.com.", "netnod.se", "www.netnod.se", "xyzzynniohiyfhe.com" } {
 	    if td.Whitelisted(n) {
	       fmt.Printf("The name \"%s\" is whitelisted\n", n)
	    } else {
	       fmt.Printf("The name \"%s\" is NOT whitelisted\n", n)
	    }
	}

	mainloop(&conf, &cfgFileUsed)
}

func GetUpstream(zone string) string {
	var upstream string
	upstreamaddrs := viper.GetStringSlice("server.upstreams")
	if len(upstreamaddrs) > 0 {
		upstream = upstreamaddrs[0]
	}

	return ParseUpDownStreams(upstream)
}

func GetDownstreams(zone string) []string {
	downstreams := viper.GetStringSlice("server.downstreams")

	var ds_parsed []string

	for _, ds := range downstreams {
		ds_parsed = append(ds_parsed, ParseUpDownStreams(ds))
	}

	return ds_parsed
}

func ParseUpDownStreams(stream string) string {
	parts := strings.Split(stream, ":")
	if len(parts) > 1 {
		portstr := parts[len(parts)-1]
		_, err := strconv.Atoi(portstr)
		if err != nil {
			TEMExiter("Illegal port specification for AXFR src: %s", portstr)
		}
		if _, ok := dns.IsDomainName(parts[0]); ok {
			ips, err := net.LookupHost(parts[0])
			if err != nil {
				TEMExiter("Error from net.LookupHost(%s): %v", parts[0], err)
			}
			parts[0] = ips[0]
		}
		stream = net.JoinHostPort(parts[0], portstr)
	} else {
		if _, ok := dns.IsDomainName(stream); ok {
			ips, err := net.LookupHost(parts[0])
			if err != nil {
				TEMExiter("Error from net.LookupHost(%s): %v", parts[0], err)
			}
			parts[0] = ips[0]
		}
		stream = net.JoinHostPort(parts[0], "53")
	}
	return stream
}

type ZoneRefresher struct {
	Name     string
	ZoneType uint8 // 1=xfr, 2=map, 3=slice
}
