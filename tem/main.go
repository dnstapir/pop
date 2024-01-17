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

func mainloop(conf *Config, configfile *string) {
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, syscall.SIGINT, syscall.SIGTERM)
	hupper := make(chan os.Signal, 1)
	signal.Notify(hupper, syscall.SIGHUP)

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
				   log.Fatalf("Could not load config %s: Error: %v", viper.ConfigFileUsed(), err)
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

	fmt.Println("mainloop: leaving signal dispatcher")
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
		log.Fatalf("Could not load config %s: Error: %v", tapir.DefaultTEMCfgFile, err)
	}


	logfile := viper.GetString("log.file")
	tapir.SetupLogging(logfile)
	fmt.Printf("Logging to file: %s\n", logfile)

	ValidateConfig(nil, cfgFileUsed) // will terminate on error

	err := viper.Unmarshal(&conf)
	if err != nil {
		log.Fatalf("Error unmarshalling config into struct: %v", err)
	}

	fmt.Printf("TEM (TAPIR Edge Manager) version %s starting.\n", appVersion)

	var stopch = make(chan struct{}, 10)
	conf.Internal.RefreshZoneCh = make(chan ZoneRefresher, 10)
	conf.Internal.RpzCmdCh = make(chan RpzCmdData, 10)
	go RefreshEngine(&conf, stopch)

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

	//	dns.HandleFunc(".", createHandler(&conf))
	//	if *soreuseport > 0 {
	//		for i := 0; i < *soreuseport; i++ {
	//			go Serve(&conf, "tcp", conf.Server.Listen, conf.Server.Port, true)
	//			go Serve(&conf, "udp", conf.Server.Listen, conf.Server.Port, true)
	//		}
	//	} else {
	//		go Serve(&conf, "tcp", conf.Server.Listen, conf.Server.Port, false)
	//		go Serve(&conf, "udp", conf.Server.Listen, conf.Server.Port, false)
	//	}

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
			log.Fatalf("Illegal port specification for AXFR src: %s", portstr)
		}
		if _, ok := dns.IsDomainName(parts[0]); ok {
			ips, err := net.LookupHost(parts[0])
			if err != nil {
				log.Fatalf("Error from net.LookupHost(%s): %v", parts[0], err)
			}
			parts[0] = ips[0]
		}
		stream = net.JoinHostPort(parts[0], portstr)
	} else {
		if _, ok := dns.IsDomainName(stream); ok {
			ips, err := net.LookupHost(parts[0])
			if err != nil {
				log.Fatalf("Error from net.LookupHost(%s): %v", parts[0], err)
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
