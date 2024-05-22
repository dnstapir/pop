/*
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package main

import (
	"flag"
	"fmt"
	"log"

	"os"
	"os/signal"

	"sync"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"

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

func (td *TemData) SaveRpzSerial() error {
	// Save the current value of td.Downstreams.Serial to a text file
	serialFile := viper.GetString("output.rpz.serialcache")
	if serialFile == "" {
		log.Fatalf("TEMExiter:No serial cache file specified")
	}
	serialData := []byte(fmt.Sprintf("%d", td.Rpz.CurrentSerial))
	err := os.WriteFile(serialFile, serialData, 0644)
	if err != nil {
		log.Printf("Error writing current serial to file: %v", err)
	} else {
		log.Printf("Saved current serial %d to file %s", td.Downstreams.Serial, serialFile)
	}
	return err
}

func mainloop(conf *Config, configfile *string, td *TemData) {
	log.Println("mainloop: enter")
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, syscall.SIGINT, syscall.SIGTERM)
	hupper := make(chan os.Signal, 1)
	signal.Notify(hupper, syscall.SIGHUP)

	TEMExiter = func(args ...interface{}) {
		var msg string
		log.Printf("TEMExiter: will try to clean up.")

		td.SaveRpzSerial()

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
				td.SaveRpzSerial()
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
			case <-conf.Internal.APIStopCh:
				log.Printf("mainloop: API instruction to stop\n")
				td.SaveRpzSerial()
				wg.Done()
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
	viper.SetConfigFile(tapir.TemOutputsCfgFile)
	if err := viper.MergeInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
		cfgFileUsed = viper.ConfigFileUsed()
	} else {
		TEMExiter("Could not load config %s: Error: %v", tapir.TemOutputsCfgFile, err)
	}
	viper.SetConfigFile(tapir.TemPolicyCfgFile)
	if err := viper.MergeInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
		cfgFileUsed = viper.ConfigFileUsed()
	} else {
		TEMExiter("Could not load config %s: Error: %v", tapir.TemPolicyCfgFile, err)
	}

	// logfile := viper.GetString("log.file")
	SetupLogging(&conf)
	fmt.Printf("Policy Logging to logger: %v\n", conf.Loggers.Policy)

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

	log.Println("*** main: Calling ParseSourcesNG()")
	err = td.ParseSourcesNG()
	if err != nil {
		TEMExiter("Error from ParseSourcesNG: %v", err)
	}
	log.Println("*** main: Returned from ParseSourcesNG()")

	err = td.ParseOutputs()
	if err != nil {
		TEMExiter("Error from ParseOutputs: %v", err)
	}

	apistopper := make(chan struct{}) //
	conf.Internal.APIStopCh = apistopper
	go APIdispatcher(&conf, apistopper)
	//	go httpsserver(&conf, apistopper)

	go DnsEngine(&conf)
	conf.BootTime = time.Now()

	mainloop(&conf, &cfgFileUsed, td)
}
