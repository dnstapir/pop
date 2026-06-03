/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package main

import (
	"fmt"
	"log"

	"os"
	"os/signal"

	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/dnstapir/tapir"
)

/* Rewritten if building with make */
var name = "BAD-BUILD"
var version = "BAD-BUILD"
var commit = "BAD-BUILD"

var POPExiter = func(args ...interface{}) {
	log.Printf("POPExiter: [placeholderfunction w/o real cleanup]")
	log.Printf("POPExiter: Exit message: %s", fmt.Sprintf(args[0].(string), args[1:]...))
	os.Exit(1)
}

func (pd *PopData) SaveRpzSerial() error {
	// Save the current value of pd.Downstreams.Serial to a text file
	serialFile := viper.GetString("services.rpz.serialcache")
	if serialFile == "" {
		log.Fatalf("POPExiter:No serial cache file specified")
	}
	// serialData := []byte(fmt.Sprintf("%d", pd.Rpz.CurrentSerial))
	// err := os.WriteFile(serialFile, serialData, 0644)
	serialYaml := fmt.Sprintf("current_serial: %d\n", pd.Rpz.CurrentSerial)
	err := os.WriteFile(serialFile, []byte(serialYaml), 0644) // #nosec G306
	if err != nil {
		log.Printf("Error writing YAML serial to file: %v", err)
	} else {
		log.Printf("Saved current serial %d to file %s", pd.Rpz.CurrentSerial, serialFile)
	}
	return err
}

// reloadConfig re-reads the given config file on SIGHUP. It first reads into a
// throwaway viper so that a malformed file cannot corrupt the live global
// config; only if that succeeds does it re-read into the global viper. It
// returns an error (rather than exiting) on any failure, so the daemon keeps
// running with its existing config — an operator's config typo must never take
// POP down (#155).
//
// Note: this re-reads the primary config file only; it does not yet re-run full
// validation or re-apply sources/outputs/policy (that belongs with the larger
// config-application rework). The guarantee here is narrowly "a bad reload does
// not kill the daemon and does not corrupt the running config".
func reloadConfig(configfile string) error {
	vtmp := viper.New()
	vtmp.SetConfigFile(configfile)
	if err := vtmp.ReadInConfig(); err != nil {
		return fmt.Errorf("config file %s did not parse: %w", configfile, err)
	}
	if err := viper.ReadInConfig(); err != nil {
		// The throwaway read above succeeded, so this is unexpected.
		return fmt.Errorf("re-reading %s into live config failed: %w", configfile, err)
	}
	return nil
}

func mainloop(conf *Config, configfile *string, pd *PopData) {
	log.Println("mainloop: enter")
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, syscall.SIGINT, syscall.SIGTERM)
	hupper := make(chan os.Signal, 1)
	signal.Notify(hupper, syscall.SIGHUP)

	POPExiter = func(args ...interface{}) {
		var msg string
		log.Printf("POPExiter: will try to clean up.")

		err := pd.SaveRpzSerial()
		if err != nil {
			log.Printf("Error saving RPZ serial: %v", err)
		}

		switch args[0].(type) {
		case string:
			msg = fmt.Sprintf("POPExiter: Exit message: %s",
				fmt.Sprintf(args[0].(string), args[1:]...))
		case error:
			msg = fmt.Sprintf("POPExiter: Error message: %s", args[0].(error).Error())

		default:
			msg = fmt.Sprintf("POPExiter: Exit message: %v", args[0])
		}

		fmt.Println(msg)
		log.Println(msg)

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
				err := pd.SaveRpzSerial()
				if err != nil {
					log.Printf("Error saving RPZ serial: %v", err)
				}
				// do whatever we need to do to wrap up nicely
				wg.Done()
				// Stop dispatching: we are shutting down. Returning here also
				// guarantees wg.Done() is called exactly once even if another
				// shutdown signal (e.g. APIStopCh) arrives concurrently —
				// otherwise the loop would Done() again and panic the
				// WaitGroup with a negative counter. (#159)
				return
			case <-hupper:
				// SIGHUP: reload config, but NEVER let a bad config file take
				// down a running daemon (#155).
				if err := reloadConfig(*configfile); err != nil {
					log.Printf("mainloop: SIGHUP: reload of %s failed (%v); keeping running config unchanged", *configfile, err)
					continue
				}
				fmt.Fprintln(os.Stderr, "Reloaded config file:", *configfile)
				log.Println("mainloop: SIGHUP received. Forcing refresh of all configured zones.")
				conf.PopData.RpzRefreshCh <- RpzRefresh{Name: ""}
			case <-conf.Internal.APIStopCh:
				log.Printf("mainloop: API instruction to stop\n")
				err := pd.SaveRpzSerial()
				if err != nil {
					log.Printf("Error saving RPZ serial: %v", err)
				}
				wg.Done()
				return // see #159 note in the exit case
			}
		}
	}()
	wg.Wait()

	log.Println("mainloop: leaving signal dispatcher")
}

var Gconfig Config
var mqttclientid string

func main() {
	fmt.Printf("%s (TAPIR Edge Manager) version %s (%s) starting.\n", name, version, commit)
	// var conf Config
	mqttclientid = "tapir-pop-" + uuid.New().String()
	flag.BoolVarP(&tapir.GlobalCF.Debug, "debug", "d", false, "Debug mode")
	flag.BoolVarP(&tapir.GlobalCF.Verbose, "verbose", "v", false, "Verbose mode")
	flag.StringVarP(&mqttclientid, "client-id", "", mqttclientid, "MQTT client id, default is a random string")

	flag.Parse()

	var cfgFileUsed string

	var cfgFile string
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigFile(tapir.DefaultPopCfgFile)
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
		cfgFileUsed = viper.ConfigFileUsed()
	} else {
		POPExiter("Could not load config %s: Error: %v", tapir.DefaultPopCfgFile, err)
	}
	viper.SetConfigFile(tapir.PopSourcesCfgFile)
	if err := viper.MergeInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
		cfgFileUsed = viper.ConfigFileUsed()
	} else {
		POPExiter("Could not load config %s: Error: %v", tapir.PopSourcesCfgFile, err)
	}
	viper.SetConfigFile(tapir.PopOutputsCfgFile)
	if err := viper.MergeInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
		cfgFileUsed = viper.ConfigFileUsed()
	} else {
		POPExiter("Could not load config %s: Error: %v", tapir.PopOutputsCfgFile, err)
	}
	viper.SetConfigFile(tapir.PopPolicyCfgFile)
	if err := viper.MergeInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
		cfgFileUsed = viper.ConfigFileUsed()
	} else {
		POPExiter("Could not load config %s: Error: %v", tapir.PopPolicyCfgFile, err)
	}

	SetupLogging(&Gconfig)

	err := ValidateConfig(nil, cfgFileUsed) // will terminate on error
	if err != nil {
		POPExiter("Error validating config: %v", err)
	}

	err = viper.Unmarshal(&Gconfig)
	if err != nil {
		POPExiter("Error unmarshalling config into struct: %v", err)
	}

	var stopch = make(chan struct{}, 10)

	statusch := make(chan tapir.ComponentStatusUpdate, 10)
	Gconfig.Internal.ComponentStatusCh = statusch

	pd, err := NewPopData(&Gconfig, log.Default())
	if err != nil {
		POPExiter("Error from NewPopData: %v", err)
	}

	if pd.MqttEngine == nil {
		pd.mu.Lock()
		err := pd.CreateMqttEngine(mqttclientid, statusch, pd.MqttLogger)
		if err != nil {
			POPExiter("Error creating MQTT Engine: %v", err)
		}
		pd.mu.Unlock()
		err = pd.StartMqttEngine(pd.MqttEngine)
		if err != nil {
			POPExiter("Error starting MQTT Engine: %v", err)
		}
	}

	go pd.ConfigUpdater(&Gconfig, stopch) // Note that ConfigUpdater must as early as possible
	go pd.StatusUpdater(&Gconfig, stopch) // Note that StatusUpdater must as early as possible
	go pd.RefreshEngine(&Gconfig, stopch)

	log.Println("*** main: Calling ParseSourcesNG()")
	err = pd.ParseSourcesNG()
	if err != nil {
		POPExiter("Error from ParseSourcesNG: %v", err)
	}
	log.Println("*** main: Returned from ParseSourcesNG()")

	err = pd.ParseOutputs()
	if err != nil {
		POPExiter("Error from ParseOutputs: %v", err)
	}

	apistopper := make(chan struct{}) //
	Gconfig.Internal.APIStopCh = apistopper
	go APIhandler(&Gconfig, apistopper)
	//	go httpsserver(&conf, apistopper)

	go func() {
		if err := DnsEngine(&Gconfig); err != nil {
			log.Printf("Error starting DnsEngine: %v", err)
		}
	}()
	Gconfig.BootTime = time.Now()

	statusch <- tapir.ComponentStatusUpdate{
		Component: "main-boot",
		Status:    tapir.StatusOK,
		Msg:       "TAPIR Policy Processor started",
		TimeStamp: time.Now(),
	}

	mainloop(&Gconfig, &cfgFileUsed, pd)
}
