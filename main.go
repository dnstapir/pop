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

// loadAllConfig loads POP's full config into v: the primary config file
// followed by a merge of the sources, outputs and policy files. It returns the
// last config file touched (for diagnostics) and an error on any failure. Both
// startup (main) and SIGHUP reload (reloadConfig) use it, so the reload reads
// exactly the same set of files, in the same order, as startup.
func loadAllConfig(v *viper.Viper) (string, error) {
	var used string
	steps := []struct {
		file  string
		merge bool // false = ReadInConfig (primary), true = MergeInConfig
	}{
		{tapir.DefaultPopCfgFile, false},
		{tapir.PopSourcesCfgFile, true},
		{tapir.PopOutputsCfgFile, true},
		{tapir.PopPolicyCfgFile, true},
	}
	for _, s := range steps {
		v.SetConfigFile(s.file)
		var err error
		if s.merge {
			err = v.MergeInConfig()
		} else {
			err = v.ReadInConfig()
		}
		if err != nil {
			return used, fmt.Errorf("could not load config %s: %w", s.file, err)
		}
		used = v.ConfigFileUsed()
	}
	return used, nil
}

// reloadConfig re-reads POP's full config on SIGHUP. It loads AND validates into
// a THROWAWAY viper first, so a malformed or invalid config cannot corrupt the
// live global config or take down a running daemon — an operator's config typo
// must never kill POP (#155). Only once the new config loads and validates does
// it re-apply the same load sequence to the global viper. It returns an error
// (never exits) on any failure, leaving the running config unchanged.
//
// Caveat: the global viper is read concurrently by other goroutines, so the
// final re-apply is still a concurrent mutation of shared config state — the
// pre-existing config-access race (design doc §5 / #157), out of scope here.
// What this guarantees: a bad reload neither kills the daemon nor replaces the
// good config with a broken one.
func reloadConfig(configfile string) error {
	vtmp := viper.New()
	if _, err := loadAllConfig(vtmp); err != nil {
		return fmt.Errorf("reload rejected, keeping running config: %w", err)
	}
	if err := ValidateConfig(vtmp, configfile); err != nil {
		return fmt.Errorf("reload rejected, keeping running config: %w", err)
	}
	// New config is valid; re-apply the same load sequence to the global viper.
	if _, err := loadAllConfig(viper.GetViper()); err != nil {
		// Unexpected: the throwaway load just succeeded.
		return fmt.Errorf("re-applying validated config to live viper failed: %w", err)
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

	viper.AutomaticEnv() // read in environment variables that match

	// Load the full config (primary + merged sources/outputs/policy). At
	// startup a load failure is genuinely fatal, so we POPExit on error here;
	// the same loadAllConfig() is reused by reloadConfig() on SIGHUP, where it
	// is non-fatal.
	cfgFileUsed, err := loadAllConfig(viper.GetViper())
	if err != nil {
		POPExiter("Error loading config: %v", err)
	}
	fmt.Fprintln(os.Stderr, "Using config file:", cfgFileUsed)

	SetupLogging(&Gconfig)

	if err := ValidateConfig(nil, cfgFileUsed); err != nil { // fatal at startup
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
