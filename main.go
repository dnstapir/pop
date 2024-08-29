/*
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
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

	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"

	"github.com/dnstapir/tapir"
)

var TEMExiter = func(args ...interface{}) {
	log.Printf("TEMExiter: [placeholderfunction w/o real cleanup]")
	log.Printf("TEMExiter: Exit message: %s", fmt.Sprintf(args[0].(string), args[1:]...))
	os.Exit(1)
}

func (td *TemData) SaveRpzSerial() error {
	// Save the current value of td.Downstreams.Serial to a text file
	serialFile := viper.GetString("services.rpz.serialcache")
	if serialFile == "" {
		log.Fatalf("TEMExiter:No serial cache file specified")
	}
	// serialData := []byte(fmt.Sprintf("%d", td.Rpz.CurrentSerial))
	// err := os.WriteFile(serialFile, serialData, 0644)
	serialYaml := fmt.Sprintf("current_serial: %d\n", td.Rpz.CurrentSerial)
	err := os.WriteFile(serialFile, []byte(serialYaml), 0644) // #nosec G306
	if err != nil {
		log.Printf("Error writing YAML serial to file: %v", err)
	} else {
		log.Printf("Saved current serial %d to file %s", td.Rpz.CurrentSerial, serialFile)
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

		err := td.SaveRpzSerial()
		if err != nil {
			log.Printf("Error saving RPZ serial: %v", err)
		}

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
				err := td.SaveRpzSerial()
				if err != nil {
					log.Printf("Error saving RPZ serial: %v", err)
				}
				// do whatever we need to do to wrap up nicely
				wg.Done()
			case <-hupper:
				// config file to use has already been set in main()
				if err := viper.ReadInConfig(); err == nil {
					fmt.Fprintln(os.Stderr, "Using config file:", *configfile)
				} else {
					TEMExiter("Could not load config %s: Error: %v", *configfile, err)
				}

				log.Println("mainloop: SIGHUP received. Forcing refresh of all configured zones.")
				log.Printf("mainloop: Requesting refresh of all RPZ zones")
				conf.TemData.RpzRefreshCh <- RpzRefresh{Name: ""}
			case <-conf.Internal.APIStopCh:
				log.Printf("mainloop: API instruction to stop\n")
				err := td.SaveRpzSerial()
				if err != nil {
					log.Printf("Error saving RPZ serial: %v", err)
				}
				wg.Done()
			}
		}
	}()
	wg.Wait()

	log.Println("mainloop: leaving signal dispatcher")
}

var Gconfig Config

func main() {
	// var conf Config
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
		TEMExiter("Could not load config %s: Error: %v", tapir.DefaultPopCfgFile, err)
	}
	viper.SetConfigFile(tapir.PopSourcesCfgFile)
	if err := viper.MergeInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
		cfgFileUsed = viper.ConfigFileUsed()
	} else {
		TEMExiter("Could not load config %s: Error: %v", tapir.PopSourcesCfgFile, err)
	}
	viper.SetConfigFile(tapir.PopOutputsCfgFile)
	if err := viper.MergeInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
		cfgFileUsed = viper.ConfigFileUsed()
	} else {
		TEMExiter("Could not load config %s: Error: %v", tapir.PopOutputsCfgFile, err)
	}
	viper.SetConfigFile(tapir.PopPolicyCfgFile)
	if err := viper.MergeInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
		cfgFileUsed = viper.ConfigFileUsed()
	} else {
		TEMExiter("Could not load config %s: Error: %v", tapir.PopPolicyCfgFile, err)
	}

	SetupLogging(&Gconfig)

	err := ValidateConfig(nil, cfgFileUsed) // will terminate on error
	if err != nil {
		TEMExiter("Error validating config: %v", err)
	}

	err = viper.Unmarshal(&Gconfig)
	if err != nil {
		TEMExiter("Error unmarshalling config into struct: %v", err)
	}

	fmt.Printf("%s (TAPIR Edge Manager) version %s (%s) starting.\n", appName, appVersion, appDate)

	var stopch = make(chan struct{}, 10)

	td, err := NewTemData(&Gconfig, log.Default())
	if err != nil {
		TEMExiter("Error from NewTemData: %v", err)
	}

	if td.MqttEngine == nil {
		td.mu.Lock()
		err := td.CreateMqttEngine(viper.GetString("tapir.mqtt.clientid"), td.MqttLogger)
		if err != nil {
			TEMExiter("Error creating MQTT Engine: %v", err)
		}
		td.mu.Unlock()
		err = td.StartMqttEngine(td.MqttEngine)
		if err != nil {
			TEMExiter("Error starting MQTT Engine: %v", err)
		}
	}

	go td.StatusUpdater(&Gconfig, stopch) // Note that StatusUpdater must as early as possible
	go td.RefreshEngine(&Gconfig, stopch)

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
	Gconfig.Internal.APIStopCh = apistopper
	go APIhandler(&Gconfig, apistopper)
	//	go httpsserver(&conf, apistopper)

	go func() {
		if err := DnsEngine(&Gconfig); err != nil {
			log.Printf("Error starting DnsEngine: %v", err)
		}
	}()
	Gconfig.BootTime = time.Now()

	mainloop(&Gconfig, &cfgFileUsed, td)
}
