/*
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
	"gopkg.in/natefinch/lumberjack.v2"
)

func SetupLogging(conf *Config) {
	logfile := viper.GetString("log.file")

	debug := viper.GetString("log.mode") == "debug"
	logoptions := log.Ldate | log.Ltime
	if debug {
		log.Println("Logging in debug mode (showing file and line number)")
		logoptions |= log.Lshortfile
	}

	prefix := ""

	if logfile != "" {
		log.SetOutput(&lumberjack.Logger{
			Filename:   logfile,
			MaxSize:    20,
			MaxBackups: 3,
			MaxAge:     14,
		})
		fmt.Printf("TAPIR-POP standard logging to: %s\n", logfile)
	} else {
		POPExiter("Error: standard log (key log.file) not specified")
	}

	logfile = viper.GetString("policy.logfile")
	if logfile != "" {
		logfile = filepath.Clean(logfile)
		f, err := os.OpenFile(logfile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644) // #nosec G302
		if err != nil {
			POPExiter("error opening TAPIR-POP policy logfile '%s': %v", logfile, err)
		}

		if debug {
			prefix = "policy: "
		}
		conf.Loggers.Policy = log.New(f, prefix, logoptions)
		conf.Loggers.Policy.SetOutput(&lumberjack.Logger{
			Filename:   logfile,
			MaxSize:    20,
			MaxBackups: 3,
			MaxAge:     14,
		})
		fmt.Printf("TAPIR-POP policy logging to: %s\n", logfile)
	} else {
		log.Println("No policy logfile specified, using default")
		conf.Loggers.Policy = log.Default()
	}

	logfile = viper.GetString("dnsengine.logfile")
	if logfile != "" {
		logfile = filepath.Clean(logfile)
		f, err := os.OpenFile(logfile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644) // #nosec G302
		if err != nil {
			POPExiter("error opening TAPIR-POP dnsengine logfile '%s': %v", logfile, err)
		}

		if debug {
			prefix = "dnsengine: "
		}
		conf.Loggers.Dnsengine = log.New(f, prefix, logoptions)
		conf.Loggers.Dnsengine.SetOutput(&lumberjack.Logger{
			Filename:   logfile,
			MaxSize:    20,
			MaxBackups: 3,
			MaxAge:     14,
		})
		fmt.Printf("TAPIR-POP dnsengine logging to: %s\n", logfile)
	} else {
		log.Println("No dnsengine logfile specified, using default")
		conf.Loggers.Dnsengine = log.Default()
	}

	logfile = viper.GetString("tapir.mqtt.logfile")
	if logfile != "" {
		logfile = filepath.Clean(logfile)
		f, err := os.OpenFile(logfile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644) // #nosec G302
		if err != nil {
			POPExiter("error opening TAPIR-POP MQTT logfile '%s': %v", logfile, err)
		}

		if debug {
			prefix = "mqtt: "
		}
		conf.Loggers.Mqtt = log.New(f, prefix, logoptions)
		conf.Loggers.Mqtt.SetOutput(&lumberjack.Logger{
			Filename:   logfile,
			MaxSize:    20,
			MaxBackups: 3,
			MaxAge:     14,
		})
		fmt.Printf("TAPIR-POP MQTT logging to: %s\n", logfile)
	} else {
		log.Println("No MQTT logfile specified, using default")
		conf.Loggers.Mqtt = log.Default()
	}
}
