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

	if logfile != "" {
		log.SetOutput(&lumberjack.Logger{
			Filename:   logfile,
			MaxSize:    20,
			MaxBackups: 3,
			MaxAge:     14,
		})
		fmt.Printf("TEM standard logging to: %s\n", logfile)
	} else {
		TEMExiter("Error: standard log (key log.file) not specified")
	}

	logfile = viper.GetString("policy.logfile")
	if logfile != "" {
		logfile = filepath.Clean(logfile)
		f, err := os.OpenFile(logfile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644) // #nosec: G302w
		if err != nil {
			TEMExiter("error opening TEM policy logfile '%s': %v", logfile, err)
		}

		conf.Loggers.Policy = log.New(f, "policy: ", log.Lshortfile)
		conf.Loggers.Policy.SetOutput(&lumberjack.Logger{
			Filename:   logfile,
			MaxSize:    20,
			MaxBackups: 3,
			MaxAge:     14,
		})
		fmt.Printf("TEM policy logging to: %s\n", logfile)
	} else {
		log.Println("No policy logfile specified, using default")
		conf.Loggers.Policy = log.Default()
	}

	logfile = viper.GetString("dnsengine.logfile")
	if logfile != "" {
		logfile = filepath.Clean(logfile)
		f, err := os.OpenFile(logfile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644) // #nosec: G302w
		if err != nil {
			TEMExiter("error opening TEM dnsengine logfile '%s': %v", logfile, err)
		}

		conf.Loggers.Dnsengine = log.New(f, "dnsengine: ", log.Lshortfile)
		conf.Loggers.Dnsengine.SetOutput(&lumberjack.Logger{
			Filename:   logfile,
			MaxSize:    20,
			MaxBackups: 3,
			MaxAge:     14,
		})
		fmt.Printf("TEM dnsengine logging to: %s\n", logfile)
	} else {
		log.Println("No dnsengine logfile specified, using default")
		conf.Loggers.Dnsengine = log.Default()
	}

	logfile = viper.GetString("mqtt.logfile")
	if logfile != "" {
		logfile = filepath.Clean(logfile)
		f, err := os.OpenFile(logfile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644) // #nosec: G302w
		if err != nil {
			TEMExiter("error opening TEM MQTT logfile '%s': %v", logfile, err)
		}

		conf.Loggers.Mqtt = log.New(f, "mqtt: ", log.Lshortfile)
		conf.Loggers.Mqtt.SetOutput(&lumberjack.Logger{
			Filename:   logfile,
			MaxSize:    20,
			MaxBackups: 3,
			MaxAge:     14,
		})
		fmt.Printf("TEM MQTT logging to: %s\n", logfile)
	} else {
		log.Println("No MQTT logfile specified, using default")
		conf.Loggers.Mqtt = log.Default()
	}
}
