/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package main

import (
	"log"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/spf13/viper"

	"github.com/dnstapir/tapir"
)

type Config struct {
	Services        ServicesConf
	ApiServer       ApiserverConf
	DnsEngine       DnsengineConf
	BootstrapServer BootstrapServerConf
    KeyStore        KeystoreConf
	Sources         map[string]SourceConf
	Policy          PolicyConf
	Log             struct {
		File    string `validate:"required"`
		Verbose *bool  `validate:"required"`
		Debug   *bool  `validate:"required"`
	}
	Loggers struct {
		Mqtt      *log.Logger
		Dnsengine *log.Logger
		Policy    *log.Logger
	}
	Internal InternalConf
	PopData  *PopData
	BootTime time.Time
}

type ServicesConf struct {
	Rpz struct {
		ZoneName    string `validate:"required"`
		SerialCache string `validate:"required"`
	}

	Reaper struct {
		Interval int `validate:"required"`
	}
}

type ApiserverConf struct {
	Active       *bool    `validate:"required"`
	Name         string   `validate:"required"`
	Key          string   `validate:"required"`
	Addresses    []string `validate:"required"`
	TlsAddresses []string `validate:"required"`
}

type DnsengineConf struct {
	Active    *bool    `validate:"required"`
	Name      string   `validate:"required"`
	Addresses []string `validate:"required"`
	Logfile   string   `validate:"required"`
	// Logger  *log.Logger
}

type BootstrapServerConf struct {
	Active       *bool    `validate:"required"`
	Name         string   `validate:"required"`
	Addresses    []string `validate:"required"`
	TlsAddresses []string `validate:"required"`
	Logfile      string
}

type ServerConf struct {
	Listen string `validate:"required"`
	Port   string `validate:"required"`
}

type KeystoreConf struct {
    Path string `validate:"required,file"`
}

type SourceConf struct {
	Active       *bool  `validate:"required"`
	Name         string `validate:"required"`
	Description  string `validate:"required"`
	Type         string `validate:"required"`
	Format       string `validate:"required"`
	Source       string `validate:"required"`
    Immutable    bool
	Topic        string
	ValidatorKey string
	Bootstrap    []string
	BootstrapUrl string
	BootstrapKey string
	Filename     string
	Upstream     string
	Zone         string
    BackupFile   string
}

type PolicyConf struct {
	Logfile string
	//	Logger    *log.Logger
	Allowlist struct {
		Action string `validate:"required"`
	}
	Denylist struct {
		Action string `validate:"required"`
	}
	Doubtlist DoubtlistConf
}

type ListConf struct {
}

type DoubtlistConf struct {
	NumSources struct {
		Limit  int    `validate:"required"`
		Action string `validate:"required"`
	}
	NumTapirTags struct {
		Limit  int    `validate:"required"`
		Action string `validate:"required"`
	}
	DenyTapir struct {
		Tags   []string `validate:"required"`
		Action string   `validate:"required"`
	}
}

type InternalConf struct {
	// RefreshZoneCh chan RpzRefresher
	// RpzCmdCh      chan RpzCmdData
	APIStopCh         chan struct{}
	ComponentStatusCh chan tapir.ComponentStatusUpdate
}

func ValidateConfig(v *viper.Viper, cfgfile string) error {
	var config Config

	if v == nil {
		if err := viper.Unmarshal(&config); err != nil {
			POPExiter("ValidateConfig: Unmarshal error: %v", err)
		}
	} else {
		if err := v.Unmarshal(&config); err != nil {
			POPExiter("ValidateConfig: Unmarshal error: %v", err)
		}
	}

	var configsections = make(map[string]interface{}, 5)

	configsections["log"] = config.Log
	configsections["services"] = config.Services
	// configsections["server"] = config.Server
	configsections["apiserver"] = config.ApiServer
	configsections["dnsengine"] = config.DnsEngine
	configsections["bootstrapserver"] = config.BootstrapServer
	configsections["policy"] = config.Policy

	// Cannot validate a map[string]foobar, must validate the individual foobars:
	for key, val := range config.Sources {
		configsections["sources-"+key] = val
	}
	//	configsections["oldsources"] = config.OldSources

	if err := ValidateBySection(&config, configsections, cfgfile); err != nil {
		POPExiter("Config \"%s\" is missing required attributes:\n%v\n", cfgfile, err)
	}
	return nil
}

func ValidateBySection(config *Config, configsections map[string]interface{}, cfgfile string) error {
	validate := validator.New()

	for k, data := range configsections {
		switch data := data.(type) {
		case *SourceConf:
			log.Printf("%s: Validating config for source %s", data.Name, k)
		case *DnsengineConf, *ApiserverConf, *BootstrapServerConf:
			//		log.Printf("%s: Validating config for service %s", data.Name, k)
		}
		if err := validate.Struct(data); err != nil {
			log.Printf("ValidateBySection: data that caused validation to fail:\n%v\n", data)
			POPExiter("ValidateBySection: Config %s, section %s: missing required attributes:\n%v\n", cfgfile, k, err)
		}
	}
	return nil
}
