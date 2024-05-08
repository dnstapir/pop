/*
 * Johan Stenstam, johani@johani.org
 */

package main

import (
	"log"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/spf13/viper"
)

type Config struct {
	Service   ServiceConf
	Server    ServerConf
	Apiserver ApiserverConf
	Dnsengine DnsengineConf
	Sources   map[string]SourceConf
	Policy    PolicyConf
	Log       struct {
		File    string `validate:"required"`
		Verbose *bool  `validate:"required"`
		Debug   *bool  `validate:"required"`
	}
	Internal InternalConf
	TemData  *TemData
	BootTime time.Time
}

type ServiceConf struct {
	Name string `validate:"required"`
	//	Filter           string `validate:"required"`
	Reset_Soa_Serial *bool `validate:"required"`
	Debug            *bool
	Verbose          *bool
}

type ServerConf struct {
	Listen string `validate:"required"`
	Port   string `validate:"required"`
}

type SourceConf struct {
	Active      *bool  `validate:"required"`
	Name        string `validate:"required"`
	Description string `validate:"required"`
	Type        string `validate:"required"`
	Format      string `validate:"required"`
	Source      string `validate:"required"`
	Filename    string
	Upstream    string
	Zone        string
}

type PolicyConf struct {
	Logfile   string
	Logger    *log.Logger
	Whitelist struct {
		Action string `validate:"required"`
	}
	Blacklist struct {
		Action string `validate:"required"`
	}
	Greylist GreylistConf
}

type ListConf struct {
}

type GreylistConf struct {
	NumSources struct {
		Limit  int    `validate:"required"`
		Action string `validate:"required"`
	}
	NumTapirTags struct {
		Limit  int    `validate:"required"`
		Action string `validate:"required"`
	}
	BlackTapir struct {
		Tags   []string `validate:"required"`
		Action string   `validate:"required"`
	}
}

type ApiserverConf struct {
	Address string `validate:"required"`
	Key     string `validate:"required"`
}
type DnsengineConf struct {
	Address string `validate:"required"`
	Logfile string `validate:"required"`
	Logger  *log.Logger
}

type InternalConf struct {
	// RefreshZoneCh chan RpzRefresher
	// RpzCmdCh      chan RpzCmdData
	APIStopCh chan struct{}
}

func ValidateConfig(v *viper.Viper, cfgfile string) error {
	var config Config

	if v == nil {
		if err := viper.Unmarshal(&config); err != nil {
			TEMExiter("ValidateConfig: Unmarshal error: %v", err)
		}
	} else {
		if err := v.Unmarshal(&config); err != nil {
			TEMExiter("ValidateConfig: unmarshal error: %v", err)
		}
	}

	var configsections = make(map[string]interface{}, 5)

	configsections["log"] = config.Log
	configsections["service"] = config.Service
	configsections["server"] = config.Server
	configsections["apiserver"] = config.Apiserver
	configsections["policy"] = config.Policy

	// Cannot validate a map[string]foobar, must validate the individual foobars:
	for key, val := range config.Sources {
		configsections["sources-"+key] = val
	}
	//	configsections["oldsources"] = config.OldSources

	if err := ValidateBySection(&config, configsections, cfgfile); err != nil {
		TEMExiter("Config \"%s\" is missing required attributes:\n%v\n", cfgfile, err)
	}
	return nil
}

func ValidateBySection(config *Config, configsections map[string]interface{}, cfgfile string) error {
	validate := validator.New()

	for k, data := range configsections {
		log.Printf("%s: Validating config for %s section\n", config.Service.Name, k)
		if err := validate.Struct(data); err != nil {
			log.Printf("ValidateBySection: data that caused validation to fail:\n%v\n", data)
			TEMExiter("ValidateBySection: Config %s, section %s: missing required attributes:\n%v\n",
				cfgfile, k, err)
		}
	}
	return nil
}
