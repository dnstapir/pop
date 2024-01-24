/*
 * Johan Stenstam, johani@johani.org
 */

package main

import (
	"log"

	"github.com/go-playground/validator/v10"
	"github.com/spf13/viper"
)

type Config struct {
	Service   ServiceConf
	Server    ServerConf
	Apiserver ApiserverConf
	Sources	  []SourceConf
	Log       struct {
		File string `validate:"required"`
	}
	Internal InternalConf
}

type ServiceConf struct {
	Name             string `validate:"required"`
	Filter           string `validate:"required"`
	Reset_Soa_Serial *bool  `validate:"required"`
	Debug            *bool
	Verbose          *bool
}

type ServerConf struct {
	Listen      string   `validate:"required"`
	Port        string   `validate:"required"`
	Upstreams   []string `validate:"required"`
	Downstreams []string `validate:"required"`
	//     Zones	   []string		`validate:"required"`
	XferZones  []string `validate:"required"`
	MapZones   []string `validate:"required"`
	SliceZones []string `validate:"required"`
}

type SourceConf struct {
        Name	        string	`validate:"required"`
	Description	string	`validate:"required"`
	Type		string	`validate:"required"`
	Format		string	`validate:"required"`
	Source		string	`validate:"required"`
	Filename	string
}

type ApiserverConf struct {
	Address string `validate:"required"`
	Key     string `validate:"required"`
}

type InternalConf struct {
	RefreshZoneCh chan ZoneRefresher
	RpzCmdCh      chan RpzCmdData
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

	configsections["log"] = config.Server
	configsections["service"] = config.Server
	configsections["server"] = config.Server
	configsections["apiserver"] = config.Apiserver

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
			TEMExiter("Config %s, section %s: missing required attributes:\n%v\n",
				cfgfile, k, err)
		}
	}
	return nil
}
