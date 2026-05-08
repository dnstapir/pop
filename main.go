/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package pop

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/dnstapir/tapir"
	"github.com/google/uuid"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type RunOptions struct {
	Name    string
	Version string
	Commit  string
	Args    []string
	Stdout  io.Writer
	Stderr  io.Writer
	Reload  <-chan struct{}
}

func (pd *PopData) SaveRpzSerial() error {
	serialFile := viper.GetString("services.rpz.serialcache")
	if serialFile == "" {
		return fmt.Errorf("no serial cache file specified")
	}

	serialYaml := fmt.Sprintf("current_serial: %d\n", pd.Rpz.CurrentSerial)
	err := os.WriteFile(serialFile, []byte(serialYaml), 0644) // #nosec G306
	if err != nil {
		log.Printf("Error writing YAML serial to file: %v", err)
	} else {
		log.Printf("Saved current serial %d to file %s", pd.Rpz.CurrentSerial, serialFile)
	}
	return err
}

func Run(ctx context.Context, opts RunOptions) (runErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	stdout := opts.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	stderr := opts.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	name := opts.Name
	if name == "" {
		name = "dnstapir-pop"
	}
	version := opts.Version
	if version == "" {
		version = "BAD-BUILD"
	}
	commit := opts.Commit
	if commit == "" {
		commit = "BAD-BUILD"
	}

	fmt.Fprintf(stdout, "%s (TAPIR Edge Manager) version %s (%s) starting.\n", name, version, commit)

	mqttClientID := "tapir-pop-" + uuid.New().String()
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVarP(&tapir.GlobalCF.Debug, "debug", "d", false, "Debug mode")
	fs.BoolVarP(&tapir.GlobalCF.Verbose, "verbose", "v", false, "Verbose mode")
	fs.StringVar(&mqttClientID, "client-id", mqttClientID, "MQTT client id, default is a random string")
	if err := fs.Parse(opts.Args); err != nil {
		return err
	}

	cfgFileUsed, err := loadConfigFiles(stderr)
	if err != nil {
		return err
	}

	if err := ValidateConfig(nil, cfgFileUsed); err != nil {
		return fmt.Errorf("error validating config: %w", err)
	}

	var conf Config
	if err := viper.Unmarshal(&conf); err != nil {
		return fmt.Errorf("error unmarshalling config into struct: %w", err)
	}

	if err := SetupLogging(&conf); err != nil {
		return err
	}

	statusch := make(chan tapir.ComponentStatusUpdate, 10)
	conf.Internal.ComponentStatusCh = statusch
	conf.Internal.APIStopCh = make(chan struct{}, 1)

	pd, err := NewPopData(&conf, log.Default())
	if err != nil {
		return fmt.Errorf("error from NewPopData: %w", err)
	}
	defer func() {
		if cleanupErr := cleanupPopData(pd); cleanupErr != nil {
			runErr = errors.Join(runErr, cleanupErr)
		}
	}()

	if pd.MqttEngine == nil {
		pd.mu.Lock()
		err := pd.CreateMqttEngine(mqttClientID, statusch, pd.MqttLogger)
		pd.mu.Unlock()
		if err != nil {
			return fmt.Errorf("error creating MQTT Engine: %w", err)
		}
		if err := pd.StartMqttEngine(pd.MqttEngine); err != nil {
			return fmt.Errorf("error starting MQTT Engine: %w", err)
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	workerErrCh := make(chan error, 5)
	startWorker := func(name string, fn func(context.Context) error) {
		go func() {
			if err := fn(ctx); err != nil && !errors.Is(err, context.Canceled) {
				select {
				case workerErrCh <- fmt.Errorf("%s: %w", name, err):
				case <-ctx.Done():
				}
			}
		}()
	}

	startWorker("config updater", func(ctx context.Context) error {
		return pd.ConfigUpdater(ctx, &conf)
	})
	startWorker("status updater", func(ctx context.Context) error {
		return pd.StatusUpdater(ctx, &conf)
	})
	startWorker("refresh engine", func(ctx context.Context) error {
		return pd.RefreshEngine(ctx, &conf)
	})

	log.Println("*** main: Calling ParseSourcesNG()")
	if err := pd.ParseSourcesNG(); err != nil {
		return fmt.Errorf("error from ParseSourcesNG: %w", err)
	}
	log.Println("*** main: Returned from ParseSourcesNG()")

	if err := pd.ParseOutputs(); err != nil {
		return fmt.Errorf("error from ParseOutputs: %w", err)
	}

	startWorker("api handler", func(ctx context.Context) error {
		return APIhandler(ctx, &conf)
	})
	startWorker("dns engine", func(ctx context.Context) error {
		return DnsEngine(ctx, &conf)
	})

	conf.BootTime = time.Now()
	statusch <- tapir.ComponentStatusUpdate{
		Component: "main-boot",
		Status:    tapir.StatusOK,
		Msg:       "TAPIR Policy Processor started",
		TimeStamp: time.Now(),
	}

	return runLoop(ctx, &conf, cfgFileUsed, opts.Reload, workerErrCh, stderr)
}

func loadConfigFiles(stderr io.Writer) (string, error) {
	viper.Reset()
	viper.SetConfigFile(tapir.DefaultPopCfgFile)
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		return "", fmt.Errorf("could not load config %s: %w", tapir.DefaultPopCfgFile, err)
	}
	cfgFileUsed := viper.ConfigFileUsed()
	fmt.Fprintln(stderr, "Using config file:", cfgFileUsed)

	for _, cfgFile := range []string{
		tapir.PopSourcesCfgFile,
		tapir.PopOutputsCfgFile,
		tapir.PopPolicyCfgFile,
	} {
		viper.SetConfigFile(cfgFile)
		if err := viper.MergeInConfig(); err != nil {
			return "", fmt.Errorf("could not load config %s: %w", cfgFile, err)
		}
		cfgFileUsed = viper.ConfigFileUsed()
		fmt.Fprintln(stderr, "Using config file:", cfgFileUsed)
	}

	return cfgFileUsed, nil
}

func runLoop(ctx context.Context, conf *Config, cfgFileUsed string, reload <-chan struct{}, workerErrCh <-chan error, stderr io.Writer) error {
	log.Println("mainloop: enter")
	defer log.Println("mainloop: leaving signal dispatcher")

	for {
		select {
		case <-ctx.Done():
			log.Println("mainloop: context cancelled. Cleaning up.")
			return nil
		case err := <-workerErrCh:
			if err != nil {
				return err
			}
		case <-reload:
			if err := reloadConfig(cfgFileUsed, stderr); err != nil {
				return err
			}
			log.Println("mainloop: SIGHUP received. Forcing refresh of all configured zones.")
			log.Printf("mainloop: Requesting refresh of all RPZ zones")
			conf.PopData.RpzRefreshCh <- RpzRefresh{Name: ""}
		case <-conf.Internal.APIStopCh:
			log.Printf("mainloop: API instruction to stop\n")
			return nil
		}
	}
}

func reloadConfig(cfgFileUsed string, stderr io.Writer) error {
	if err := viper.ReadInConfig(); err != nil {
		return fmt.Errorf("could not load config %s: %w", cfgFileUsed, err)
	}
	fmt.Fprintln(stderr, "Using config file:", cfgFileUsed)
	return nil
}

func cleanupPopData(pd *PopData) error {
	if pd == nil {
		return nil
	}

	var errs []error
	if err := pd.SaveRpzSerial(); err != nil {
		errs = append(errs, fmt.Errorf("error saving RPZ serial: %w", err))
	}
	if pd.MqttEngine != nil && pd.TapirMqttEngineRunning {
		if _, err := pd.MqttEngine.StopEngine(); err != nil {
			errs = append(errs, fmt.Errorf("error stopping MQTT Engine: %w", err))
		}
	}
	return errors.Join(errs...)
}
