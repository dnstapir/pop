/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
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

// lumberjackWriter is the rotating writer every pop log goes through.
func lumberjackWriter(logfile string) *lumberjack.Logger {
	return &lumberjack.Logger{
		Filename:   logfile,
		MaxSize:    20,
		MaxBackups: 3,
		MaxAge:     14,
	}
}

// newFileLogger returns a logger writing to logfile, or the default logger
// when no file is configured.
//
// There is deliberately no os.OpenFile check here, and its absence is the
// point. There used to be one on the policy, dnsengine and MQTT logs, and it
// was the reason a missing log DIRECTORY killed pop outright before it had
// served anything -- while the standard log, which goes straight to
// lumberjack, quietly created that same directory and carried on. The
// inconsistency was the bug.
//
// The check also tested nothing the writer could not handle: lumberjack does
// os.MkdirAll when it opens. And it leaked what it opened -- the *os.File was
// handed to log.New and then immediately superseded by
// SetOutput(&lumberjack.Logger{...}), so it was never written to and never
// closed.
//
// What replaces it is a probe: create the directory, confirm the file can be
// opened for append, and CLOSE it again. That is deliberate rather than
// trusting lumberjack alone, because lumberjack opens lazily and log.Logger
// discards write errors -- so an unwritable path would otherwise lose the log
// in silence, which is a worse trade than the fatal it replaced.
//
// A log destination that cannot be opened is a reason to say so loudly, and to
// fall back to a log that works. It is not a reason to refuse to run: pop's
// job is to serve a policy zone, and it can do that while complaining that one
// of its logs is unwritable.
func newFileLogger(name, logfile, prefix string, logoptions int) *log.Logger {
	if logfile == "" {
		log.Printf("No %s logfile specified, using default", name)
		return log.Default()
	}
	if err := probeLogfile(logfile); err != nil {
		log.Printf("WARNING: cannot write the %s log to %s (%v); using the default log instead", name, logfile, err)
		return log.Default()
	}
	lg := log.New(lumberjackWriter(logfile), prefix, logoptions)
	fmt.Printf("TAPIR-POP %s logging to: %s\n", name, logfile)
	return lg
}

// probeLogfile checks that logfile can actually be written, creating its
// directory as lumberjack would. The descriptor is closed again: this is a
// check, not the writer.
func probeLogfile(logfile string) error {
	logfile = filepath.Clean(logfile)
	if err := os.MkdirAll(filepath.Dir(logfile), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(logfile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644) // #nosec G302
	if err != nil {
		return err
	}
	return f.Close()
}

func SetupLogging(conf *Config) {
	debug := viper.GetString("log.mode") == "debug"
	logoptions := log.Ldate | log.Ltime
	if debug {
		log.Println("Logging in debug mode (showing file and line number)")
		logoptions |= log.Lshortfile
	}

	prefixFor := func(name string) string {
		if debug {
			return name + ": "
		}
		return ""
	}

	// The standard log. Falling back to stderr rather than refusing to start:
	// an unset log.file is a configuration omission, and stderr is a perfectly
	// good answer to it -- under systemd it is captured anyway. Killing the
	// daemon over it means a trivial config slip stops DNS being served.
	logfile := viper.GetString("log.file")
	switch {
	case logfile == "":
		log.SetOutput(os.Stderr)
		log.Println("WARNING: no standard logfile configured (key log.file); logging to stderr")
	default:
		if err := probeLogfile(logfile); err != nil {
			log.SetOutput(os.Stderr)
			log.Printf("WARNING: cannot write the standard log to %s (%v); logging to stderr", logfile, err)
			break
		}
		log.SetOutput(lumberjackWriter(logfile))
		fmt.Printf("TAPIR-POP standard logging to: %s\n", logfile)
	}

	conf.Loggers.Policy = newFileLogger("policy", viper.GetString("policy.logfile"), prefixFor("policy"), logoptions)
	conf.Loggers.Dnsengine = newFileLogger("dnsengine", viper.GetString("dnsengine.logfile"), prefixFor("dnsengine"), logoptions)
	conf.Loggers.Mqtt = newFileLogger("mqtt", viper.GetString("tapir.mqtt.logfile"), prefixFor("mqtt"), logoptions)
}
