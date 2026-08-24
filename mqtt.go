/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package main

import (
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/dnstapir/tapir"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

// How pop treats the MQTT connection, from tapir.mqtt.mode.
//
// Three states, because there are genuinely three situations and only one of
// them used to be expressible. Before this, MQTT startup was unconditional and
// blocked until the broker answered -- so a deployment with no broker, or with
// a broker that happened to be down, hung in main() and served nothing at all:
// no DNS, no API, while holding perfectly good local lists (issue #191).
const (
	// MqttModeRequired: pop will not run without a working broker. The
	// connection attempt is still BOUNDED -- it fails with a clear message
	// rather than hanging, which is the part that was actually broken.
	MqttModeRequired = "required"

	// MqttModeOptional: try to connect, but start regardless. The default.
	//
	// Safe by construction rather than by hope, because of how TAPIR
	// observations work: they are aggressively expired and stay alive only by
	// being refreshed over MQTT. A disconnected pop therefore SHEDS
	// observations as they age out and converges on "RPZ feeds and local lists
	// only" -- the honest state -- instead of serving stale intelligence
	// indefinitely.
	MqttModeOptional = "optional"

	// MqttModeIgnored: do not connect at all, and do not require any MQTT
	// configuration. For a pop fed purely by RPZ transfer and local files, and
	// for testing. Config that is present is left alone rather than removed,
	// which is why this is "ignored" and not "disabled".
	MqttModeIgnored = "ignored"
)

const defaultMqttConnectTimeout = 10 * time.Second

// mqttMode reads tapir.mqtt.mode. An unrecognised value is a config error and
// is always fatal, whatever it says: guessing which of three behaviours an
// operator meant is worse than refusing.
func mqttMode() (string, error) {
	switch mode := strings.ToLower(strings.TrimSpace(viper.GetString("tapir.mqtt.mode"))); mode {
	case "":
		return MqttModeOptional, nil
	case MqttModeRequired, MqttModeOptional, MqttModeIgnored:
		return mode, nil
	default:
		return "", fmt.Errorf("unknown tapir.mqtt.mode %q: must be one of %s, %s, %s",
			mode, MqttModeRequired, MqttModeOptional, MqttModeIgnored)
	}
}

func mqttConnectTimeout() time.Duration {
	if secs := viper.GetInt("tapir.mqtt.connect-timeout"); secs > 0 {
		return time.Duration(secs) * time.Second
	}
	return defaultMqttConnectTimeout
}

// mqttSourcesConfigured reports whether any source is fed over MQTT, so that
// mode: ignored can say plainly that those sources will not be loaded rather
// than leaving an operator to work it out from an empty list.
func mqttSourcesConfigured() []string {
	var out []string
	for name := range viper.GetStringMap("sources") {
		if strings.EqualFold(viper.GetString("sources."+name+".source"), "mqtt") {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// SetupMqtt brings the MQTT engine up according to tapir.mqtt.mode.
//
// It returns an error ONLY when the configured mode makes failure fatal, so
// the caller does not have to know the policy. Anything non-fatal is logged
// and reported through the component-status channel.
func (pd *PopData) SetupMqtt(clientid string, statusch chan tapir.ComponentStatusUpdate, lg *log.Logger) error {
	mode, err := mqttMode()
	if err != nil {
		return err
	}

	if mode == MqttModeIgnored {
		pd.Logger.Printf("MQTT is %s (tapir.mqtt.mode); not connecting", MqttModeIgnored)
		if srcs := mqttSourcesConfigured(); len(srcs) > 0 {
			pd.Logger.Printf("WARNING: tapir.mqtt.mode is %s, so these MQTT sources will NOT be loaded: %s",
				MqttModeIgnored, strings.Join(srcs, ", "))
		}
		return nil
	}

	if pd.MqttEngine == nil {
		if err := pd.CreateMqttEngine(clientid, statusch, lg); err != nil {
			return pd.mqttSetupFailure(mode, statusch, err)
		}
	}
	return pd.StartMqttEngine(pd.MqttEngine, mode, statusch)
}

// mqttSetupFailure applies the mode: fatal for required, reported and survived
// for optional.
func (pd *PopData) mqttSetupFailure(mode string, statusch chan tapir.ComponentStatusUpdate, err error) error {
	if mode == MqttModeRequired {
		return fmt.Errorf("MQTT is %s (tapir.mqtt.mode) and could not be brought up: %w", MqttModeRequired, err)
	}
	pd.Logger.Printf("WARNING: MQTT unavailable (%v); continuing because tapir.mqtt.mode is %s. "+
		"Sources fed over MQTT will be empty until it connects.", err, mode)
	select {
	case statusch <- tapir.ComponentStatusUpdate{
		Component: "mqtt-engine",
		Status:    tapir.StatusFail,
		Msg:       fmt.Sprintf("MQTT unavailable: %v", err),
		TimeStamp: time.Now(),
	}:
	default: // never block startup on a full status channel
	}
	return nil
}

func (pd *PopData) CreateMqttEngine(clientid string, statusch chan tapir.ComponentStatusUpdate, lg *log.Logger) error {
	if clientid == "" {
		return fmt.Errorf("MQTT clientid not specified in config")
	}
	var err error
	pd.Logger.Printf("Creating MQTT Engine with clientid %s", clientid)
	pd.MqttEngine, err = tapir.NewMqttEngine("tapir-pop", clientid, tapir.TapirSub, statusch, lg) // sub, but no pub
	if err != nil {
		return fmt.Errorf("NewMqttEngine: %w", err)
	}
	return nil
}

// StartMqttEngine wires up the engine's channels and then connects, with the
// connection BOUNDED by tapir.mqtt.connect-timeout.
//
// The channels are wired BEFORE the connection is attempted, and that ordering
// is the whole trick. CmdChan, PublishChan and SubscribeChan are created by
// NewMqttEngine and exist independently of any connection; StartEngine merely
// hands the same ones back once it has connected. Taking them up front means
// pop can stop waiting for a broker without leaving nil channels behind for
// the refresh engine to read, and without needing to bind them later from
// another goroutine -- which would be a data race for no benefit.
func (pd *PopData) StartMqttEngine(meng *tapir.MqttEngine, mode string, statusch chan tapir.ComponentStatusUpdate) error {
	if pd.TapirMqttEngineRunning {
		return nil
	}

	pd.TapirMqttCmdCh = meng.CmdChan
	pd.TapirMqttPubCh = meng.PublishChan
	pd.TapirObservations = meng.SubscribeChan
	pd.TapirMqttEngineRunning = true
	meng.SetupInterruptHandler()

	// StartEngine blocks until the broker answers, and against an unreachable
	// one it never returns. Run it off to the side and put a bound on how long
	// startup will wait for it.
	done := make(chan error, 1)
	go func() {
		_, _, _, err := meng.StartEngine()
		done <- err
	}()

	timeout := mqttConnectTimeout()
	select {
	case err := <-done:
		if err != nil {
			return pd.mqttSetupFailure(mode, statusch, err)
		}
		pd.Logger.Printf("MQTT engine connected")
		return nil

	case <-time.After(timeout):
		// Still trying. The goroutine above is left running deliberately: if
		// the broker comes up, the connection completes and the channels
		// already wired above start delivering.
		go func() {
			if err := <-done; err != nil {
				pd.Logger.Printf("MQTT engine gave up connecting: %v", err)
				return
			}
			pd.Logger.Printf("MQTT engine connected (after startup had already continued)")
		}()
		return pd.mqttSetupFailure(mode, statusch,
			fmt.Errorf("broker did not answer within %s", timeout))
	}
}

// Evaluating an update consists of two steps:
// 1. Iterate through the update, adding and/or removing the data in the update to the correct list(s).
//
// 2. Iterate through the update a second time:
//    - fetch the current output for each name
//    - recompute the output for that name, given new data
//    - if different, add the diff (DEL+ADD) to a growing "IXFR" describing the consequences of the update.
//

// func (pd *PopData) ProcessTapirUpdate(tpkg tapir.MqttPkgIn) (bool, error) {
func (pd *PopData) ProcessTapirUpdate(tm tapir.TapirMsg) (bool, error) {
	//	tm := tapir.TapirMsg{}
	//	err := json.Unmarshal(tpkg.Payload, &tm)
	//	if err != nil {
	//		fmt.Printf("MQTT: failed to decode json: %v", err)
	//		return false, fmt.Errorf("MQTT: failed to decode json: %v", err)
	//	}

	if pd.Debug {
		pd.Logger.Printf("ProcessTapirUpdate: update of MQTT source %s contains %d adds and %d removes",
			tm.SrcName, len(tm.Added), len(tm.Removed))
		tapir.PrintTapirMsg(tm, pd.Logger)
	}

	var wbgl *tapir.WBGlist
	var exists bool

	pd.Logger.Printf("ProcessTapirUpdate: looking up list [%s][%s]", tm.ListType, tm.SrcName)

	switch tm.ListType {
	case "allowlist", "doubtlist", "denylist":
		wbgl, exists = pd.Lists[tm.ListType][tm.SrcName]
	default:
		pd.Logger.Printf("TapirUpdate for unknown listtype from source \"%s\" rejected.", tm.SrcName)
		return false, fmt.Errorf("MQTT ListType %s is unknown, update rejected", tm.ListType)
	}

	if !exists {
		pd.Logger.Printf("TapirUpdate for unknown source \"%s\" rejected.", tm.SrcName)
		return false, fmt.Errorf("MQTT Source %s is unknown, update rejected", tm.SrcName)
	}

	for _, tname := range tm.Added {
		ttl := time.Duration(tname.TTL) * time.Second
		tmp := tapir.TapirName{
			Name:      dns.Fqdn(tname.Name),
			TimeAdded: tname.TimeAdded,
			TTL:       ttl,
			TagMask:   tname.TagMask,
		}
		wbgl.Names[tname.Name] = tmp

		pd.Logger.Printf("ProcessTapirUpdate: adding name %s to %s (TimeAdded: %s ttl: %v)",
			tname.Name, wbgl.Name, tname.TimeAdded.Format(tapir.TimeLayout), tname.TTL)

		// Time that the name will be removed from the list
		// must ensure that reapertime is at least ReaperInterval into the future
		reptime := tname.TimeAdded.Add(ttl).Truncate(pd.ReaperInterval).Add(pd.ReaperInterval)

		// Ensure that there are no prior removal events for this name
		for reaperTime, namesMap := range wbgl.ReaperData {
			if reaperTime.Before(reptime) {
				if _, exists := namesMap[tname.Name]; exists {
					delete(namesMap, tname.Name)
					if len(namesMap) == 0 {
						delete(wbgl.ReaperData, reaperTime)
					}
				}
			}
		}

		// Add the name to the removal list for the time it will be removed
		if wbgl.ReaperData[reptime] == nil {
			wbgl.ReaperData[reptime] = make(map[string]bool)
		}
		wbgl.ReaperData[reptime][tname.Name] = true
	}

	pd.Logger.Printf("ProcessTapirUpdate: current state of %s %s ReaperData:", tm.ListType, wbgl.Name)
	for t, v := range wbgl.ReaperData {
		if len(v) > 0 {
			pd.Logger.Printf("== At time %s the following names will be removed from the dns-tapir list:", t.Format(tapir.TimeLayout))
			for name := range v {
				pd.Logger.Printf("  %s", name)
			}
		} else {
			pd.Logger.Printf("ReaperData: timekey %s is empty, deleting", t.Format(tapir.TimeLayout))
			delete(wbgl.ReaperData, t)
		}
	}

	for _, tname := range tm.Removed {
		delete(wbgl.Names, dns.Fqdn(tname.Name))
	}

	// GenerateRpzIxfr computes the delta AND publishes the new snapshot (the
	// applied zone), so there is no separate apply step that could half-update
	// state on error (fixes #165). It returns an empty RpzIxfr when the update
	// produced no policy change.
	ixfr, err := pd.GenerateRpzIxfr(&tm)
	if err != nil {
		return false, err
	}
	if ixfr.FromSerial == ixfr.ToSerial {
		// no change -> no new snapshot was published, nothing to notify
		return true, nil
	}
	err = pd.NotifyDownstreams()
	return true, err // return to RefreshEngine
}
