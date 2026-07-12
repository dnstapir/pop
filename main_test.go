/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
)

// ValidateConfig must RETURN an error (never call POPExiter / os.Exit) on a bad
// config, so it is safe to call on a SIGHUP reload of a running daemon (#155).
// Before this change it crashed the process, which is exactly why reloadConfig
// could not validate before swapping. These tests pin the non-fatal contract.
func TestValidateConfigReturnsErrorNotFatal(t *testing.T) {
	dir := t.TempDir()

	t.Run("invalid config returns error", func(t *testing.T) {
		// A config missing the required sections must produce an error, not a
		// process exit. (If this regressed to POPExiter/os.Exit, the test binary
		// would die here and the run would fail loudly — which is the point.)
		f := filepath.Join(dir, "invalid.yaml")
		if err := os.WriteFile(f, []byte("log:\n  verbose: true\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		v := viper.New()
		v.SetConfigFile(f)
		if err := v.ReadInConfig(); err != nil {
			t.Fatalf("ReadInConfig: %v", err)
		}
		if err := ValidateConfig(v, f); err == nil {
			t.Errorf("ValidateConfig(invalid) = nil, want error")
		}
	})

	t.Run("unparseable unmarshal returns error", func(t *testing.T) {
		// Type mismatch (string where a struct/section is expected) should be
		// surfaced as an error from the unmarshal/validate path, not a crash.
		f := filepath.Join(dir, "badtype.yaml")
		if err := os.WriteFile(f, []byte("services: \"not-a-section\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		v := viper.New()
		v.SetConfigFile(f)
		if err := v.ReadInConfig(); err != nil {
			t.Fatalf("ReadInConfig: %v", err)
		}
		if err := ValidateConfig(v, f); err == nil {
			t.Errorf("ValidateConfig(bad type) = nil, want error")
		}
	})
}

// loadAllConfig reads the primary config then merges sources/outputs/policy.
// On a missing file it must return an error (so reloadConfig can reject a bad
// reload), not panic or exit.
func TestLoadAllConfigMissingFileErrors(t *testing.T) {
	// The real config paths (tapir.DefaultPopCfgFile, ...) do not exist in the
	// test environment, so loadAllConfig must report that as an error.
	v := viper.New()
	if _, err := loadAllConfig(v); err == nil {
		t.Errorf("loadAllConfig with no config files present = nil, want error")
	}
}

// applyToGlobalViper must REPLACE the live config with the validated settings,
// not merge onto it — so keys removed from the new config do not survive as
// orphans (#177 adversarial review §2.2), and new values take effect.
func TestApplyToGlobalViperReplacesAndDropsOrphans(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	// Seed the live global config with an "old" state including a key that the
	// new config will NOT contain.
	viper.Set("keep", "old")
	viper.Set("orphan", "should-disappear")

	// The validated incoming config (as if just loaded into a throwaway viper).
	src := viper.New()
	src.Set("keep", "new")
	src.Set("added", "present")

	if err := applyToGlobalViper(src); err != nil {
		t.Fatalf("applyToGlobalViper: %v", err)
	}

	if got := viper.GetString("keep"); got != "new" {
		t.Errorf("keep = %q, want new (new value should apply)", got)
	}
	if got := viper.GetString("added"); got != "present" {
		t.Errorf("added = %q, want present (new key should apply)", got)
	}
	if viper.IsSet("orphan") {
		t.Errorf("orphan key survived the reload; Reset should have dropped it (got %q)", viper.GetString("orphan"))
	}
}
