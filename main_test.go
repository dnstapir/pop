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

// reloadConfig must never propagate a way to kill the daemon: a malformed
// config file returns an error (the SIGHUP handler logs it and keeps running),
// and crucially must NOT corrupt the live global viper config (#155).
func TestReloadConfig(t *testing.T) {
	dir := t.TempDir()

	good := filepath.Join(dir, "good.yaml")
	if err := os.WriteFile(good, []byte("log:\n  verbose: true\nkeyval: original\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Establish a known live config.
	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.SetConfigFile(good)
	if err := viper.ReadInConfig(); err != nil {
		t.Fatalf("initial ReadInConfig: %v", err)
	}
	if got := viper.GetString("keyval"); got != "original" {
		t.Fatalf("setup: keyval = %q, want original", got)
	}

	t.Run("valid reload succeeds and applies", func(t *testing.T) {
		if err := os.WriteFile(good, []byte("log:\n  verbose: true\nkeyval: updated\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := reloadConfig(good); err != nil {
			t.Fatalf("reloadConfig(valid) = %v, want nil", err)
		}
		if got := viper.GetString("keyval"); got != "updated" {
			t.Errorf("after reload keyval = %q, want updated", got)
		}
	})

	t.Run("malformed reload errors and does NOT corrupt live config", func(t *testing.T) {
		bad := filepath.Join(dir, "bad.yaml")
		// Invalid YAML.
		if err := os.WriteFile(bad, []byte("log:\n  verbose: true\n  : : not valid : :\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		before := viper.GetString("keyval")
		if err := reloadConfig(bad); err == nil {
			t.Errorf("reloadConfig(malformed) = nil, want error")
		}
		if got := viper.GetString("keyval"); got != before {
			t.Errorf("live config changed after failed reload: %q -> %q", before, got)
		}
	})

	t.Run("missing file errors", func(t *testing.T) {
		if err := reloadConfig(filepath.Join(dir, "nonexistent.yaml")); err == nil {
			t.Errorf("reloadConfig(missing) = nil, want error")
		}
	})
}
