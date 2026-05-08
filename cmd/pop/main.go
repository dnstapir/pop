/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	pop "dnstapir-pop"
)

/* Rewritten if building with make */
var name = "BAD-BUILD"
var version = "BAD-BUILD"
var commit = "BAD-BUILD"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	reload := make(chan struct{}, 1)
	hupper := make(chan os.Signal, 1)
	signal.Notify(hupper, syscall.SIGHUP)
	defer signal.Stop(hupper)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hupper:
				select {
				case reload <- struct{}{}:
				default:
				}
			}
		}
	}()

	if err := pop.Run(ctx, pop.RunOptions{
		Name:    name,
		Version: version,
		Commit:  commit,
		Args:    os.Args[1:],
		Stdout:  os.Stdout,
		Stderr:  os.Stderr,
		Reload:  reload,
	}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
