/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package main

import (
	"fmt"
	"time"

	"github.com/dnstapir/tapir"
)

// type WBGC map[string]*tapir.WBGlist

// 1. Iterate over all lists
// 2. Delete all items from the list that is in the ReaperData bucket for this time slot
// 3. Delete the bucket from the ReaperData map
// 4. Generate a new IXFR for the deleted items
// 5. Send the IXFR to the RPZ
func (pd *PopData) Reaper(full bool) error {
	timekey := time.Now().Truncate(pd.ReaperInterval)
	// tpkg := tapir.MqttPkgIn{}
	tm := tapir.TapirMsg{}
	// ReaperData buckets to clear, but ONLY after GenerateRpzIxfr publishes the
	// removals successfully. Deleting names from pd.Lists (so decide() reflects
	// the removal) must happen BEFORE GenerateRpzIxfr — otherwise decide() still
	// sees the name listed and emits no delete. But the ReaperData bucket is the
	// retry source of truth: if the publish fails we must keep it so the next
	// reaper tick re-attempts the (still-unpublished) removals. So Lists is
	// mutated in phase 1; ReaperData buckets are cleared in phase 2 on success.
	bucketsToClear := []*tapir.WBGlist{}
	pd.Logger.Printf("Reaper: working on time slot %s across all lists", timekey.Format(tapir.TimeLayout))
	for _, listtype := range []string{"allowlist", "doubtlist", "denylist"} {
		for listname, wbgl := range pd.Lists[listtype] {
			// This loop is here to ensure that we don't have any old data in the ReaperData bucket
			// that has already passed its time slot.
			for t, d := range wbgl.ReaperData {
				if t.Before(timekey) {
					if len(d) == 0 {
						continue
					}

					pd.Logger.Printf("Reaper: Warning: found old reaperdata for time slot %s (that has already passed). Moving %d names to current time slot (%s)", t.Format(tapir.TimeLayout), len(d), timekey.Format(tapir.TimeLayout))
					pd.mu.Lock()
					if _, exist := wbgl.ReaperData[timekey]; !exist {
						wbgl.ReaperData[timekey] = map[string]bool{}
					}
					for name := range d {
						wbgl.ReaperData[timekey][name] = true
					}
					// wbgl.ReaperData[timekey] = d
					delete(wbgl.ReaperData, t)
					pd.mu.Unlock()
				}
			}
			// pd.Logger.Printf("Reaper: working on %s %s", listtype, listname)
			if len(wbgl.ReaperData[timekey]) > 0 {
				pd.Logger.Printf("Reaper: list [%s][%s] has %d timekeys stored", listtype, listname,
					len(wbgl.ReaperData[timekey]))
				pd.mu.Lock()
				for name := range wbgl.ReaperData[timekey] {
					pd.Logger.Printf("Reaper: removing %s from %s %s", name, listtype, listname)
					delete(pd.Lists[listtype][listname].Names, name)
					tm.Removed = append(tm.Removed, tapir.Domain{Name: name})
				}
				pd.mu.Unlock()
				// Defer clearing this bucket until the publish succeeds (below).
				bucketsToClear = append(bucketsToClear, wbgl)
			}
		}
	}

	if len(tm.Removed) > 0 {
		// GenerateRpzIxfr publishes the new snapshot itself. The names are
		// already gone from pd.Lists (so decide() reflects the removal); if the
		// publish fails we keep the ReaperData buckets so the next tick retries.
		ixfr, err := pd.GenerateRpzIxfr(&tm)
		if err != nil {
			return fmt.Errorf("Reaper: GenerateRpzIxfr failed (ReaperData kept for retry): %w", err)
		}
		// Publish succeeded: now it is safe to clear the reaper buckets.
		pd.mu.Lock()
		for _, wbgl := range bucketsToClear {
			delete(wbgl.ReaperData, timekey)
		}
		pd.mu.Unlock()
		if ixfr.FromSerial != ixfr.ToSerial {
			if err := pd.NotifyDownstreams(); err != nil {
				pd.Logger.Printf("Reaper: Error from NotifyDownstreams(): %v", err)
			}
		}
	}
	return nil
}
