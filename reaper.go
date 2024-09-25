/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package main

import (
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
	pd.Logger.Printf("Reaper: working on time slot %s across all lists", timekey.Format(tapir.TimeLayout))
	for _, listtype := range []string{"whitelist", "greylist", "blacklist"} {
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
					delete(wbgl.ReaperData[timekey], name)
					tm.Removed = append(tm.Removed, tapir.Domain{Name: name})
				}
				// pd.Logger.Printf("Reaper: %s %s now has %d items:", listtype, listname, len(pd.Lists[listtype][listname].Names))
				// for name, item := range pd.Lists[listtype][listname].Names {
				// 	pd.Logger.Printf("Reaper: remaining: key: %s name: %s", name, item.Name)
				// }
				delete(wbgl.ReaperData, timekey)
				pd.mu.Unlock()
			}
		}
	}

	if len(tm.Removed) > 0 {
		ixfr, err := pd.GenerateRpzIxfr(&tm)
		if err != nil {
			pd.Logger.Printf("Reaper: Error from GenerateRpzIxfr(): %v", err)
		}
		err = pd.ProcessIxfrIntoAxfr(ixfr)
		if err != nil {
			pd.Logger.Printf("Reaper: Error from ProcessIxfrIntoAxfr(): %v", err)
		}
	}
	return nil
}
