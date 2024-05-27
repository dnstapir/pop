/*
 * Copyright (c) DNS TAPIR
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
func (td *TemData) Reaper(full bool) error {
	timekey := time.Now().Truncate(td.ReaperInterval)
	tpkg := tapir.MqttPkg{}
	td.Logger.Printf("Reaper: working on time slot %s across all lists", timekey.Format(tapir.TimeLayout))
	for _, listtype := range []string{"whitelist", "greylist", "blacklist"} {
		for listname, wbgl := range td.Lists[listtype] {
			// This loop is here to ensure that we don't have any old data in the ReaperData bucket
			// that has already passed its time slot.
			for t, d := range wbgl.ReaperData {
				if t.Before(timekey) {
					if len(d) == 0 {
						continue
					}

					td.Logger.Printf("Reaper: Warning: found old reaperdata for time slot %s (that has already passed). Moving %d names to current time slot (%s)", t.Format(tapir.TimeLayout), len(d), timekey.Format(tapir.TimeLayout))
					td.mu.Lock()
					if _, exist := wbgl.ReaperData[timekey]; !exist {
						wbgl.ReaperData[timekey] = map[string]bool{}
					}
					for name := range d {
						wbgl.ReaperData[timekey][name] = true
					}
					// wbgl.ReaperData[timekey] = d
					delete(wbgl.ReaperData, t)
					td.mu.Unlock()
				}
			}
			// td.Logger.Printf("Reaper: working on %s %s", listtype, listname)
			if len(wbgl.ReaperData[timekey]) > 0 {
				td.Logger.Printf("Reaper: list [%s][%s] has %d timekeys stored", listtype, listname,
					len(wbgl.ReaperData[timekey]))
				td.mu.Lock()
				for name := range wbgl.ReaperData[timekey] {
					td.Logger.Printf("Reaper: removing %s from %s %s", name, listtype, listname)
					delete(td.Lists[listtype][listname].Names, name)
					delete(wbgl.ReaperData[timekey], name)
					tpkg.Data.Removed = append(tpkg.Data.Removed, tapir.Domain{Name: name})
				}
				// td.Logger.Printf("Reaper: %s %s now has %d items:", listtype, listname, len(td.Lists[listtype][listname].Names))
				// for name, item := range td.Lists[listtype][listname].Names {
				// 	td.Logger.Printf("Reaper: remaining: key: %s name: %s", name, item.Name)
				// }
				delete(wbgl.ReaperData, timekey)
				td.mu.Unlock()
			}
		}
	}

	if len(tpkg.Data.Removed) > 0 {
		ixfr, err := td.GenerateRpzIxfr(&tpkg.Data)
		if err != nil {
			td.Logger.Printf("Reaper: Error from GenerateRpzIxfr(): %v", err)
		}
		err = td.ProcessIxfrIntoAxfr(ixfr)
		if err != nil {
			td.Logger.Printf("Reaper: Error from ProcessIxfrIntoAxfr(): %v", err)
		}
	}
	return nil
}
