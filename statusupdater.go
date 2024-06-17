/*
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package main

import (
	"log"
	"time"

	"github.com/dnstapir/tapir"
)

type xxxTemStatusUpdate struct {
	Status    string
	Component string // downstream | rpz | mqtt | config | ...
	Msg       string
	Response  chan xxxTemStatus
}

type xxxTemStatus struct {
	ComponentStatus map[string]string    // downstreamnotify | downstreamixfr | rpzupdate | mqttmsg | config | ...
	TimeStamps      map[string]time.Time // downstreamnotify | downstreamixfr | rpzupdate | mqttmsg | config | ...
	Counters        map[string]int       // downstreamnotify | downstreamixfr | rpzupdate | mqttmsg | config | ...
	ErrorMsgs       map[string]string    // downstreamnotify | downstreamixfr | rpzupdate | mqttmsg | config | ...
	NumFailures     int
	LastFailure     time.Time
}

func StatusUpdater(conf *Config, stopch chan struct{}) {

	var s = tapir.TemStatus{
		ComponentStatus: make(map[string]string),
		TimeStamps:      make(map[string]time.Time),
		Counters:        make(map[string]int),
		ErrorMsgs:       make(map[string]string),
	}

	var TemStatusCh = make(chan tapir.TemStatusUpdate, 10)
	conf.Internal.TemStatusCh = TemStatusCh

	log.Printf("StatusUpdater: Starting")

	var tsu tapir.TemStatusUpdate
	for {
		select {
		case tsu = <-TemStatusCh:
			switch tsu.Status {
			case "failure":
				log.Printf("StatusUpdater: status failure: %s", tsu.Msg)
				switch tsu.Component {
				case "mqtt", "rpz", "downstream-notify", "downstream-ixfr", "config":
					s.ErrorMsgs[tsu.Component] = tsu.Msg
					s.ComponentStatus[tsu.Component] = "failure"
					s.TimeStamps[tsu.Component] = time.Now()
					s.Counters[tsu.Component]++
					s.NumFailures++
					s.LastFailure = time.Now()
				default:
					log.Printf("StatusUpdater: Failure report for unknown component: %s", tsu.Component)
				}

			case "success":
				log.Printf("StatusUpdater: status success: %s", tsu.Msg)
				switch tsu.Component {
				case "mqtt", "rpz", "downstream-notify", "downstream-ixfr", "config":
					s.TimeStamps[tsu.Component] = time.Now()
					s.Counters[tsu.Component]++
					s.ComponentStatus[tsu.Component] = "ok"
					delete(s.ErrorMsgs, tsu.Component)
				default:
					log.Printf("StatusUpdater: Success report for unknown component: %s", tsu.Component)
				}

			case "report":
				log.Printf("StatusUpdater: request for status report: %s", tsu.Msg)
				if tsu.Response != nil {
					tsu.Response <- s
				} else {
					log.Printf("StatusUpdater: request for status report ignored due to lack of a response channel: %s", tsu.Msg)
				}

			default:
				log.Printf("StatusUpdater: Unknown status: %s", tsu.Status)
			}
		}
	}
}
