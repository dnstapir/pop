/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package main

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/dnstapir/tapir"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func (pd *PopData) BootstrapRpzOutput() error {
	apextmpl := `
$TTL 3600
${ZONE}		IN	SOA	mname. hostmaster.dnstapir.se. (
				${SERIAL}
				60
				60
				86400
				60 )
${ZONE}		IN	NS	ns1.${ZONE}
${ZONE}		IN	NS	ns2.${ZONE}
ns1.${ZONE}	IN	A	127.0.0.1
ns2.${ZONE}	IN	AAAA	::1`

	rpzzone := viper.GetString("services.rpz.zonename")
	apex := strings.Replace(apextmpl, "${ZONE}", rpzzone, -1)
	apex = strings.Replace(apex, "${SERIAL}", fmt.Sprintf("%d", pd.Rpz.CurrentSerial), -1)

	zd := tapir.ZoneData{
		ZoneName: rpzzone,
		ZoneType: tapir.RpzZone,
		Logger:   log.Default(),
		Verbose:  true,
		Debug:    true,
	}

	_, err := zd.ReadZoneString(apex)
	if err != nil {
		pd.Logger.Printf("Error from ReadZoneString(): %v", err)
	}

	// Publish the initial (empty-Data) snapshot so readers have something
	// consistent to serve before sources are parsed. ParseSources -> the first
	// GenerateRpzAxfr then publishes the populated zone. Runs at startup before
	// the engine serves, so no concurrent reader yet.
	soa := zd.SOA
	soa.Serial = pd.Rpz.CurrentSerial
	pd.snapshot.Store(&ZoneSnapshot{
		ZoneName: rpzzone,
		Serial:   pd.Rpz.CurrentSerial,
		SOA:      soa,
		NSrrs:    zd.NSrrs,
		Data:     map[string]*tapir.RpzName{},
	})
	return nil
}

func (pd *PopData) RpzAxfrOut(w dns.ResponseWriter, r *dns.Msg) (uint32, int, error) {
	// Load the immutable snapshot once; serve the whole transfer from it with
	// no lock. A concurrent engine publish just means we serve the (consistent)
	// slightly-older zone, which is correct.
	snap := pd.snapshot.Load()
	if snap == nil {
		return 0, 0, fmt.Errorf("RpzAxfrOut: no snapshot published yet")
	}
	zone := snap.ZoneName

	outbound_xfr := make(chan *dns.Envelope)
	tr := new(dns.Transfer)
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		err := tr.Out(w, r, outbound_xfr)
		if err != nil {
			pd.Logger.Printf("Error from transfer.Out(): %v", err)
		}
		wg.Done()
	}()

	count := 0

	soa := snap.SOA // copy; snapshot is immutable
	rrs := []dns.RR{dns.RR(&soa)}
	var total_sent int

	rrs = append(rrs, snap.NSrrs...)
	count = len(rrs)

	for _, rpzn := range snap.Data {
		rrs = append(rrs, *rpzn.RR)
		count++
		if count >= 500 {
			total_sent += len(rrs)
			outbound_xfr <- &dns.Envelope{RR: rrs}
			rrs = []dns.RR{}
			count = 0
		}
	}

	rrs = append(rrs, dns.RR(&soa)) // trailing SOA

	total_sent += len(rrs)
	outbound_xfr <- &dns.Envelope{RR: rrs}

	close(outbound_xfr)
	wg.Wait()        // wait until everything is written out
	err := w.Close() // close connection
	if err != nil {
		pd.Logger.Printf("RpzAxfrOut: Error from Close(): %v", err)
	}

	pd.Logger.Printf("ZoneTransferOut: %s: Sent %d RRs (including SOA twice).", zone, total_sent)

	return snap.Serial, total_sent - 1, nil
}

// An IXFR has the following structure:
// SOA # current SOA serial
// 1: SOA N-1 # serial that the IXFR is the DIFF *from*
// 1: RR, RR, RR  # RRs that should be removed
// 1: SOA N # serial that the IXFR is the DIFF *to*
// 1: RR, RR, RR  # RRs that should be added
// SOA N # current soa serial
//
// This is an XFR with a single IXFR inside the outermost SOA pair. It is also possible to have a series of
// IXFRs chained:
//
// SOA N # current
// 1: SOA N-3
// 1: RR, RR, RR # removals
// 1: SOA N-2
// 1: RR, RR, RR # adds
// 2: SOA N-2
// 2: RR, RR, RR # removals
// 2: SOA N-1
// 2: RR, RR, RR # adds
// 3: SOA N-1
// 3: RR, RR, RR # removals
// 3: SOA N
// 3: RR, RR, RR # adds
// SOA N
// Returns: serial that we gave the client, number of RRs sent, error
func (pd *PopData) RpzIxfrOut(w dns.ResponseWriter, r *dns.Msg) (uint32, int, error) {

	var curserial uint32 = 0 // serial that the client claims to have

	if len(r.Ns) > 0 {
		for _, rr := range r.Ns {
			switch rr := rr.(type) {
			case *dns.SOA:
				curserial = rr.Serial
			default:
				pd.Logger.Printf("RpzIxfrOut: unexpected RR in IXFR request Authority section:\n%s\n", rr.String())
			}
		}
	}

	downstream, _, err := net.SplitHostPort(w.RemoteAddr().String())
	if err != nil {
		pd.Logger.Printf("RpzIxfrOut: Error from net.SplitHostPort(): %v", err)
		return 0, 0, err
	}

	// Record the serial this downstream claims to hold (used by the engine to
	// decide how far the IXFR chain can be pruned). Own mutex, not pd.mu.
	pd.downstreamSerials.record(downstream, curserial)

	snap := pd.snapshot.Load()
	if snap == nil {
		return 0, 0, fmt.Errorf("RpzIxfrOut: no snapshot published yet")
	}
	zone := snap.ZoneName

	// Fall back to AXFR if we cannot serve an incremental update: empty chain,
	// or the client is further behind than the oldest delta we still hold.
	if len(snap.IxfrChain) == 0 {
		pd.Logger.Printf("RpzIxfrOut: Downstream %s claims RPZ %s serial %d, but the IXFR chain is empty; AXFR needed", downstream, zone, curserial)
		serial, _, err := pd.RpzAxfrOut(w, r)
		if err != nil {
			return 0, 0, err
		}
		return serial, 0, nil
	} else if curserial < snap.IxfrChain[0].FromSerial {
		pd.Logger.Printf("RpzIxfrOut: Downstream %s claims RPZ %s serial %d, but the IXFR chain starts at %d; AXFR needed", downstream, zone, curserial, snap.IxfrChain[0].FromSerial)
		serial, _, err := pd.RpzAxfrOut(w, r)
		if err != nil {
			return 0, 0, err
		}
		return serial, 0, nil
	}

	if pd.Verbose {
		pd.Logger.Printf("RpzIxfrOut: Will try to serve RPZ %s to %v (%d IXFRs in chain), client serial %d", zone,
			w.RemoteAddr().String(), len(snap.IxfrChain), curserial)
	}

	outbound_xfr := make(chan *dns.Envelope)
	tr := new(dns.Transfer)
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		err := tr.Out(w, r, outbound_xfr)
		if err != nil {
			pd.Logger.Printf("Error from transfer.Out(): %v", err)
			pd.ComponentStatusCh <- tapir.ComponentStatusUpdate{
				Component: "rpz-ixfr",
				Status:    tapir.StatusFail,
				Msg:       fmt.Sprintf("Error from transfer.Out(): %v", err),
				TimeStamp: time.Now(),
			}
		}
		wg.Done()
	}()

	// All SOAs derive from the snapshot's single authoritative SOA — there is
	// no longer a separate ZoneData.SOA to drift from the served serial.
	soa := snap.SOA
	rrs := []dns.RR{dns.RR(&soa)} // leading SOA at current serial

	var total_sent, count int
	// Default to the client's own serial: if no delta applies (client already
	// up to date) we serve a SOA-only IXFR and report the unchanged serial,
	// not 0.
	finalSerial := curserial
	for _, ixfr := range snap.IxfrChain {
		if ixfr.FromSerial < curserial {
			continue
		}
		finalSerial = ixfr.ToSerial

		fromsoa := dns.Copy(dns.RR(&soa))
		fromsoa.(*dns.SOA).Serial = ixfr.FromSerial
		rrs = append(rrs, fromsoa)
		count++
		for _, tn := range ixfr.Removed {
			rrs = append(rrs, *tn.RR)
			count++
			if count >= 500 {
				outbound_xfr <- &dns.Envelope{RR: rrs}
				total_sent += len(rrs)
				rrs = []dns.RR{}
				count = 0
			}
		}
		tosoa := dns.Copy(dns.RR(&soa))
		tosoa.(*dns.SOA).Serial = ixfr.ToSerial
		rrs = append(rrs, tosoa)
		count++
		for _, tn := range ixfr.Added {
			rrs = append(rrs, *tn.RR)
			count++
			if count >= 500 {
				outbound_xfr <- &dns.Envelope{RR: rrs}
				total_sent += len(rrs)
				rrs = []dns.RR{}
				count = 0
			}
		}
	}

	rrs = append(rrs, dns.RR(&soa)) // trailing SOA
	total_sent += len(rrs)
	outbound_xfr <- &dns.Envelope{RR: rrs}

	close(outbound_xfr)
	wg.Wait()       // wait until everything is written out
	err = w.Close() // close connection
	if err != nil {
		pd.Logger.Printf("RpzIxfrOut: Error from Close(): %v", err)
	}

	pd.ComponentStatusCh <- tapir.ComponentStatusUpdate{
		Component: "rpz-ixfr",
		Status:    tapir.StatusOK,
		TimeStamp: time.Now(),
	}

	pd.Logger.Printf("RpzIxfrOut: %s: Sent %d RRs (including SOA twice).", zone, total_sent)
	return finalSerial, total_sent - 1, nil
}

// pruneIxfrChain returns chain trimmed to the deltas still needed: everything
// from the slowest downstream's serial onward is kept. If no downstreams are
// tracked, the chain is returned unchanged (the hard maxIxfrChain bound in
// GenerateRpzIxfr still caps it). Pure function — called by the engine while
// building a new snapshot, so all chain mutation stays on the engine goroutine.
// (Replaces the old PruneRpzIxfrChain, which mutated shared state from a DNS
// goroutine and had an off-by-two bug.)
//
// Invariant relied on: the chain is contiguous and oldest-first — each delta's
// ToSerial equals the next delta's FromSerial. GenerateRpzIxfr guarantees this
// by only ever appending curserial -> curserial+1. Trimming a contiguous chain
// from the front preserves contiguity, so RpzIxfrOut can always walk an
// unbroken serial path from any in-range client serial to the current one.
func pruneIxfrChain(chain []RpzIxfr, lowSerial uint32, haveDownstreams bool) []RpzIxfr {
	if !haveDownstreams || len(chain) == 0 {
		return chain
	}
	// Keep deltas whose ToSerial is still > lowSerial (a downstream at
	// lowSerial needs every delta that advances past it); drop fully-superseded
	// older deltas. Chain is ordered oldest-first.
	keepFrom := 0
	for i, ix := range chain {
		if ix.ToSerial > lowSerial {
			keepFrom = i
			break
		}
		keepFrom = i + 1
	}
	if keepFrom <= 0 {
		return chain
	}
	if keepFrom >= len(chain) {
		// keep at least the most recent delta so the FromSerial floor is sane
		return chain[len(chain)-1:]
	}
	return chain[keepFrom:]
}
