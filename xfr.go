/*
 * Copyright (c) DNS TAPIR
 */

package main

import (
	"fmt"
	"log"
	"math"
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
	// pd.Rpz.CurrentSerial = serial

	pd.mu.Lock()
	pd.Rpz.Axfr.ZoneData = &zd // XXX: This is not thread safe
	pd.Rpz.Axfr.SOA = zd.SOA
	pd.Rpz.Axfr.NSrrs = zd.NSrrs
	pd.mu.Unlock()
	return nil
}

func (pd *PopData) RpzAxfrOut(w dns.ResponseWriter, r *dns.Msg) (uint32, int, error) {

	zone := pd.Rpz.ZoneName

	// if pd.Verbose {
	//		pd.Logger.Printf("RpzAxfrOut: Will try to serve RPZ %s (%d RRs)", zone,
	//			len(pd.Rpz.Axfr.Data))
	//	}

	outbound_xfr := make(chan *dns.Envelope)
	tr := new(dns.Transfer)
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		err := tr.Out(w, r, outbound_xfr)
		if err != nil {
			fmt.Printf("Error from transfer.Out(): %v\n", err)
			pd.Logger.Printf("Error from transfer.Out(): %v", err)
		}
		wg.Done()
	}()

	count := 0
	send_count := 0

	pd.Rpz.Axfr.SOA.Serial = pd.Rpz.CurrentSerial
	rrs := []dns.RR{dns.RR(&pd.Rpz.Axfr.SOA)}
	// pd.Logger.Printf("RpzAxfrOut: Adding SOA RR to env:%s", rrs[0].String())
	var total_sent int

	rrs = append(rrs, pd.Rpz.Axfr.NSrrs...)
	count = len(rrs)

	for _, rpzn := range pd.Rpz.Axfr.Data {
		// pd.Logger.Printf("RpzAxfrOut: Adding RR to env:%s", (*rpzn.RR).String())
		rrs = append(rrs, *rpzn.RR)
		count++
		if count >= 500 {
			send_count++
			total_sent += len(rrs)
			// fmt.Printf("Sending %d RRs\n", len(rrs))
			outbound_xfr <- &dns.Envelope{RR: rrs}
			rrs = []dns.RR{}
			// fmt.Printf("Sent %d RRs: done\n", len(rrs))
			count = 0
		}
	}

	rrs = append(rrs, dns.RR(&pd.Rpz.Axfr.SOA)) // trailing SOA

	total_sent += len(rrs)
	//	pd.Logger.Printf("RpzAxfrOut: Zone %s: Sending final %d RRs (including trailing SOA, total sent %d)\n",
	//		zone, len(rrs), total_sent)
	outbound_xfr <- &dns.Envelope{RR: rrs}

	close(outbound_xfr)
	wg.Wait()        // wait until everything is written out
	err := w.Close() // close connection
	if err != nil {
		pd.Logger.Printf("RpzAxfrOut: Error from Close(): %v", err)
	}

	pd.Logger.Printf("ZoneTransferOut: %s: Sent %d RRs (including SOA twice).", zone, total_sent)

	return pd.Rpz.CurrentSerial, total_sent - 1, nil
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

	// tmp := pd.Downstreams[downstream]
	// tmp.Serial = curserial

	pd.mu.Lock()
	pd.DownstreamSerials[downstream] = curserial
	zone := pd.Rpz.ZoneName
	pd.mu.Unlock()

	if len(pd.Rpz.IxfrChain) == 0 {
		pd.Logger.Printf("RpzIxfrOut: Downstream %s claims to have RPZ %s with serial %d, but the IXFR chain is empty; AXFR needed", downstream, zone, curserial)
		serial, _, err := pd.RpzAxfrOut(w, r)
		if err != nil {
			return 0, 0, err
		}
		return serial, 0, nil
	} else if curserial < pd.Rpz.IxfrChain[0].FromSerial {
		pd.Logger.Printf("RpzIxfrOut: Downstream %s claims to have RPZ %s with serial %d, but the IXFR chain starts at %d; AXFR needed", downstream, zone, curserial, pd.Rpz.IxfrChain[0].FromSerial)
		serial, _, err := pd.RpzAxfrOut(w, r)
		if err != nil {
			return 0, 0, err
		}
		return serial, 0, nil
	}

	if pd.Verbose {
		pd.Logger.Printf("RpzIxfrOut: Will try to serve RPZ %s to %v (%d IXFRs in chain)\n", zone,
			w.RemoteAddr().String(), len(pd.Rpz.IxfrChain))
		pd.Logger.Printf("RpzIxfrOut: Client claims to have RPZ %s with serial %d", zone, curserial)
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

	rrs := []dns.RR{}

	var total_sent int

	pd.Rpz.Axfr.SOA.Serial = pd.Rpz.CurrentSerial
	rrs = append(rrs, dns.RR(&pd.Rpz.Axfr.SOA))

	var totcount, count int
	var finalSerial uint32
	for _, ixfr := range pd.Rpz.IxfrChain {
		pd.Logger.Printf("RpzIxfrOut: checking client serial(%d) against IXFR[from:%d, to:%d]",
			curserial, ixfr.FromSerial, ixfr.ToSerial)
		if ixfr.FromSerial >= curserial {
			finalSerial = ixfr.ToSerial
			pd.Logger.Printf("PushIxfrs: pushing the IXFR[from:%d, to:%d] onto output",
				ixfr.FromSerial, ixfr.ToSerial)
			fromsoa := dns.Copy(dns.RR(&pd.Rpz.Axfr.ZoneData.SOA))
			fromsoa.(*dns.SOA).Serial = ixfr.FromSerial
			if pd.Debug {
				pd.Logger.Printf("IxfrOut: adding FROMSOA to output: %s", fromsoa.String())
			}
			rrs = append(rrs, fromsoa)
			count++
			pd.Logger.Printf("RpzIxfrOut: IXFR[%d,%d] has %d RRs in the removal list",
				ixfr.FromSerial, ixfr.ToSerial, len(ixfr.Removed))
			for _, tn := range ixfr.Removed {
				if pd.Debug {
					pd.Logger.Printf("DEL: adding RR to ixfr output: %s", tn.Name)
				}
				rrs = append(rrs, *tn.RR) // should do proper slice magic instead
				count++
				if count >= 500 {
					pd.Logger.Printf("Sending %d RRs\n", len(rrs))
					for _, rr := range rrs {
						pd.Logger.Printf("SEND DELS: %s", rr.String())
					}
					outbound_xfr <- &dns.Envelope{RR: rrs}
					rrs = []dns.RR{}
					totcount += count
					count = 0
				}
			}
			tosoa := dns.Copy(dns.RR(&pd.Rpz.Axfr.ZoneData.SOA))
			tosoa.(*dns.SOA).Serial = ixfr.ToSerial
			if pd.Debug {
				pd.Logger.Printf("RpzIxfrOut: adding TOSOA to output: %s", tosoa.String())
			}
			rrs = append(rrs, tosoa)
			count++
			pd.Logger.Printf("RpzIxfrOut: IXFR[%d,%d] has %d RRs in the added list",
				ixfr.FromSerial, ixfr.ToSerial, len(ixfr.Added))
			for _, tn := range ixfr.Added {
				if pd.Debug {
					pd.Logger.Printf("ADD: adding RR to ixfr output: %s", tn.Name)
				}
				rrs = append(rrs, *tn.RR) // should do proper slice magic instead
				count++
				if count >= 500 {
					pd.Logger.Printf("Sending %d RRs\n", len(rrs))
					for _, rr := range rrs {
						pd.Logger.Printf("SEND ADDS: %s", rr.String())
					}
					outbound_xfr <- &dns.Envelope{RR: rrs}
					// fmt.Printf("Sent %d RRs: done\n", len(rrs))
					rrs = []dns.RR{}
					totcount += count
					count = 0
				}
			}
		}
	}

	rrs = append(rrs, dns.RR(&pd.Rpz.Axfr.SOA)) // trailing SOA

	total_sent += len(rrs)
	pd.Logger.Printf("RpzIxfrOut: Zone %s: Sending final %d RRs (including trailing SOA, total sent %d)\n",
		zone, len(rrs), total_sent)

	//	pd.Logger.Printf("Sending %d RRs\n", len(rrs))
	//	for _, rr := range rrs {
	//		pd.Logger.Printf("SEND FINAL: %s", rr.String())
	//	}
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
	err = pd.PruneRpzIxfrChain()
	if err != nil {
		pd.Logger.Printf("RpzIxfrOut: Error from PruneRpzIxfrChain(): %v", err)
	}

	return finalSerial, total_sent - 1, nil
}

func (pd *PopData) PruneRpzIxfrChain() error {
	lowSerial := uint32(math.MaxUint32)
	for _, serial := range pd.DownstreamSerials {
		if serial < lowSerial {
			lowSerial = serial
		}
	}

	indexToDeleteUpTo := -1
	for i := 0; i < len(pd.Rpz.IxfrChain); i++ {
		if pd.Rpz.IxfrChain[i].FromSerial == lowSerial {
			indexToDeleteUpTo = i - 2
			break
		}
	}

	if indexToDeleteUpTo >= 0 {
		pd.Rpz.IxfrChain = pd.Rpz.IxfrChain[indexToDeleteUpTo+1:]
		pd.Logger.Printf("PruneRpzIxfrChain: Pruning IXFR chain up to two serials before serial %d", lowSerial)
	} else {
		pd.Logger.Printf("PruneRpzIxfrChain: Nothing to prune from the IXFR chain")
	}
	return nil
}
