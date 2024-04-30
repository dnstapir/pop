/*
 * Copyright (c) DNS TAPIR
 */

package main

import (
	"log"
	"strings"
	"sync"

	"github.com/dnstapir/tapir"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func (td *TemData) BootstrapRpzOutput() error {
	apextmpl := `
$TTL 3600
${ZONE}		IN	SOA	mname. hostmaster.dnstapir.se. (
				123
				60
				60
				86400
				60 )
${ZONE}		IN	NS	ns1.${ZONE}
${ZONE}		IN	NS	ns2.${ZONE}
ns1.${ZONE}	IN	A	127.0.0.1
ns2.${ZONE}	IN	AAAA	::1`

	rpzzone := viper.GetString("output.rpz.zonename")
	apex := strings.Replace(apextmpl, "${ZONE}", rpzzone, -1)

	zd := tapir.ZoneData{
		ZoneName: rpzzone,
		ZoneType: tapir.RpzZone,
		Logger:   log.Default(),
		Verbose:  true,
		Debug:    true,
	}

	serial, err := zd.ReadZoneString(apex)
	if err != nil {
		td.Logger.Printf("Error from ReadZoneString(): %v", err)
	}
	td.Rpz.CurrentSerial = serial

	td.Rpz.Axfr.ZoneData = &zd // XXX: This is not thread safe
	td.Rpz.Axfr.SOA = zd.SOA
	td.Rpz.Axfr.NSrrs = zd.NSrrs
	return nil
}

func (td *TemData) RpzAxfrOut(w dns.ResponseWriter, r *dns.Msg) (int, error) {

	zone := td.Rpz.ZoneName

	if td.Verbose {
		td.Logger.Printf("RpzAxfrOut: Will try to serve RPZ %s (%d RRs)", zone,
			len(td.Rpz.Axfr.Data))
	}

	outbound_xfr := make(chan *dns.Envelope)
	tr := new(dns.Transfer)
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		err := tr.Out(w, r, outbound_xfr)
		if err != nil {
			td.Logger.Printf("Error from transfer.Out(): %v", err)
		}
		wg.Done()
	}()

	count := 0
	send_count := 0
	env := dns.Envelope{}

	td.Rpz.Axfr.SOA.Serial = td.Rpz.CurrentSerial
	env.RR = append(env.RR, dns.RR(&td.Rpz.Axfr.SOA))
	//	total_sent := 1
	var total_sent int

	env.RR = append(env.RR, td.Rpz.Axfr.NSrrs...)

	for _, rpzn := range td.Rpz.Axfr.Data {
		env.RR = append(env.RR, *rpzn.RR) // should do proper slice magic instead
		count++
		if count >= 500 {
			send_count++
			total_sent += len(env.RR)
			// fmt.Printf("Sending %d RRs\n", len(env.RR))
			outbound_xfr <- &env
			// fmt.Printf("Sent %d RRs: done\n", len(env.RR))
			env = dns.Envelope{}
			count = 0
		}
	}

	env.RR = append(env.RR, dns.RR(&td.Rpz.Axfr.SOA)) // trailing SOA

	total_sent += len(env.RR)
	td.Logger.Printf("RpzAxfrOut: Zone %s: Sending final %d RRs (including trailing SOA, total sent %d)\n",
		zone, len(env.RR), total_sent)
	outbound_xfr <- &env

	close(outbound_xfr)
	wg.Wait() // wait until everything is written out
	w.Close() // close connection

	td.Logger.Printf("ZoneTransferOut: %s: Sent %d RRs (including SOA twice).", zone, total_sent)

	return total_sent - 1, nil
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
func (td *TemData) RpzIxfrOut(w dns.ResponseWriter, r *dns.Msg) (int, error) {

	var curserial uint32 = 0 // serial that the client claims to have

	if len(r.Ns) > 0 {
		for _, rr := range r.Ns {
			switch rr.(type) {
			case *dns.SOA:
				curserial = rr.(*dns.SOA).Serial
			default:
				td.Logger.Printf("RpzIxfrOut: unexpected RR in IXFR request Authority section:\n%s\n",
					rr.String())
			}
		}
	}

	zone := td.Rpz.ZoneName

	if td.Verbose {
		td.Logger.Printf("RpzIxfrOut: Will try to serve RPZ %s to %v (%d IXFRs in chain)\n", zone,
			w.RemoteAddr().String(), len(td.Rpz.IxfrChain))
		td.Logger.Printf("RpzIxfrOut: Client claims to have RPZ %s with serial %d", zone, curserial)
	}

	outbound_xfr := make(chan *dns.Envelope)
	tr := new(dns.Transfer)
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		tr.Out(w, r, outbound_xfr)
		wg.Done()
	}()

	env := dns.Envelope{}

	var total_sent int

	td.Rpz.Axfr.SOA.Serial = td.Rpz.CurrentSerial
	env.RR = append(env.RR, dns.RR(&td.Rpz.Axfr.SOA))

	var totcount, count int
	for _, ixfr := range td.Rpz.IxfrChain {
		td.Logger.Printf("IxfrOut: checking client serial(%d) against IXFR[from:%d, to:%d]",
			curserial, ixfr.FromSerial, ixfr.ToSerial)
		if ixfr.FromSerial >= curserial {
			td.Logger.Printf("PushIxfrs: pushing the IXFR[from:%d, to:%d] onto output",
				ixfr.FromSerial, ixfr.ToSerial)
			fromsoa := dns.Copy(dns.RR(&td.Rpz.Axfr.ZoneData.SOA))
			fromsoa.(*dns.SOA).Serial = ixfr.FromSerial
			if td.Debug {
				td.Logger.Printf("IxfrOut: adding FROMSOA to output: %s", fromsoa.String())
			}
			env.RR = append(env.RR, fromsoa)
			count++
			td.Logger.Printf("IxfrOut: IXFR[%d,%d] has %d RRs in the removal list",
				ixfr.FromSerial, ixfr.ToSerial, len(ixfr.Removed))
			for _, tn := range ixfr.Removed {
				if td.Debug {
					td.Logger.Printf("DEL: adding RR to ixfr output: %s", tn.Name)
				}
				env.RR = append(env.RR, *tn.RR) // should do proper slice magic instead
				count++
				if count >= 500 {
					td.Logger.Printf("Sending %d RRs\n", len(env.RR))
					for _, rr := range env.RR {
						td.Logger.Printf("SEND DELS: %s", rr.String())
					}
					outbound_xfr <- &env
					env = dns.Envelope{}
					totcount += count
					count = 0
				}
			}
			tosoa := dns.Copy(dns.RR(&td.Rpz.Axfr.ZoneData.SOA))
			tosoa.(*dns.SOA).Serial = ixfr.ToSerial
			if td.Debug {
				td.Logger.Printf("IxfrOut: adding TOSOA to output: %s", tosoa.String())
			}
			env.RR = append(env.RR, tosoa)
			count++
			td.Logger.Printf("IxfrOut: IXFR[%d,%d] has %d RRs in the added list",
				ixfr.FromSerial, ixfr.ToSerial, len(ixfr.Added))
			for _, tn := range ixfr.Added {
				if td.Debug {
					td.Logger.Printf("ADD: adding RR to ixfr output: %s", tn.Name)
				}
				env.RR = append(env.RR, *tn.RR) // should do proper slice magic instead
				count++
				if count >= 500 {
					td.Logger.Printf("Sending %d RRs\n", len(env.RR))
					for _, rr := range env.RR {
						td.Logger.Printf("SEND ADDS: %s", rr.String())
					}
					outbound_xfr <- &env
					// fmt.Printf("Sent %d RRs: done\n", len(env.RR))
					env = dns.Envelope{}
					totcount += count
					count = 0
				}
			}
		}
	}

	env.RR = append(env.RR, dns.RR(&td.Rpz.Axfr.SOA)) // trailing SOA

	total_sent += len(env.RR)
	td.Logger.Printf("ZoneTransferOut: Zone %s: Sending final %d RRs (including trailing SOA, total sent %d)\n",
		zone, len(env.RR), total_sent)

	//	td.Logger.Printf("Sending %d RRs\n", len(env.RR))
	//	for _, rr := range env.RR {
	//		td.Logger.Printf("SEND FINAL: %s", rr.String())
	//	}
	outbound_xfr <- &env

	close(outbound_xfr)
	wg.Wait() // wait until everything is written out
	w.Close() // close connection

	td.Logger.Printf("ZoneTransferOut: %s: Sent %d RRs (including SOA twice).", zone, total_sent)

	return total_sent - 1, nil
}