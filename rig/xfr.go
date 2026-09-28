/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Reading pop's zone two ways: whole, and as the chain of deltas that is meant
 * to add up to the same thing.
 */
package rig

import (
	"fmt"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// IXFR asks pop for everything that changed since serial `from`.
//
// The answer is one of two shapes, and which one it is matters to the caller:
// a real incremental chain, or the whole zone because pop decided the chain
// could not reach that serial. See ApplyIXFR.
func (p *Pop) IXFR(from uint32) ([]dns.RR, error) {
	m := new(dns.Msg)
	// The SOA in the authority section needs a well-formed MNAME and RNAME:
	// empty ones do not encode to valid domain names and pop answers FORMERR.
	// The values are not otherwise used -- only the serial is.
	m.SetIxfr(p.ZoneName, from, "ns1."+p.ZoneName, "hostmaster."+p.ZoneName)
	ch, err := new(dns.Transfer).In(m, p.DNSAddr)
	if err != nil {
		return nil, err
	}
	var out []dns.RR
	for env := range ch {
		if env.Error != nil {
			return nil, env.Error
		}
		out = append(out, env.RR...)
	}
	return out, nil
}

// ZoneBody is a zone's content as a set, for comparing two transfers that
// describe the same zone.
//
// A set rather than a sequence, because the order records come out in is not
// part of what the zone IS: the full-zone build walks a Go map, so two AXFRs of
// one unchanged zone can legitimately differ in order. Comparing byte streams
// would fail for a reason that has nothing to do with correctness.
//
// The SOA is excluded. Its serial is the thing that differs by construction,
// and every other field is constant.
type ZoneBody map[string]bool

// ZoneBodyOf reduces transferred records to a comparable set.
func ZoneBodyOf(rrs []dns.RR) ZoneBody {
	body := ZoneBody{}
	for _, rr := range rrs {
		if rr.Header().Rrtype == dns.TypeSOA {
			continue
		}
		body[rrKey(rr)] = true
	}
	return body
}

// rrKey is owner, type and rdata -- everything that identifies the record,
// without the TTL, which is not what an equivalence check is about.
func rrKey(rr dns.RR) string {
	h := rr.Header()
	rdata := strings.TrimPrefix(rr.String(), h.String())
	return fmt.Sprintf("%s %s %s", strings.ToLower(h.Name), dns.TypeToString[h.Rrtype], rdata)
}

// Equal reports whether two zone bodies hold the same records.
func (z ZoneBody) Equal(other ZoneBody) bool {
	if len(z) != len(other) {
		return false
	}
	for k := range z {
		if !other[k] {
			return false
		}
	}
	return true
}

// Diff describes how z differs from want, for a failure message that says what
// is wrong rather than that something is.
func (z ZoneBody) Diff(want ZoneBody) string {
	var missing, extra []string
	for k := range want {
		if !z[k] {
			missing = append(missing, k)
		}
	}
	for k := range z {
		if !want[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)

	var b strings.Builder
	if len(missing) > 0 {
		fmt.Fprintf(&b, "\n  missing (%d):", len(missing))
		for _, k := range missing {
			fmt.Fprintf(&b, "\n    %s", k)
		}
	}
	if len(extra) > 0 {
		fmt.Fprintf(&b, "\n  unexpected (%d):", len(extra))
		for _, k := range extra {
			fmt.Fprintf(&b, "\n    %s", k)
		}
	}
	return b.String()
}

// IxfrResult is what applying an IXFR response produced.
type IxfrResult struct {
	// Body is the zone after applying the response to the base it was given.
	Body ZoneBody

	// Incremental is false when pop answered with the whole zone instead of a
	// delta chain -- which it does, legitimately, when the chain cannot reach
	// the serial asked for.
	//
	// A test comparing the two transfer paths MUST check this. A full-zone
	// answer trivially equals the zone, so an equivalence assertion that does
	// not look would pass without having tested the delta path at all.
	Incremental bool

	// Serial the response ends at, and how many deltas it carried.
	Serial uint32
	Deltas int
}

// ApplyIXFR replays an IXFR response onto base and reports the result.
//
// The wire format is RFC 1995: a leading SOA at the current serial, then, if
// incremental, one section per delta -- SOA(from), the records removed, SOA(to),
// the records added -- and a trailing SOA. A response whose second record is
// not a SOA is a whole zone instead, and replaces base rather than amending it.
func ApplyIXFR(base ZoneBody, rrs []dns.RR) (*IxfrResult, error) {
	if len(rrs) == 0 {
		return nil, fmt.Errorf("empty IXFR response")
	}
	head, ok := rrs[0].(*dns.SOA)
	if !ok {
		return nil, fmt.Errorf("IXFR response does not begin with a SOA, got %s",
			dns.TypeToString[rrs[0].Header().Rrtype])
	}

	// Whole zone: SOA, records, SOA -- no inner SOA pair.
	if len(rrs) < 2 {
		return nil, fmt.Errorf("IXFR response has a SOA and nothing else")
	}
	if _, second := rrs[1].(*dns.SOA); !second {
		return &IxfrResult{Body: ZoneBodyOf(rrs), Incremental: false, Serial: head.Serial}, nil
	}

	// A SOA-only answer (client already current) is incremental with no deltas.
	body := ZoneBody{}
	for k := range base {
		body[k] = true
	}

	result := &IxfrResult{Incremental: true, Serial: head.Serial}
	i := 1
	for i < len(rrs) {
		from, ok := rrs[i].(*dns.SOA)
		if !ok {
			return nil, fmt.Errorf("expected a SOA starting a delta at record %d, got %s",
				i, dns.TypeToString[rrs[i].Header().Rrtype])
		}
		// The trailing SOA closes the response.
		if i == len(rrs)-1 {
			if from.Serial != head.Serial {
				return nil, fmt.Errorf("trailing SOA serial %d does not match the leading %d",
					from.Serial, head.Serial)
			}
			break
		}
		i++

		// Removals, up to the SOA that opens the additions.
		for i < len(rrs) {
			if _, isSOA := rrs[i].(*dns.SOA); isSOA {
				break
			}
			delete(body, rrKey(rrs[i]))
			i++
		}
		if i >= len(rrs) {
			return nil, fmt.Errorf("delta from serial %d has no closing SOA", from.Serial)
		}
		to := rrs[i].(*dns.SOA)
		if to.Serial < from.Serial {
			return nil, fmt.Errorf("delta goes backwards: %d -> %d", from.Serial, to.Serial)
		}
		i++

		// Additions, up to the SOA that opens the next delta or closes the
		// response.
		for i < len(rrs) {
			if _, isSOA := rrs[i].(*dns.SOA); isSOA {
				break
			}
			body[rrKey(rrs[i])] = true
			i++
		}
		result.Deltas++
		result.Serial = to.Serial
	}

	result.Body = body
	return result, nil
}
