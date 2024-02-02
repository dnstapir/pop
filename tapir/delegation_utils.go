/*
 *
 */
package tapir

import (
	"github.com/miekg/dns"
	"log"
)

func (zd *ZoneData) FindGlue(nsrrs RRset, dnssec_ok bool) *RRset {
	zd.Logger.Printf("FindGlue: nsrrs: %v", nsrrs)
	var glue, maybe_glue RRset
	var nsname string
	child := nsrrs.RRs[0].Header().Name
	for _, rr := range nsrrs.RRs {
		if nsrr, ok := rr.(*dns.NS); ok {
			nsname = nsrr.Ns
			zd.Logger.Printf("FindGlue: child '%s' has a nameserver '%s'", child, nsname)

			var nsnamerrs *OwnerData

			switch zd.ZoneType {
			case 3:
				nsnidx := zd.OwnerIndex[nsname]
				nsnamerrs = &zd.Owners[nsnidx]
			case 2:
				tmp := zd.Data[nsname]
				nsnamerrs = &tmp
			}

			if nsnamerrs != nil {
				log.Printf("FindGlue nsname='%s': there are RRs", nsname)
				if ns_A_rrs, ok := nsnamerrs.RRtypes[dns.TypeA]; ok {
					log.Printf("FindGlue for nsname='%s': there are A RRs", nsname)
					// Ok, we found an A RR
					maybe_glue.RRs = append(maybe_glue.RRs, ns_A_rrs.RRs...)
				}
				if ns_AAAA_rrs, ok := nsnamerrs.RRtypes[dns.TypeAAAA]; ok {
					log.Printf("FindGlue for nsname='%s': there are AAAA RRs", nsname)
					// Ok, we found an AAAA RR
					maybe_glue.RRs = append(maybe_glue.RRs, ns_AAAA_rrs.RRs...)
				}
			}
		}
	}

	if len(maybe_glue.RRs) == 0 {
		log.Printf("FindGlue: no glue for child=%s found in %s", child, zd.ZoneName)
	} else {
		log.Printf("FindGlue: found %d glue RRs child=%s in %s",
			len(glue.RRs), child, zd.ZoneName)
		glue = maybe_glue
	}
	return &glue
}
