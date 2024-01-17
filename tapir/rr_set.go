/*
 *
 */
package tapir

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/miekg/dns"
	"github.com/twotwotwo/sorts"
)

// RRArray represents an array of rrs
// It implements Swapper interface, and is sortable.
type RRArray []dns.RR

// Len returns the length of an RRArray.
func (array RRArray) Len() int {
	return len(array)
}

// Swap swaps elements on positions i and j from RRArray
func (array RRArray) Swap(i, j int) {
	array[i], array[j] = array[j], array[i]
}

// Less returns true if the element in the position i of RRArray is less than the element in position j of RRArray.
func (array RRArray) Less(i, j int) bool {

	// RR Canonical order:
	// 1.- Canonical Owner Name (RFC 3034 6.1)
	// 2.- RR Class
	// 3.- Type
	// 4.- RRData (as left-aligned canonical form)

	si := dns.SplitDomainName(array[i].Header().Name)
	sj := dns.SplitDomainName(array[j].Header().Name)

	// Comparing tags, right to left
	ii, ij := len(si)-1, len(sj)-1
	for ii >= 0 && ij >= 0 {
		if si[ii] != sj[ij] {
			return si[ii] < sj[ij]
		}
		ii--
		ij--
	}
	// Now one is a subdomain (or the same domain) of the other
	if ii != ij {
		return ii < ij
	}
	// Equal subdomain
	if array[i].Header().Class != array[j].Header().Class {
		return array[i].Header().Class < array[j].Header().Class
	} else if array[i].Header().Rrtype != array[j].Header().Rrtype {
		return array[i].Header().Rrtype < array[j].Header().Rrtype
	} else {
		return compareRRData(array[i], array[j])
	}

}

func compareRRData(rri, rrj dns.RR) bool {
	bytei := make([]byte, dns.MaxMsgSize)
	sizei, err := dns.PackRR(rri, bytei, 0, nil, false)
	if err != nil {
		return false
	}
	rrdatai := bytei[uint16(sizei)-rri.Header().Rdlength : sizei] // We remove the header from the representation
	bytej := make([]byte, dns.MaxMsgSize)
	sizej, err := dns.PackRR(rrj, bytej, 0, nil, false)
	if err != nil {
		return false
	}
	rrdataj := bytej[uint16(sizej)-rrj.Header().Rdlength : sizej] // We remove the header from the representation
	return bytes.Compare(rrdatai, rrdataj) < 0
}

// String returns a string representation of the RRArray, based on the name, class and Rrtype of the first element.
func (array RRArray) String() string {
	if len(array) == 0 {
		return "<empty_setlist>"
	}
	return fmt.Sprintf("%s#%s#%s", array[0].Header().Name, dns.ClassToString[array[0].Header().Class], dns.TypeToString[array[0].Header().Rrtype])
}

func quickSort(sortable sort.Interface) {
	sorts.Quicksort(sortable)
}
