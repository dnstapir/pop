/*
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tapir

import (
        "net/http"
	"log"
	"time"

	"github.com/miekg/dns"
)

type ZoneData struct {
	ZoneName	string
	ZoneType	uint8	// 1 = "xfr", 2 = "map", 3 = "slice". An xfr zone only supports xfr related ops
	Owners		Owners
	OwnerIndex	map[string]int
	// Apex RRs
	ApexLen		int	// # RRs that are stored separately
	SOA		dns.SOA
	SOA_RRSIG	[]dns.RR
	NSrrs		[]dns.RR	 // apex NS RRs
	TXTrrs		[]dns.RR  // apex TXT RRs
	ZONEMDrrs	[]dns.RR	 // apex ZONEMD RRs
	// Rest of zone
	RRs		RRArray	 // FilteredRRs + ApexRRs
	FilteredRRs	RRArray
	// Data		map[string]map[uint16][]dns.RR	// map[owner]map[rrtype][]dns.RR
	Data		map[string]OwnerData	// map[owner]map[rrtype][]dns.RR
	// Other stuff
	DroppedRRs	int
	ZONEMDHashAlgs	[]uint8
	XfrType		string	// axfr | ixfr
	Logger		*log.Logger
	ZoneFile	string
	IncomingSerial	uint32
	ZoneID		string	// intended to be the unixtime found in the apex TXT RR
	Epoch		uint32	// essentially the same as ZoneID, but as an uint32
	KeepFunc	func(uint16) bool
	Verbose		bool
}

type Owners	[]OwnerData

type OwnerData struct {
     Name  	  string
     RRtypes	  map[uint16]RRset
}

type RRset struct {
     RRs   	  []dns.RR
//   RRSIGs	  []dns.RR
}

type CommandPost struct {
     Command	 string
     Zone	 string
     Name	 string	// Domain name to add/remove an RPZ action for
     ListType	 string
     Policy	 string	// RPZ policy
     Action	 string	// RPZ action (OBE)
     RpzSource	 string	// corresponds with the sourceid in tem.conf
}

type CommandResponse struct {
     Time	     time.Time
     Status	     string
     Zone	     string
     Serial	     uint32
     Msg	     string
     Error	     bool
     ErrorMsg	     string
}

type DebugPost struct {
     Command	 string
     Zone	 string
     Qname	 string
     Qtype	 uint16
}

type DebugResponse struct {
     Time	     time.Time
     Status	     string
     Zone	     string
     ZoneData	     ZoneData
     OwnerIndex	     map[string]int
     RRset	     RRset
     Msg	     string
     Error	     bool
     ErrorMsg	     string
}

type Api struct {
        Name       string
        Client     *http.Client
        BaseUrl    string
        apiKey     string
        Authmethod string
        Verbose    bool
        Debug      bool
}

type ShowAPIresponse struct {
        Status int
        Msg    string
        Data   []string
}

type PingPost struct {
        Msg     string
        Pings   int
}
        
type PingResponse struct {
        Time      	time.Time
	BootTime	time.Time
	Daemon		string
	ServerHost	string
	Version		string
        Client  	string
        Msg		string
        Pings   	int
        Pongs   	int
}
