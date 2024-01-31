/*
 * Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tapir

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"time"

	"github.com/eclipse/paho.golang/paho"
	"github.com/miekg/dns"
)

type ZoneData struct {
	ZoneName   string
	ZoneType   uint8 // 1 = "xfr", 2 = "map", 3 = "slice". An xfr zone only supports xfr related ops
	Owners     Owners
	OwnerIndex map[string]int
	// Apex RRs
	ApexLen int // # RRs that are stored separately
	SOA     dns.SOA
	NSrrs   []dns.RR // apex NS RRs
	// Rest of zone
	FilteredRRs RRArray // FilteredRRs should die
	RRs         RRArray // FilteredRRs + ApexRRs
	// Data		map[string]map[uint16][]dns.RR	// map[owner]map[rrtype][]dns.RR
	Data map[string]OwnerData // map[owner]map[rrtype][]dns.RR
	// Other stuff
	DroppedRRs     int
	KeptRRs        int
	XfrType        string // axfr | ixfr
	Logger         *log.Logger
	IncomingSerial uint32
	RRKeepFunc     func(uint16) bool
	RRParseFunc    func(*dns.RR, *ZoneData) bool
	Verbose        bool
	RpzData	       map[string]string	// map[ownername]action. owner w/o rpz zone name
}

type Owners []OwnerData

type OwnerData struct {
	Name    string
	RRtypes map[uint16]RRset
}

type RRset struct {
	RRs []dns.RR
}

type CommandPost struct {
	Command   string
	Zone      string
	Name      string // Domain name to add/remove an RPZ action for
	ListType  string
	Policy    string // RPZ policy
	Action    string // RPZ action (OBE)
	RpzSource string // corresponds with the sourceid in tem.conf
}

type CommandResponse struct {
	Time     time.Time
	Status   string
	Zone     string
	Serial   uint32
	Msg      string
	Error    bool
	ErrorMsg string
}

type DebugPost struct {
	Command string
	Zone    string
	Qname   string
	Qtype   uint16
}

type DebugResponse struct {
	Time       time.Time
	Status     string
	Zone       string
	ZoneData   ZoneData
	OwnerIndex map[string]int
	RRset      RRset
	Msg        string
	Error      bool
	ErrorMsg   string
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
	Msg   string
	Pings int
}

type PingResponse struct {
	Time       time.Time
	BootTime   time.Time
	Daemon     string
	ServerHost string
	Version    string
	Client     string
	Msg        string
	Pings      int
	Pongs      int
}

type MqttPkg struct {
	Type      string	// text | data, only used on sender side
	Error     bool   // only used for sub.
	ErrorMsg  string // only used for sub.
	Msg       string
	Data      TapirMsg
	TimeStamp time.Time		// time mqtt packet was sent or received, mgmt by MQTT Engine
}

type TapirMsg struct {
	Type      string // "intelupdate", "reset", ...
	Added     []Domain
	Removed   []Domain
	Msg       string
	TimeStamp time.Time		// time encoded in the payload by the sender, not touched by MQTT
}

type Domain struct {
	Name string
	Tags []string // this should become a bit field in the future
}

type MqttEngine struct {
	Topic         string
	ClientID      string
	Server        string
	QoS           int
	PrivKey       *ecdsa.PrivateKey
	PubKey        any
	Client        *paho.Client
	ClientCert    tls.Certificate
	CaCertPool    *x509.CertPool
	MsgChan       chan *paho.Publish
	CmdChan       chan MqttEngineCmd
	PublishChan   chan MqttPkg
	SubscribeChan chan MqttPkg
	CanPublish    bool
	CanSubscribe  bool
}

type MqttEngineCmd struct {
	Cmd  string
	Resp chan MqttEngineResponse
}

type MqttEngineResponse struct {
	Status   string
	Error    bool
	ErrorMsg string
}
