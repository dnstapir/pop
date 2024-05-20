/*
 * Johan Stenstam, johani@johani.org
 */
package main

import (
	"crypto/tls"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/spf13/viper"

	"github.com/dnstapir/tapir"
)

type RpzCmdData struct {
	Command   string
	Zone      string
	Domain    string
	ListType  string
	RpzSource string // Name of one feed
	Policy    string
	Action    string
	Result    chan RpzCmdResponse
}

type RpzCmdResponse struct {
	Time      time.Time
	Zone      string
	Domain    string
	Msg       string
	OldSerial uint32
	NewSerial uint32
	Error     bool
	ErrorMsg  string
	Status    bool
}

func APIcommand(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		decoder := json.NewDecoder(r.Body)
		var cp tapir.CommandPost
		err := decoder.Decode(&cp)
		if err != nil {
			log.Println("APICommand: error decoding command post:", err)
		}

		log.Printf("API: received /command request (cmd: %s) from %s.\n",
			cp.Command, r.RemoteAddr)

		resp := tapir.CommandResponse{}

		defer func() {
			// log.Printf("defer: resp: %v", resp)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}()

		switch cp.Command {
		case "status":
			log.Printf("Daemon status inquiry\n")
			resp = tapir.CommandResponse{
				Status: "ok", // only status we know, so far
				Msg:    "We're happy, but send more cookies"}
		case "stop":
			log.Printf("Daemon instructed to stop\n")
			resp = tapir.CommandResponse{
				Status: "stopping",
				Msg:    "Daemon was happy, but now winding down",
			}
			conf.Internal.APIStopCh <- struct{}{}
		case "bump":
			resp.Msg, err = BumpSerial(conf, cp.Zone)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "mqtt-start":
			conf.TemData.MqttEngine.StartEngine()
			resp.Msg = "MQTT engine started"

		case "mqtt-stop":
			conf.TemData.MqttEngine.StopEngine()
			resp.Msg = "MQTT engine stopped"

		case "mqtt-restart":
			conf.TemData.MqttEngine.RestartEngine()
			resp.Msg = "MQTT engine restarted"

		case "rpz-add":
			log.Printf("Received RPZ-ADD %s policy %s RPZ source %s command", cp.Name, cp.Policy, cp.RpzSource)

			log.Printf("apihandler: RPZ-ADD 1. Len(ch): %d", len(conf.TemData.RpzCommandCh))
			var respch = make(chan RpzCmdResponse, 1)
			conf.TemData.RpzCommandCh <- RpzCmdData{
				Command:   "RPZ-ADD",
				Domain:    cp.Name,
				Policy:    cp.Policy,
				RpzSource: cp.RpzSource,
				Result:    respch,
			}
			log.Printf("apihandler: RPZ-ADD 2")
			rpzresp := <-respch

			log.Printf("apihandler: RPZ-ADD 3")
			if rpzresp.Error {
				log.Printf("RPZ-ADD: Error from RefreshEngine: %s", resp.ErrorMsg)
				resp.Error = true
				resp.ErrorMsg = rpzresp.ErrorMsg
			}
			log.Printf("apihandler: RPZ-ADD 4")
			resp.Msg = rpzresp.Msg

		case "rpz-lookup":
			log.Printf("Received RPZ-LOOKUP %s command", cp.Name)

			var respch = make(chan RpzCmdResponse, 1)
			conf.TemData.RpzCommandCh <- RpzCmdData{
				Command: "RPZ-LOOKUP",
				Domain:  cp.Name,
				Result:  respch,
			}
			rpzresp := <-respch

			if rpzresp.Error {
				log.Printf("RPZ-REMOVE: Error from RefreshEngine: %s", resp.ErrorMsg)
				resp.Error = true
				resp.ErrorMsg = rpzresp.ErrorMsg
			}
			resp.Msg = rpzresp.Msg

		case "rpz-remove":
			log.Printf("Received RPZ-REMOVE %s source %s command", cp.Name, cp.RpzSource)

			var respch = make(chan RpzCmdResponse, 1)
			conf.TemData.RpzCommandCh <- RpzCmdData{
				Command:   "RPZ-REMOVE",
				Domain:    cp.Name,
				RpzSource: cp.RpzSource,
				Result:    respch,
			}
			rpzresp := <-respch

			if rpzresp.Error {
				log.Printf("RPZ-REMOVE: Error from RefreshEngine: %s", resp.ErrorMsg)
				resp.Error = true
				resp.ErrorMsg = rpzresp.ErrorMsg
			}
			resp.Msg = rpzresp.Msg

		case "rpz-list-sources":
			log.Printf("Received RPZ-LIST-SOURCES command")

			var respch = make(chan RpzCmdResponse, 1)
			conf.TemData.RpzCommandCh <- RpzCmdData{
				Command: "RPZ-LIST-SOURCES",
				Result:  respch,
			}
			rpzresp := <-respch

			if rpzresp.Error {
				log.Printf("RPZ-LIST-SOURCS: Error from RefreshEngine: %s", resp.ErrorMsg)
				resp.Error = true
				resp.ErrorMsg = rpzresp.ErrorMsg
			}
			resp.Msg = rpzresp.Msg

			//		case "stop":
			//			log.Printf("Daemon instructed to stop\n")
			//			// var done struct{}
			// conf.Internal.APIStopCh <- done
			//			resp = tapir.CommandResponse{
			//				Status: "stopping",
			//				Msg:    "Daemon was happy, but now winding down",
			//			}

		// End of Selection
		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Unknown command: %s", cp.Command)
		}
	}
}

func APIbootstrap(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		resp := tapir.BootstrapResponse{
			Status: "ok", // only status we know, so far
			Msg:    "We're happy, but send more cookies",
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				log.Printf("Error from json encoder: %v", err)
				log.Printf("resp: %v", resp)
			}
		}()

		decoder := json.NewDecoder(r.Body)
		var bp tapir.BootstrapPost
		err := decoder.Decode(&bp)
		if err != nil {
			log.Println("APIbootstrap: error decoding command post:", err)
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Error decoding command post: %v", err)
			return
		}

		log.Printf("API: received /bootstrap request (cmd: %s) from %s.\n",
			bp.Command, r.RemoteAddr)

		switch bp.Command {
		case "export-greylist":
			td := conf.TemData
			td.mu.RLock()
			defer td.mu.RUnlock()

			greylist, ok := td.Lists["greylist"][bp.ListName]
			if !ok {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Greylist '%s' not found", bp.ListName)
				return
			}
			log.Printf("Found %s greylist: %v", bp.ListName, greylist)

			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Disposition", "attachment; filename=greylist-dns-tapir.gob")

			encoder := gob.NewEncoder(w)
			err := encoder.Encode(greylist)
			if err != nil {
				log.Printf("Error encoding greylist: %v", err)
				resp.Error = true
				resp.ErrorMsg = err.Error()
				return
			}
		default:
			resp.ErrorMsg = fmt.Sprintf("Unknown command: %s", bp.Command)
			resp.Error = true
		}
	}
}

func APIdebug(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	td := conf.TemData

	return func(w http.ResponseWriter, r *http.Request) {

		resp := tapir.DebugResponse{
			Status: "ok", // only status we know, so far
			Msg:    "We're happy, but send more cookies",
		}

		defer func() {
			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				log.Printf("Error from json encoder: %v", err)
				log.Printf("resp: %v", resp)
			}
		}()

		decoder := json.NewDecoder(r.Body)
		var dp tapir.DebugPost
		err := decoder.Decode(&dp)
		if err != nil {
			log.Println("APICdebug: error decoding debug post:", err)
		}

		log.Printf("API: received /debug request (cmd: %s) from %s.\n",
			dp.Command, r.RemoteAddr)

		switch dp.Command {
		case "rrset":
			log.Printf("TEM debug rrset inquiry")
			if zd, ok := td.RpzSources[dp.Zone]; ok {
				if owner := &zd.Owners[zd.OwnerIndex[dp.Qname]]; owner != nil {
					if rrset, ok := owner.RRtypes[dp.Qtype]; ok {
						resp.RRset = rrset
					}
					log.Printf("TEM debug rrset: owner: %v", owner)
				}
			} else {
				resp.Msg = fmt.Sprintf("Zone %s is unknown", dp.Zone)
			}

		case "zonedata":
			log.Printf("TEM debug zone inquiry")
			if zd, ok := td.RpzSources[dp.Zone]; ok {
				//			       resp.ZoneData = *zd
				//			       resp.ZoneData.RRKeepFunc = nil
				//			       resp.ZoneData.RRParseFunc = nil
				log.Printf("TEM debug zone: name: %s rrs: %d owners: %d", dp.Zone,
					len(zd.RRs), len(zd.Owners))
			} else {
				resp.Msg = fmt.Sprintf("Zone %s is unknown", dp.Zone)
			}

		case "mqtt-stats":
			log.Printf("TEM debug MQTT stats")
			resp.MqttStats = td.MqttEngine.Stats()

		case "reaper-stats":
			log.Printf("TEM debug reaper stats")
			resp.ReaperStats = make(map[string]map[time.Time][]string)
			for SrcName, list := range td.Lists["greylist"] {
				resp.ReaperStats[SrcName] = make(map[time.Time][]string)
				for ts, items := range list.ReaperData {
					for _, item := range items {
						resp.ReaperStats[SrcName][ts] = append(resp.ReaperStats[SrcName][ts], item.Name)
					}
				}
			}

		case "colourlists":
			log.Printf("TEM debug white/black/grey lists")
			resp.Lists = map[string]map[string]*tapir.WBGlist{}
			for t, l := range td.Lists {
				resp.Lists[t] = map[string]*tapir.WBGlist{}
				for n, v := range l {
					resp.Lists[t][n] = &tapir.WBGlist{
						Name:        v.Name,
						Description: td.Lists[t][n].Description,
						Type:        td.Lists[t][n].Type,
						Format:      td.Lists[t][n].Format,
						Names:       td.Lists[t][n].Names,
						Filename:    td.Lists[t][n].Filename,
						RpzZoneName: td.Lists[t][n].RpzZoneName,
						RpzSerial:   td.Lists[t][n].RpzSerial,
					}
				}
			}

		case "gen-output":
			log.Printf("TEM debug generate RPZ output")
			err = td.GenerateRpzAxfr()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}
			resp.BlacklistedNames = td.BlacklistedNames
			resp.GreylistedNames = td.GreylistedNames
			for _, rpzn := range td.Rpz.Axfr.Data {
				resp.RpzOutput = append(resp.RpzOutput, *rpzn)
			}

		default:
			resp.ErrorMsg = fmt.Sprintf("Unknown command: %s", dp.Command)
			resp.Error = true
		}
	}
}

func SetupRouter(conf *Config) *mux.Router {
	r := mux.NewRouter().StrictSlash(true)

	sr := r.PathPrefix("/api/v1").Headers("X-API-Key",
		viper.GetString("apiserver.key")).Subrouter()
	sr.HandleFunc("/ping", tapir.APIping("tem", conf.BootTime)).Methods("POST")
	sr.HandleFunc("/command", APIcommand(conf)).Methods("POST")
	sr.HandleFunc("/bootstrap", APIbootstrap(conf)).Methods("POST")
	sr.HandleFunc("/debug", APIdebug(conf)).Methods("POST")
	// sr.HandleFunc("/show/api", tapir.APIshowAPI(r)).Methods("GET")

	return r
}

func SetupBootstrapRouter(conf *Config) *mux.Router {
	r := mux.NewRouter().StrictSlash(true)

	sr := r.PathPrefix("/api/v1").Headers("X-API-Key", viper.GetString("apiserver.key")).Subrouter()
	sr.HandleFunc("/ping", tapir.APIping("tem", conf.BootTime)).Methods("POST")
	sr.HandleFunc("/bootstrap", APIbootstrap(conf)).Methods("POST")
	// sr.HandleFunc("/debug", APIdebug(conf)).Methods("POST")
	// sr.HandleFunc("/show/api", tapir.APIshowAPI(r)).Methods("GET")

	return r
}

func walkRoutes(router *mux.Router, address string) {
	log.Printf("Defined API endpoints for router on: %s\n", address)

	walker := func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		path, _ := route.GetPathTemplate()
		methods, _ := route.GetMethods()
		for m := range methods {
			log.Printf("%-6s %s\n", methods[m], path)
		}
		return nil
	}
	if err := router.Walk(walker); err != nil {
		log.Panicf("Logging err: %s\n", err.Error())
	}
	//	return nil
}

// In practice APIdispatcher doesn't need a termination signal, as it will
// just sit inside http.ListenAndServe, but we keep it for symmetry.
func APIdispatcher(conf *Config, done <-chan struct{}) {
	gob.Register(tapir.WBGlist{}) // Must register the type for gob encoding
	router := SetupRouter(conf)

	walkRoutes(router, viper.GetString("apiserver.address"))
	log.Println("")

	address := viper.GetString("apiserver.address")
	tlsaddress := viper.GetString("apiserver.tlsaddress")
	certfile := viper.GetString("certs.tem.cert")
	keyfile := viper.GetString("certs.tem.key")

	bootstrapaddress := viper.GetString("bootstrapserver.address")
	bootstraptlsaddress := viper.GetString("bootstrapserver.tlsaddress")
	bootstraprouter := SetupBootstrapRouter(conf)

	tlspossible := true

	_, err := os.Stat(certfile)
	if os.IsNotExist(err) {
		tlspossible = false
	}
	_, err = os.Stat(keyfile)
	if os.IsNotExist(err) {
		tlspossible = false
	}

	tlsConfig, err := tapir.NewServerConfig(viper.GetString("certs.cacertfile"), tls.VerifyClientCertIfGiven)
	// Alternatives are: tls.RequireAndVerifyClientCert, tls.VerifyClientCertIfGiven,
	// tls.RequireAnyClientCert, tls.RequestClientCert, tls.NoClientCert

	if err != nil {
		TEMExiter("Error creating API server tls config: %v\n", err)
	}

	tlsServer := &http.Server{
		Addr:      tlsaddress,
		Handler:   router,
		TLSConfig: tlsConfig,
	}
	bootstrapTlsServer := &http.Server{
		Addr:      bootstraptlsaddress,
		Handler:   bootstraprouter,
		TLSConfig: tlsConfig,
	}

	var wg sync.WaitGroup

	log.Println("*** API: Starting API dispatcher #1. Listening on", address)

	if address != "" {
		wg.Add(1)
		go func(wg *sync.WaitGroup) {
			log.Println("*** API: Starting API dispatcher #1. Listening on", address)
			wg.Done()
			TEMExiter(http.ListenAndServe(address, router))
		}(&wg)
	}

	if tlsaddress != "" {
		if tlspossible {
			wg.Add(1)
			go func(wg *sync.WaitGroup) {
				log.Println("*** API: Starting TLS API dispatcher #1. Listening on", tlsaddress)
				wg.Done()
				TEMExiter(tlsServer.ListenAndServeTLS(certfile, keyfile))
			}(&wg)
		} else {
			log.Printf("*** API: APIdispatcher: Error: Cannot provide TLS service without cert and key files.\n")
		}
	}

	if bootstrapaddress != "" {
		wg.Add(1)
		go func(wg *sync.WaitGroup) {
			log.Println("*** API: Starting Bootstrap API dispatcher #1. Listening on", bootstrapaddress)
			wg.Done()
			TEMExiter(http.ListenAndServe(bootstrapaddress, bootstraprouter))
		}(&wg)
	} else {
		log.Println("*** API: No bootstrap address specified")
	}

	if bootstraptlsaddress != "" {
		if tlspossible {
			wg.Add(1)
			go func(wg *sync.WaitGroup) {
				log.Println("*** API: Starting Bootstrap TLS API dispatcher #1. Listening on", bootstraptlsaddress)
				wg.Done()
				TEMExiter(bootstrapTlsServer.ListenAndServeTLS(certfile, keyfile))
			}(&wg)
		} else {
			log.Printf("*** API: APIdispatcher: Error: Cannot provide Bootstrap TLS service without cert and key files.\n")
		}
	} else {
		log.Println("*** API: No bootstrap TLS address specified")
	}

	wg.Wait()
	log.Println("API dispatcher: unclear how to stop the http server nicely.")
}

func BumpSerial(conf *Config, zone string) (string, error) {
	var respch = make(chan RpzCmdResponse, 1)
	conf.TemData.RpzCommandCh <- RpzCmdData{
		Command: "BUMP",
		Zone:    zone,
		Result:  respch,
	}

	resp := <-respch

	if resp.Error {
		log.Printf("BumpSerial: Error from RefreshEngine: %s", resp.ErrorMsg)
		return fmt.Sprintf("Zone %s: error bumping SOA serial: %s", zone, resp.ErrorMsg),
			fmt.Errorf("Zone %s: error bumping SOA serial and epoch: %v", zone, resp.ErrorMsg)
	}

	if resp.Msg == "" {
		resp.Msg = fmt.Sprintf("Zone %s: bumped SOA serial from %d to %d", zone, resp.OldSerial, resp.NewSerial)
	}
	return resp.Msg, nil
}
