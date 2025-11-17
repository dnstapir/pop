/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
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
			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				log.Printf("Error from json encoder: %v", err)
				log.Printf("resp: %v", resp)
			}
		}()

		switch cp.Command {
		case "status":
			log.Printf("Daemon status inquiry\n")
			rt := make(chan tapir.StatusUpdaterResponse)
			var ts *tapir.StatusUpdaterResponse

			conf.Internal.ComponentStatusCh <- tapir.ComponentStatusUpdate{
				Component: "status",
				Status:    tapir.StatusReport,
				Response:  rt,
			}

			select {
			case foo := <-rt:
				ts = &foo
			case <-time.After(2 * time.Second):
				log.Println("Timeout waiting for response on rt channel")
				ts = nil
			}

			resp = tapir.CommandResponse{
				Status: "ok", // only status we know, so far
				Msg:    "We're happy, but send more cookies",
			}
			if ts != nil {
				resp.TapirFunctionStatus = ts.FunctionStatus
			}

		case "stop":
			log.Printf("Daemon instructed to stop\n")
			resp = tapir.CommandResponse{
				Status: "stopping",
				Msg:    "Daemon was happy, but now winding down",
			}
			log.Printf("Stopping MQTT engine\n")
			_, err := conf.PopData.MqttEngine.StopEngine()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}
			conf.Internal.APIStopCh <- struct{}{}
		case "bump":
			resp.Msg, err = BumpSerial(conf, cp.Zone)
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}

		case "mqtt-start":
			_, _, _, err := conf.PopData.MqttEngine.StartEngine()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}
			resp.Msg = "MQTT engine started"

		case "mqtt-stop":
			_, err := conf.PopData.MqttEngine.StopEngine()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}
			resp.Msg = "MQTT engine stopped"

		case "mqtt-restart":
			_, err := conf.PopData.MqttEngine.RestartEngine()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}
			resp.Msg = "MQTT engine restarted"

		case "rpz-add":
			log.Printf("Received RPZ-ADD %s policy %s RPZ source %s command", cp.Name, cp.Policy, cp.RpzSource)

			log.Printf("apihandler: RPZ-ADD 1. Len(ch): %d", len(conf.PopData.RpzCommandCh))
			var respch = make(chan RpzCmdResponse, 1)
			conf.PopData.RpzCommandCh <- RpzCmdData{
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
			conf.PopData.RpzCommandCh <- RpzCmdData{
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
			conf.PopData.RpzCommandCh <- RpzCmdData{
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
			conf.PopData.RpzCommandCh <- RpzCmdData{
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
			me := conf.PopData.MqttEngine
            me.DataMu.Lock() /* Lock because resp.TopicData needs to be accessed safely */
			err := json.NewEncoder(w).Encode(resp)
            me.DataMu.Unlock()
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

		log.Printf("API: received /bootstrap request (cmd: %s) from %s.\n", bp.Command, r.RemoteAddr)

		switch bp.Command {
		case "doubtlist-status":
			me := conf.PopData.MqttEngine
            me.DataMu.Lock()
			stats := me.Stats()
            me.DataMu.Unlock()
			// resp.MsgCounters = stats.MsgCounters
			// resp.MsgTimeStamps = stats.MsgTimeStamps
			resp.TopicData = stats
			// log.Printf("API: doubtlist-status: msgs: %d last msg: %v", stats.MsgCounters[bp.ListName], stats.MsgTimeStamps[bp.ListName])
			log.Printf("API: doubtlist-status: %v", stats)

		case "export-doubtlist":
			td := conf.PopData
			td.mu.RLock()
			defer td.mu.RUnlock()

			doubtlist, ok := td.Lists["doubtlist"][bp.ListName]
			if !ok {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Doubtlist '%s' not found", bp.ListName)
				return
			}
			log.Printf("Found %s doubtlist containing %d names", bp.ListName, len(doubtlist.Names))

			switch bp.Encoding {
			case "gob":
				w.Header().Set("Content-Type", "application/octet-stream")
				w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=doubtlist-%s.gob", bp.ListName))

				encoder := gob.NewEncoder(w)
				err := encoder.Encode(doubtlist)
				if err != nil {
					log.Printf("Error encoding doubtlist: %v", err)
					resp.Error = true
					resp.ErrorMsg = err.Error()
					return
				}

				//			case "protobuf":
				//				w.Header().Set("Content-Type", "application/octet-stream")
				//				w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=doubtlist-%s.protobuf", bp.ListName))
				//
				//				data, err := proto.Marshal(doubtlist)
				//				if err != nil {
				//					log.Printf("Error encoding doubtlist to protobuf: %v", err)
				//					resp.Error = true
				//					resp.ErrorMsg = err.Error()
				//					return
				//				}

				//				_, err = w.Write(data)
				//				if err != nil {
				//					log.Printf("Error writing protobuf data to response: %v", err)
				//					resp.Error = true
				//					resp.ErrorMsg = err.Error()
				//					return
				//				}

			// case "flatbuffer":
			// 	w.Header().Set("Content-Type", "application/octet-stream")
			// 	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=doubtlist-%s.flatbuffer", bp.ListName))

			// 	builder := flatbuffers.NewBuilder(0)
			// 	names := make([]flatbuffers.UOffsetT, len(doubtlist.Names))

			// 	i := 0
			// 	for name := range doubtlist.Names {
			// 		nameOffset := builder.CreateString(name)
			// 		tapir.NameStart(builder)
			// 		tapir.NameAddName(builder, nameOffset)
			// 		names[i] = tapir.NameEnd(builder)
			// 		i++
			// 	}

			// 	tapir.DoubtlistStartNamesVector(builder, len(names))
			// 	for j := len(names) - 1; j >= 0; j-- {
			// 		builder.PrependUOffsetT(names[j])
			// 	}
			// 	namesVector := builder.EndVector(len(names))

			// 	tapir.DoubtlistStart(builder)
			// 	tapir.DoubtlistAddNames(builder, namesVector)
			// 	doubtlistOffset := tapir.DoubtlistEnd(builder)

			// 	builder.Finish(doubtlistOffset)
			// 	buf := builder.FinishedBytes()

			// 	_, err := w.Write(buf)
			// 	if err != nil {
			// 		log.Printf("Error writing flatbuffer data to response: %v", err)
			// 		resp.Error = true
			// 		resp.ErrorMsg = err.Error()
			// 		return
			// 	}

			default:
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Unknown encoding: %s", bp.Encoding)
				return
			}

		default:
			resp.ErrorMsg = fmt.Sprintf("Unknown command: %s", bp.Command)
			resp.Error = true
		}
	}
}

func APIdebug(conf *Config) func(w http.ResponseWriter, r *http.Request) {
	td := conf.PopData

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
			log.Printf("TAPIR-POP debug rrset inquiry")
			if zd, ok := td.RpzSources[dp.Zone]; ok {
				if owner := &zd.Owners[zd.OwnerIndex[dp.Qname]]; owner != nil {
					if rrset, ok := owner.RRtypes[dp.Qtype]; ok {
						resp.RRset = rrset
					}
					log.Printf("TAPIR-POP debug rrset: owner: %v", owner)
				}
			} else {
				resp.Msg = fmt.Sprintf("Zone %s is unknown", dp.Zone)
			}

		case "zonedata":
			log.Printf("TAPIR-POP debug zone inquiry")
			if zd, ok := td.RpzSources[dp.Zone]; ok {
				//			       resp.ZoneData = *zd
				//			       resp.ZoneData.RRKeepFunc = nil
				//			       resp.ZoneData.RRParseFunc = nil
				log.Printf("TAPIR-POP debug zone: name: %s rrs: %d owners: %d", dp.Zone,
					len(zd.RRs), len(zd.Owners))
			} else {
				resp.Msg = fmt.Sprintf("Zone %s is unknown", dp.Zone)
			}

		case "mqtt-stats":
			log.Printf("TAPIR-POP debug MQTT stats")
			resp.TopicData = td.MqttEngine.Stats()

		case "reaper-stats":
			log.Printf("TAPIR-POP debug reaper stats")
			resp.ReaperStats = make(map[string]map[time.Time][]string)
			for SrcName, list := range td.Lists["doubtlist"] {
				resp.ReaperStats[SrcName] = make(map[time.Time][]string)
				for ts, names := range list.ReaperData {
					for name := range names {
						resp.ReaperStats[SrcName][ts] = append(resp.ReaperStats[SrcName][ts], name)
					}
				}
			}

		case "filterlists":
			log.Printf("TAPIR-POP debug allow/deny/doubt lists")
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
						SrcFormat:   td.Lists[t][n].SrcFormat,
					}
				}
			}

		case "gen-output":
			log.Printf("TAPIR-POP debug generate RPZ output")
			err = td.GenerateRpzAxfr()
			if err != nil {
				resp.Error = true
				resp.ErrorMsg = err.Error()
			}
			resp.DenylistedNames = td.DenylistedNames
			resp.DoubtlistedNames = td.DoubtlistedNames
			for _, rpzn := range td.Rpz.Axfr.Data {
				resp.RpzOutput = append(resp.RpzOutput, *rpzn)
			}

		case "send-status":
			log.Printf("TAPIR-POP debug send status")

			rt := make(chan tapir.StatusUpdaterResponse)
			var sur *tapir.StatusUpdaterResponse

			conf.Internal.ComponentStatusCh <- tapir.ComponentStatusUpdate{
				Component: dp.Component,
				Status:    dp.Status,
				Msg:       "debug status update",
				TimeStamp: time.Now(),
				Response:  rt,
			}

			select {
			case foo := <-rt:
				sur = &foo
			case <-time.After(2 * time.Second):
				log.Println("Timeout waiting for response on rt channel")
				sur = nil
			}

			if sur != nil {
				resp.Status = "ok"
				resp.Msg = sur.Msg
			} else {
				resp.Msg = "Status update for component " + dp.Component + " sent"
				resp.Error = true
				resp.ErrorMsg = "Timeout waiting for response on rt channel"
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
	sr.HandleFunc("/ping", tapir.APIping("tapir-pop", conf.BootTime)).Methods("POST")
	sr.HandleFunc("/command", APIcommand(conf)).Methods("POST")
	sr.HandleFunc("/bootstrap", APIbootstrap(conf)).Methods("POST")
	sr.HandleFunc("/debug", APIdebug(conf)).Methods("POST")
	// sr.HandleFunc("/show/api", tapir.APIshowAPI(r)).Methods("GET")

	return r
}

func SetupBootstrapRouter(conf *Config) *mux.Router {
	r := mux.NewRouter().StrictSlash(true)

	sr := r.PathPrefix("/api/v1").Headers("X-API-Key", viper.GetString("apiserver.key")).Subrouter()
	sr.HandleFunc("/ping", tapir.APIping("tapir-pop", conf.BootTime)).Methods("POST")
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
func APIhandler(conf *Config, done <-chan struct{}) {
	gob.Register(tapir.WBGlist{}) // Must register the type for gob encoding
	router := SetupRouter(conf)

	walkRoutes(router, viper.GetString("apiserver.address"))
	log.Println("")

	addresses := viper.GetStringSlice("apiserver.addresses")
	tlsaddresses := viper.GetStringSlice("apiserver.tlsaddresses")
	certfile := viper.GetString("certs.tapir-pop.cert")
	if certfile == "" {
		log.Printf("*** APIhandler: Error: TLS cert file not specified under key certs.tapir-pop.cert")
	}
	keyfile := viper.GetString("certs.tapir-pop.key")
	if keyfile == "" {
		log.Printf("*** APIhandler: Error: TLS key file not specified under key certs.tapir-pop.key")
	}

	bootstrapaddresses := viper.GetStringSlice("bootstrapserver.addresses")
	bootstraptlsaddresses := viper.GetStringSlice("bootstrapserver.tlsaddresses")
	bootstraprouter := SetupBootstrapRouter(conf)

	log.Printf("*** APIhandler: addresses: %v bootstrapaddresses: %v", addresses, bootstrapaddresses)
	log.Printf("*** APIhandler: tlsaddresses: %v bootstraptlsaddresses: %v", tlsaddresses, bootstraptlsaddresses)

	tlspossible := true

	_, err := os.Stat(certfile)
	if os.IsNotExist(err) {
		log.Printf("*** APIhandler: Error: TLS cert file \"%s\" does not exist", certfile)
		tlspossible = false
	}
	_, err = os.Stat(keyfile)
	if os.IsNotExist(err) {
		log.Printf("*** APIhandler: Error: TLS key file \"%s\" does not exist", keyfile)
		tlspossible = false
	}

	tlsConfig, err := tapir.NewServerConfig(viper.GetString("certs.cacertfile"), tls.VerifyClientCertIfGiven)
	// Alternatives are: tls.RequireAndVerifyClientCert, tls.VerifyClientCertIfGiven,
	// tls.RequireAnyClientCert, tls.RequestClientCert, tls.NoClientCert

	if err != nil {
		POPExiter("Error creating API server tls config: %v\n", err)
	}

	var wg sync.WaitGroup

	// log.Println("*** API: Starting API dispatcher #1. Listening on", address)

	if len(addresses) > 0 {
		for idx, address := range addresses {
			wg.Add(1)
			go func(wg *sync.WaitGroup) {
				apiServer := &http.Server{
					Addr:         address,
					Handler:      router,
					ReadTimeout:  10 * time.Second,
					WriteTimeout: 10 * time.Second,
				}

				log.Printf("*** API: Starting API dispatcher #%d. Listening on %s", idx+1, address)
				wg.Done()
				POPExiter(apiServer.ListenAndServe())
			}(&wg)
		}
	}

	if len(tlsaddresses) > 0 {
		if tlspossible {
			for idx, tlsaddress := range tlsaddresses {
				wg.Add(1)
				go func(wg *sync.WaitGroup) {
					tlsServer := &http.Server{
						Addr:         tlsaddress,
						Handler:      router,
						TLSConfig:    tlsConfig,
						ReadTimeout:  10 * time.Second,
						WriteTimeout: 10 * time.Second,
					}
					log.Printf("*** API: Starting TLS API dispatcher #%d. Listening on %s", idx+1, tlsaddress)
					wg.Done()
					POPExiter(tlsServer.ListenAndServeTLS(certfile, keyfile))
				}(&wg)
			}
		} else {
			log.Printf("*** API: APIdispatcher: Error: Cannot provide TLS service without cert and key files.\n")
		}
	}

	if len(bootstrapaddresses) > 0 {
		for idx, address := range bootstrapaddresses {
			wg.Add(1)
			go func(wg *sync.WaitGroup) {
				apiServer := &http.Server{
					Addr:         address,
					Handler:      bootstraprouter,
					ReadTimeout:  10 * time.Second,
					WriteTimeout: 10 * time.Second,
				}
				log.Printf("*** API: Starting Bootstrap API dispatcher #%d. Listening on %s", idx+1, address)
				wg.Done()
				POPExiter(apiServer.ListenAndServe())
			}(&wg)
		}
	} else {
		log.Println("*** API: No bootstrap address specified")
	}

	if len(bootstraptlsaddresses) > 0 {
		if tlspossible {
			for idx, address := range bootstraptlsaddresses {
				wg.Add(1)
				go func(wg *sync.WaitGroup) {
					bootstrapTlsServer := &http.Server{
						Addr:         address,
						Handler:      bootstraprouter,
						TLSConfig:    tlsConfig,
						ReadTimeout:  10 * time.Second,
						WriteTimeout: 10 * time.Second,
					}

					log.Printf("*** API: Starting Bootstrap TLS API dispatcher #%d. Listening on %s", idx+1, address)
					wg.Done()
					POPExiter(bootstrapTlsServer.ListenAndServeTLS(certfile, keyfile))
				}(&wg)
			}
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
	conf.PopData.RpzCommandCh <- RpzCmdData{
		Command: "BUMP",
		Zone:    zone,
		Result:  respch,
	}

	resp := <-respch

	if resp.Error {
		log.Printf("BumpSerial: Error from RefreshEngine: %s", resp.ErrorMsg)
		return fmt.Sprintf("Zone %s: error bumping SOA serial: %s", zone, resp.ErrorMsg),
			fmt.Errorf("zone %s: error bumping SOA serial and epoch: %v", zone, resp.ErrorMsg)
	}

	if resp.Msg == "" {
		resp.Msg = fmt.Sprintf("Zone %s: bumped SOA serial from %d to %d", zone, resp.OldSerial, resp.NewSerial)
	}
	return resp.Msg, nil
}
