/*
 *
 */
package tapir

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

var pongs int = 0

func APIping(appName string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		tls := ""
		if r.TLS != nil {
			tls = "TLS "
		}

		log.Printf("APIping: received %s/ping request from %s.\n", tls, r.RemoteAddr)

		decoder := json.NewDecoder(r.Body)
		var pp PingPost
		err := decoder.Decode(&pp)
		if err != nil {
			log.Println("APIping: error decoding ping post:", err)
		}
		pongs += 1
		hostname, _ := os.Hostname()
		response := PingResponse{
			Time:   time.Now(),
			Client: r.RemoteAddr,
			Msg:    fmt.Sprintf("%spong from %s @ %s", tls, appName, hostname),
			Pings:  pp.Pings + 1,
			Pongs:  pongs,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}
