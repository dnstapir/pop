/*
 * Johan Stenstam, johani@johani.org
 */
package tapir

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

func (api *ApiClient) SendPing(pingcount int, dieOnError bool) (PingResponse, error) {
	data := PingPost{
		Msg:   "One ping to rule them all and in the darkness bing them.",
		Pings: pingcount,
	}

	_, buf, err := api.RequestNG(http.MethodPost, "/ping", data, dieOnError)
	if err != nil {
		return PingResponse{}, err
	}

	var pr PingResponse
	err = json.Unmarshal(buf, &pr)
	if err != nil {
		log.Printf("Error parsing JSON for PingResponse: %s", string(buf))
		log.Fatalf("Error from json.Unmarshal PingResponse: %v\n", err)
	}
	return pr, nil
}

func (api *ApiClient) ShowApi() {
	_, buf, _ := api.RequestNG(http.MethodGet, "/show/api", nil, true)

	var sar ShowAPIresponse
	err := json.Unmarshal(buf, &sar)
	if err != nil {
		log.Printf("Error parsing JSON for ShowAPIResponse: %s", string(buf))
		log.Fatalf("Error from unmarshal of ShowAPIresponse: %v\n", err)
	}
	for _, ep := range sar.Data[1:] {
		fmt.Printf("%s\n", ep)
	}
}
