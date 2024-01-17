/*
 * Johan Stenstam, johani@johani.org
 */
package tapir

// Client side API client calls

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	// "crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

func printConnState(conn *tls.Conn) {
	log.Print(">>>>>>>>>>>>>>>> TLS Connection State <<<<<<<<<<<<<<<<")
	state := conn.ConnectionState()
	log.Printf("Version: %x", state.Version)
	log.Printf("HandshakeComplete: %t", state.HandshakeComplete)
	log.Printf("DidResume: %t", state.DidResume)
	log.Printf("CipherSuite: %x", state.CipherSuite)
	log.Printf("NegotiatedProtocol: %s", state.NegotiatedProtocol)
	log.Printf("NegotiatedProtocolIsMutual: %t", state.NegotiatedProtocolIsMutual)

	log.Print("Certificate chain:")
	for i, cert := range state.PeerCertificates {
		subject := cert.Subject
		issuer := cert.Issuer
		log.Printf(" %d s:/C=%v/ST=%v/L=%v/O=%v/OU=%v/CN=%s", i, subject.Country, subject.Province, subject.Locality,
			subject.Organization, subject.OrganizationalUnit, subject.CommonName)
		log.Printf("   i:/C=%v/ST=%v/L=%v/O=%v/OU=%v/CN=%s", issuer.Country, issuer.Province, issuer.Locality,
			issuer.Organization, issuer.OrganizationalUnit, issuer.CommonName)
	}
	log.Print(">>>>>>>>>>>>>>>> State End <<<<<<<<<<<<<<<<")
}

type ApiClient struct {
	BaseUrl    string
	AuthMethod string
	ApiKey     string
	Timeout    int
	ClientName string	// ClientName is used to figure out which client cert to use for TLS setup.
	UseTLS     bool
	Verbose    bool
	Debug      bool
	HttpClient *http.Client
}

func NewApiClient(params ApiClient) *ApiClient {
	var client *http.Client
	var path string

	if params.Timeout > 20 {
		params.Timeout = 20
	}

	if params.ClientName == "" {
	   params.ClientName = "axfr-cli"
	}

	ac := ApiClient{
		BaseUrl:    params.BaseUrl,
		AuthMethod: params.AuthMethod,
		ApiKey:     params.ApiKey,
		Timeout:    params.Timeout,
		ClientName: params.ClientName,
		UseTLS:     params.UseTLS,
		Verbose:    GlobalCF.Verbose,
		Debug:      GlobalCF.Debug,
	}

	var protocol = "http"
	if ac.UseTLS {
		protocol = "https"
	}

	if ac.BaseUrl == "" {
		log.Fatalf("BaseUrl not defined. Abort.")
	}
	if ac.Debug {
		fmt.Printf("NewApiClient: Using baseurl \"%s\"\n", ac.BaseUrl)
	}

	// if the service string contains either https:// or http:// then that
	// will override the usetls parameter.
	if strings.HasPrefix(strings.ToLower(ac.BaseUrl), "https://") {
		ac.UseTLS = true
		protocol = "https"
		ac.BaseUrl = ac.BaseUrl[8:]
	} else if strings.HasPrefix(strings.ToLower(ac.BaseUrl), "http://") {
		ac.UseTLS = false
		protocol = "http"
		ac.BaseUrl = ac.BaseUrl[7:]
	}

	ip, port, err := net.SplitHostPort(ac.BaseUrl)
	if err != nil {
		log.Fatalf("NewApiClient: Error from SplitHostPort: %s. Abort.", err)
	}

	if strings.Contains(port, "/") {
		portparts := strings.Split(port, "/")
		port = portparts[0]
		path = "/" + strings.Join(portparts[1:], "/")
	}

	addr := net.ParseIP(ip)
	if addr == nil {
		log.Fatalf("NewApiClient: Illegal address specification: %s. Abort.", ip)
	}

	ac.BaseUrl = fmt.Sprintf("%s://%s:%s%s", protocol, addr.String(), port, path)

	if ac.Debug {
		fmt.Printf("NAC: Debug: ip: %s port: %s path: '%s'. BaseURL: %s\n",
			ip, port, path, ac.BaseUrl)
	}

	if ac.UseTLS {
		cacert := viper.GetString("certs.cacertfile")
		if cacert == "" {
			log.Fatalf("Cannot use TLS without a CA cert, see config key certs.cacertfile")
		}

		cd := viper.GetString("certs.certdir") + "/clients"

		tlsConfig, err := NewClientConfig(viper.GetString("certs.cacertfile"),
			fmt.Sprintf("%s/%s.key", cd, ac.ClientName),
			fmt.Sprintf("%s/%s.crt", cd, ac.ClientName))
		if err != nil {
			log.Fatalf("NewApiClient: Error: Could not set up TLS: %v", err)
		} else {
			client = &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: tlsConfig,
				},
				Timeout: time.Duration(ac.Timeout) * time.Second,
			}
		}
	} else {
		client = &http.Client{
			Timeout: time.Duration(ac.Timeout) * time.Second,
			// CheckRedirect: redirectPolicyFunc,
		}
	}

	if ac.AuthMethod != "Authorization" && ac.AuthMethod != "X-API-Key" && ac.AuthMethod != "none" {
		log.Fatalf("NewApiClient: unknown http auth method: %s", ac.AuthMethod)
	}

	ac.HttpClient = client
	return &ac
}

func (api *ApiClient) Setup() error {
	var client *http.Client
	var path string

	if api.Timeout > 20 {
		api.Timeout = 20
	}

	api.UseTLS = false
	api.Verbose = GlobalCF.Verbose
	api.Debug = GlobalCF.Debug

	var protocol = "http"

	if api.BaseUrl == "" {
		return fmt.Errorf("BaseUrl not defined. Abort.")
	}
	if api.Debug {
		log.Printf("api.Setup(): Using baseurl \"%s\"\n", api.BaseUrl)
	}

	// if the service string contains either https:// or http:// then that
	// will override the usetls parameter.
	if strings.HasPrefix(strings.ToLower(api.BaseUrl), "https://") {
		api.BaseUrl = api.BaseUrl[8:]
	} else if strings.HasPrefix(strings.ToLower(api.BaseUrl), "http://") {
		api.BaseUrl = api.BaseUrl[7:]
	}

	ip, port, err := net.SplitHostPort(api.BaseUrl)
	if err != nil {
		return fmt.Errorf("api.Setup(): Error from SplitHostPort: %s. Abort.", err)
	}

	if strings.Contains(port, "/") {
		portparts := strings.Split(port, "/")
		port = portparts[0]
		path = "/" + strings.Join(portparts[1:], "/")
	}

	addr := net.ParseIP(ip)
	if addr == nil {
		return fmt.Errorf("api.Setup(): Illegal address specification: %s. Abort.", ip)
	}

	api.BaseUrl = fmt.Sprintf("%s://%s:%s%s", protocol, addr.String(), port, path)

	if api.Debug {
		log.Printf("NAC: Debug: ip: %s port: %s path: '%s'. BaseURL: %s\n",
			ip, port, path, api.BaseUrl)
	}

	if api.UseTLS {
		return fmt.Errorf("api.Setup(): Use api.SetupTls() for setup of a TLS client")
	} 

	client = &http.Client{
		Timeout: time.Duration(api.Timeout) * time.Second,
		// CheckRedirect: redirectPolicyFunc,
	}

	if api.AuthMethod != "Authorization" && api.AuthMethod != "X-API-Key" && api.AuthMethod != "none" {
		return fmt.Errorf("api.Setup(): unknown http auth method: %s", api.AuthMethod)
	}

	api.HttpClient = client
	return nil
}

// This is a version of the ApiClient constructor that should replace NewTlsApiClient()
func (api *ApiClient) SetupTLS(tlsConfig *tls.Config) error {
	var client *http.Client
	var path string

	api.UseTLS = false
	api.Verbose = GlobalCF.Verbose
	api.Debug = GlobalCF.Debug

	var protocol = "https"

	if api.BaseUrl == "" {
		return fmt.Errorf("BaseUrl not defined. Abort.")
	}
	if api.Debug {
		log.Printf("api.SetupTLS: Using baseurl \"%s\"\n", api.BaseUrl)
	}

	// Strip off https:// or http://
	if strings.HasPrefix(strings.ToLower(api.BaseUrl), "https://") {
		api.BaseUrl = api.BaseUrl[8:]
	} else if strings.HasPrefix(strings.ToLower(api.BaseUrl), "http://") {
		api.BaseUrl = api.BaseUrl[7:]
	}

	ip, port, err := net.SplitHostPort(api.BaseUrl)
	if err != nil {
		return fmt.Errorf("api.SetupTLS: Error from SplitHostPort: %s. Abort.", err)
	}

	if strings.Contains(port, "/") {
		portparts := strings.Split(port, "/")
		port = portparts[0]
		path = "/" + strings.Join(portparts[1:], "/")
	}

	addr := net.ParseIP(ip)
	if addr == nil {
		return fmt.Errorf("api.SetupTLS: Illegal address specification: %s. Abort.", ip)
	}

	api.BaseUrl = fmt.Sprintf("%s://%s:%s%s", protocol, addr.String(), port, path)

	if api.Debug {
		log.Printf("api.SetupTLS: Debug: ip: %s port: %s path: '%s'. BaseURL: %s\n",
			ip, port, path, api.BaseUrl)
	}

	cacert := viper.GetString("certs.cacertfile")
	if cacert == "" {
		return fmt.Errorf("Cannot use TLS without a CA cert, see config key certs.cacertfile")
	}
	_, err = os.ReadFile(cacert)
	if err != nil {
		return fmt.Errorf("Error reading CA file '%s': %v\n", cacert, err)
	}
	//	roots := x509.NewCertPool()
	//	ok := roots.AppendCertsFromPEM(caCertPEM)
	//	if !ok {
	//		log.Printf("Error parsing root cert: %v\n", err)
	//	}

	client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: 10 * time.Second,
	}

	if api.AuthMethod != "Authorization" && api.AuthMethod != "X-API-Key" && api.AuthMethod != "none" {
		log.Fatalf("api.SetupTLS: unknown http auth method: %s", api.AuthMethod)
	}

	api.HttpClient = client
	return nil
}

func (api *ApiClient) UrlReport(method, endpoint string, data []byte) {
	if !api.Debug {
		return
	}

	if api.UseTLS {
		fmt.Printf("API%s: apiurl: %s (using TLS)\n", method, api.BaseUrl+endpoint)
	} else {
		fmt.Printf("API%s: apiurl: %s\n", method, api.BaseUrl+endpoint)
	}

	if (method == http.MethodPost) || (method == http.MethodPut) {
		var prettyJSON bytes.Buffer

		error := json.Indent(&prettyJSON, data, "", "  ")
		if error != nil {
			log.Println("JSON parse error: ", error)
		}
		fmt.Printf("API%s: posting %d bytes of data: %s\n", method, len(data), prettyJSON.String())
	}
}

// this function will die when we kill the individual request functions.
func (api *ApiClient) AddAuthHeader(req *http.Request) {
	req.Header.Add("Content-Type", "application/json")
	if api.AuthMethod == "X-API-Key" {
		req.Header.Add("X-API-Key", api.ApiKey)
	} else if api.AuthMethod == "Authorization" {
		req.Header.Add("Authorization", fmt.Sprintf("token %s", api.ApiKey))
	} else if api.AuthMethod == "none" {
		// do not add any authentication header at all
	}
}

func (api *ApiClient) Request(method, endpoint string, data []byte) (int, []byte, error) {
	api.UrlReport(method, endpoint, data)

	req, err := http.NewRequest(method, api.BaseUrl+endpoint, bytes.NewBuffer(data))
	req.Header.Add("Content-Type", "application/json")
	if api.AuthMethod == "X-API-Key" {
		req.Header.Add("X-API-Key", api.ApiKey)
	} else if api.AuthMethod == "Authorization" {
		req.Header.Add("Authorization", fmt.Sprintf("token %s", api.ApiKey))
	} else if api.AuthMethod == "none" {
		// do not add any authentication header at all
	}
	resp, err := api.HttpClient.Do(req)

	if err != nil {
		return 501, nil, err
	}

	defer resp.Body.Close()
	buf, err := ioutil.ReadAll(resp.Body)

	if api.Debug {
		var prettyJSON bytes.Buffer

		error := json.Indent(&prettyJSON, buf, "", "  ")
		if error != nil {
			log.Println("JSON parse error: ", error)
		}
		fmt.Printf("requestHelper: received %d bytes of response data: %s\n", len(buf), prettyJSON.String())
	}

	// not bothering to copy buf, this is a one-off
	return resp.StatusCode, buf, err
}

func (api *ApiClient) RequestNG(method, endpoint string, data interface{}, dieOnError bool) (int, []byte, error) {
	bytebuf := new(bytes.Buffer)
	err := json.NewEncoder(bytebuf).Encode(data)
	if err != nil {
		fmt.Printf("api.RequestNG: Error from json.NewEncoder: %v\n", err)
		if dieOnError {
			os.Exit(1)
		}
	}

	api.UrlReport(method, endpoint, bytebuf.Bytes())

	if api.Debug {
		fmt.Printf("api.RequestNG: %s %s dieOnError: %v\n", method, endpoint, dieOnError)
	}

	req, err := http.NewRequest(method, api.BaseUrl+endpoint, bytebuf)
	req.Header.Add("Content-Type", "application/json")
	if api.AuthMethod == "X-API-Key" {
		req.Header.Add("X-API-Key", api.ApiKey)
	} else if api.AuthMethod == "Authorization" {
		req.Header.Add("Authorization", fmt.Sprintf("token %s", api.ApiKey))
	} else if api.AuthMethod == "none" {
		// do not add any authentication header at all
	}
	resp, err := api.HttpClient.Do(req)

	if err != nil {
		if api.Debug {
			fmt.Printf("api.RequestNG: %s %s dieOnError: %v err: %v\n", method, endpoint, dieOnError, err)
		}

		var msg string
		if strings.Contains(err.Error(), "connection refused") {
			msg = fmt.Sprintf("Connection refused. Server process probably not running.")
		} else {
			fmt.Sprintf("Error from API request %s: %v", method, err)
		}
		if dieOnError {
			fmt.Printf("%s\n", msg)
			os.Exit(1)
		} else {
			return 501, nil, err
		}
	}

	status := resp.StatusCode
	defer resp.Body.Close()
	if api.Debug {
		fmt.Printf("Status from %s: %d\n", method, status)
	}

	buf, err := ioutil.ReadAll(resp.Body)

	if api.Debug {
		var prettyJSON bytes.Buffer

		error := json.Indent(&prettyJSON, buf, "", "  ")
		if error != nil {
			log.Println("JSON parse error: ", error)
		}
		fmt.Printf("API%s: received %d bytes of response data: %s\n", method, len(buf), prettyJSON.String())
	}

	// not bothering to copy buf, this is a one-off
	return status, buf, nil
}
