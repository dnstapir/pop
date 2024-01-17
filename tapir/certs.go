package tapir

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
)

type Config struct {
	CAFile   string `validate:"existing-file-ro"`
	KeyFile  string `validate:"existing-file-ro"`
	CertFile string `validate:"existing-file-ro"`
}

type SimpleConfig struct {
	CAFile string `validate:"existing-file-ro"`
}

func loadCertPool(filename string) (*x509.CertPool, error) {
	caCert, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	return caCertPool, nil
}

// Create a tls.Config for a server.
// clientAuth: tls.NoClientCert                => Accept any client.
// clientAuth: tls.RequireAndVerifyClientCert  => Only accept client with valid cert.
func NewServerConfig(caFile string, clientAuth tls.ClientAuthType) (*tls.Config, error) {
	caCertPool, err := loadCertPool(caFile)
	if err != nil {
		return nil, err
	}

	config := &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: clientAuth,
		NextProtos: []string{"h2", "http/1.1"},
	}

	config.BuildNameToCertificate()

	return config, nil
}

func NewClientConfig(caFile, keyFile, certFile string) (*tls.Config, error) {

	caCertPool, err := loadCertPool(caFile)
	if err != nil {
		return nil, err
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}
	config.BuildNameToCertificate()

	return config, nil
}

// NewSimpleClientConfig creates a TLS config with a common CA cert,
// specified in caFile, but without a client certificate.
func NewSimpleClientConfig(caFile string) (*tls.Config, error) {
	caCertPool, err := loadCertPool(caFile)
	if err != nil {
		return nil, err
	}

	config := &tls.Config{
		RootCAs: caCertPool,
	}

	return config, nil
}
