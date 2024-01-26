/*
 * Copyright (c) DNS TAPIR
 */
 
package tapir

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/eclipse/paho.golang/paho"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/spf13/viper"
)

type MqttEngine struct {
     Topic	   string
     ClientID	   string
     Server	   string
     QoS	   int		
     PrivKey	   *ecdsa.PrivateKey
     PubKey	   any
     Client	   *paho.Client
     ClientCert	   tls.Certificate
     CaCertPool	   *x509.CertPool
     MsgChan	   chan *paho.Publish
}

func newMqttEngine() (*MqttEngine, error) {
	server := viper.GetString("mqtt.server")
	if server == "" {
	   return nil, fmt.Errorf("MQTT server not specified in config")
	}

	topic := viper.GetString("mqtt.topic")
	if topic == "" {
	   return nil, fmt.Errorf("MQTT topic not specified in config")
	}

	clientid := viper.GetString("mqtt.pub.clientid")
	if clientid == "" {
	   return nil, fmt.Errorf("MQTT client id not specified in config")
	}
	
	clientCertFile := viper.GetString("mqtt.pub.clientcert")
	if clientCertFile == "" {
	   log.Fatal("MQTT client cert file not specified in config")
	}
	
	clientKeyFile := viper.GetString("mqtt.pub.clientkey")
	if clientKeyFile == "" {
	   log.Fatal("MQTT client key file not specified in config")
	}

	cacertFile := viper.GetString("mqtt.cacert")
	if cacertFile == "" {
	   log.Fatal("MQTT CA cert file not specified in config")
	}

	signingKeyFile := viper.GetString("mqtt.pub.signingkey")
	if signingKeyFile == "" {
	   log.Fatal("MQTT signing key file not specified in config")
	}

	// Setup CA cert for validating the MQTT connection
	caCert, err := os.ReadFile(cacertFile)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	ok := caCertPool.AppendCertsFromPEM([]byte(caCert))
	if !ok {
		panic("failed to parse CA certificate")
	}

	// Setup client cert/key for mTLS authentication
	clientCert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
	if err != nil {
		log.Fatal(err)
	}

	return &MqttEngine{
			Topic:		topic,
			ClientID:	clientid,
			Server:		server,
			ClientCert:	clientCert,
			CaCertPool:	caCertPool,
	       }, nil
}

func NewMqttPublisher() (*MqttEngine, error) {

     me, err := newMqttEngine()
     if err != nil {
     	return me, err
     }
     
	signingKeyFile := viper.GetString("mqtt.pub.signingkey")
	if signingKeyFile == "" {
	   log.Fatal("MQTT signing key file not specified in config")
	}

	signingKey, err := os.ReadFile(signingKeyFile)
	if err != nil {
		log.Fatal(err)
	}

	// Setup key used for creating the JWS
	pemBlock, _ := pem.Decode(signingKey)
	if pemBlock == nil || pemBlock.Type != "EC PRIVATE KEY" {
		log.Fatal("failed to decode PEM block containing private key")
	}
	privKey, err := x509.ParseECPrivateKey(pemBlock.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	me.PrivKey = privKey

	// Setup connection to the MQTT bus
	conn, err := tls.Dial("tcp", me.Server, &tls.Config{
		RootCAs:      me.CaCertPool,
		Certificates: []tls.Certificate{me.ClientCert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		log.Fatal(err)
	}

	c := paho.NewClient(paho.ClientConfig{
		Conn: conn,
	})

	me.Client = c

	return me, nil
}

func NewMqttSubscriber() (*MqttEngine, error) {

     me, err := newMqttEngine()
     if err != nil {
     	return me, err
     }
     
	me.QoS = viper.GetInt("mqtt.sub.qos")
	if me.QoS == 0 {
	   fmt.Printf("MQTT subsscribe quality-of-service not specified in config, using 0")
	}

	signingPubFile := viper.GetString("mqtt.sub.validatorkey")
	if signingPubFile == "" {
	   log.Fatal("MQTT validator pub file not specified in config")
	}

	signingPub, err := os.ReadFile(signingPubFile)
	if err != nil {
		log.Fatal(err)
	}

	// Setup key used for creating the JWS
	pemBlock, _ := pem.Decode(signingPub)
	if pemBlock == nil || pemBlock.Type != "PUBLIC KEY" {
		log.Fatal("failed to decode PEM block containing public key")
	}
	pubKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	me.PubKey = pubKey
	log.Printf("PubKey is of type %t", pubKey)

	// Setup connection to the MQTT bus
	conn, err := tls.Dial("tcp", me.Server, &tls.Config{
		RootCAs:      me.CaCertPool,
		Certificates: []tls.Certificate{me.ClientCert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		log.Fatal(err)
	}

	logger := log.New(os.Stdout, "SUB: ", log.LstdFlags)

	me.MsgChan = make(chan *paho.Publish)

	c := paho.NewClient(paho.ClientConfig{
		Router: paho.NewSingleHandlerRouter(func(m *paho.Publish) {
			me.MsgChan <- m
		}),
		Conn: conn,
	})
	c.SetDebugLogger(logger)
	c.SetErrorLogger(logger)

	me.Client = c

	return me, nil
}

// Based on publish example at: https://github.com/eclipse/paho.golang/tree/master/paho/cmd/stdinpub
func (mp *MqttEngine) RunPublisher() {
	stdin := bufio.NewReader(os.Stdin)

	cp := &paho.Connect{
		KeepAlive:  30,
		ClientID:   mp.ClientID,
		CleanStart: true,
	}

	ca, err := mp.Client.Connect(context.Background(), cp)
	if err != nil {
		log.Fatalln(err)
	}
	if ca.ReasonCode != 0 {
		log.Fatalf("Failed to connect to %s : %d - %s", mp.Server, ca.ReasonCode, ca.Properties.ReasonString)
	}

	fmt.Printf("Connected to %s\n", mp.Server)

	ic := make(chan os.Signal, 1)
	signal.Notify(ic, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ic
		fmt.Println("signal received, exiting")
		if mp.Client != nil {
			d := &paho.Disconnect{ReasonCode: 0}
			err := mp.Client.Disconnect(d)
			if err != nil {
				log.Fatal(err)
			}
		}
		os.Exit(0)
	}()

	for {
		message, err := stdin.ReadString('\n')
		if err == io.EOF {
			os.Exit(0)
		}

		signedMessage, err := jws.Sign([]byte(message), jws.WithJSON(), jws.WithKey(jwa.ES256, mp.PrivKey))
		if err != nil {
			log.Printf("failed to created JWS message: %s", err)
			return
		}

		if _, err = mp.Client.Publish(context.Background(), &paho.Publish{
			Topic:   mp.Topic,
			Payload: signedMessage,
		}); err != nil {
			log.Println("error sending message:", err)
			continue
		}
		log.Printf("sent signed JWS: %s", string(signedMessage))
	}
}

// Based on subscribe example at: https://github.com/eclipse/paho.golang/tree/master/paho/cmd/stdoutsub
func (me *MqttEngine) RunSubscriber() {

	cp := &paho.Connect{
		KeepAlive:  30,
		ClientID:   me.ClientID,
		CleanStart: true,
	}

	ca, err := me.Client.Connect(context.Background(), cp)
	if err != nil {
		log.Fatalln(err)
	}
	if ca.ReasonCode != 0 {
		log.Fatalf("Failed to connect to %s : %d - %s", me.Server, ca.ReasonCode, ca.Properties.ReasonString)
	}

	fmt.Printf("Connected to %s\n", me.Server)

	ic := make(chan os.Signal, 1)
	signal.Notify(ic, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ic
		fmt.Println("signal received, exiting")
		if me.Client != nil {
			d := &paho.Disconnect{ReasonCode: 0}
			err = me.Client.Disconnect(d)
			if err != nil {
				log.Fatal(err)
			}
		}
		os.Exit(0)
	}()

	sa, err := me.Client.Subscribe(context.Background(), &paho.Subscribe{
		Subscriptions: []paho.SubscribeOptions{
			{Topic: me.Topic, QoS: byte(me.QoS)},
		},
	})
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(string(sa.Reasons))
	if sa.Reasons[0] != byte(me.QoS) {
		log.Fatalf("Failed to subscribe to %s : %d", me.Topic, sa.Reasons[0])
	}
	log.Printf("Subscribed to %s", me.Topic)

	for m := range me.MsgChan {
		log.Println("received message:", string(m.Payload))
		verified, err := jws.Verify(m.Payload, jws.WithKey(jwa.ES256, me.PubKey))
		if err != nil {
			log.Fatalf("failed to verify message: %s", err)
		}
		log.Printf("verified message: %s", verified)
	}
}
