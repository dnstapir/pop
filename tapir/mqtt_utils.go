/*
 * Copyright (c) DNS TAPIR
 */

package tapir

import (
	//	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	//	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/eclipse/paho.golang/paho"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/spf13/viper"
)

func Chomp(s string) string {
	if len(s) > 0 && strings.HasSuffix(s, "\n") {
		return s[:len(s)-1]
	}
	return s
}

type MqttEngine struct {
	Topic        string
	ClientID     string
	Server       string
	QoS          int
	PrivKey      *ecdsa.PrivateKey
	PubKey       any
	Client       *paho.Client
	ClientCert   tls.Certificate
	CaCertPool   *x509.CertPool
	MsgChan      chan *paho.Publish
	CmdChan      chan MqttPubSubCmd
	PublishChan  chan MqttPublish
	CanPublish   bool
	CanSubscribe bool
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

	clientCertFile := viper.GetString("mqtt.clientcert")
	if clientCertFile == "" {
		log.Fatal("MQTT client cert file not specified in config")
	}

	clientKeyFile := viper.GetString("mqtt.clientkey")
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
		log.Fatalf("failed to parse CA certificate in file %s", cacertFile)
	}

	// Setup client cert/key for mTLS authentication
	clientCert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
	if err != nil {
		log.Fatal(err)
	}

	return &MqttEngine{
		Topic:      topic,
		Server:     server,
		ClientCert: clientCert,
		CaCertPool: caCertPool,
	}, nil
}

func NewMqttPublisher(clientid string) (*MqttEngine, error) {
	me, err := newMqttEngine()
	if err != nil {
		return me, err
	}

	if clientid == "" {
		return nil, fmt.Errorf("MQTT client id not specified")
	}
	me.ClientID = clientid

	signingKeyFile := viper.GetString("mqtt.pub.signingkey")
	if signingKeyFile == "" {
		// log.Fatal("MQTT signing key file not specified in config")
		log.Printf("MQTT signing key file not specified in config, publish not possible")
	} else {
		signingKey, err := os.ReadFile(signingKeyFile)
		if err != nil {
			log.Fatal(err)
		}

		// Setup key used for creating the JWS
		pemBlock, _ := pem.Decode(signingKey)
		if pemBlock == nil || pemBlock.Type != "EC PRIVATE KEY" {
			log.Fatal("failed to decode PEM block containing private key")
		}
		me.PrivKey, err = x509.ParseECPrivateKey(pemBlock.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		me.CanPublish = true
	}

	//-----

	me.QoS = viper.GetInt("mqtt.sub.qos")
	if me.QoS == 0 {
		fmt.Printf("MQTT subscribe quality-of-service not specified in config, using 0")
	}

	signingPubFile := viper.GetString("mqtt.sub.validatorkey")
	if signingPubFile == "" {
		// log.Fatal("MQTT validator pub file not specified in config")
		log.Printf("MQTT validator pub file not specified in config, subscribe not possible")
	} else {
		signingPub, err := os.ReadFile(signingPubFile)
		if err != nil {
			log.Fatal(err)
		}

		// Setup key used for creating the JWS
		pemBlock, _ := pem.Decode(signingPub)
		if pemBlock == nil || pemBlock.Type != "PUBLIC KEY" {
			log.Fatal("failed to decode PEM block containing public key")
		}
		me.PubKey, err = x509.ParsePKIXPublicKey(pemBlock.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("PubKey is of type %t", me.PubKey)
		me.CanSubscribe = true
	}

	//-----

	// Setup connection to the MQTT bus
	conn, err := tls.Dial("tcp", me.Server, &tls.Config{
		RootCAs:      me.CaCertPool,
		Certificates: []tls.Certificate{me.ClientCert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		log.Fatal(err)
	}

	logger := log.New(os.Stdout, fmt.Sprintf("SUB (%s): ", me.ClientID), log.LstdFlags)

	me.MsgChan = make(chan *paho.Publish)

	c := paho.NewClient(paho.ClientConfig{
		// XXX: The router seems to only bee needed for subscribers
		Router: paho.NewSingleHandlerRouter(func(m *paho.Publish) {
			me.MsgChan <- m
		}),
		Conn: conn,
	})

	c.SetDebugLogger(logger)
	c.SetErrorLogger(logger)

	me.Client = c

	me.CmdChan = make(chan MqttPubSubCmd, 1)
	me.PublishChan = make(chan MqttPublish, 10)

	StartEngine := func(resp chan MqttPubSubResponse) {
		cp := &paho.Connect{
			KeepAlive:  30,
			ClientID:   me.ClientID,
			CleanStart: true,
		}

		ca, err := me.Client.Connect(context.Background(), cp)
		if err != nil {
			resp <- MqttPubSubResponse{
				Error:    true,
				ErrorMsg: fmt.Sprintf("Error from mp.Client.Connect: %v", err),
			}
		}
		if ca.ReasonCode != 0 {
			resp <- MqttPubSubResponse{
				Error: true,
				ErrorMsg: fmt.Sprintf("Failed to connect to %s: %d - %s", me.Server,
					ca.ReasonCode, ca.Properties.ReasonString),
			}
		}
		fmt.Printf("Connected to %s\n", me.Server)
		resp <- MqttPubSubResponse{
			Error:  false,
			Status: "all ok",
		}

//		if !me.CanPublish {
//			resp <- MqttPubSubResponse{
//				Error:    true,
//				ErrorMsg: fmt.Sprintf("Engine has no signing key, publish not possible"),
//			}
//		}

		if me.CanSubscribe {
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
		}
	}

	StopEngine := func(resp chan MqttPubSubResponse) {
		if me.Client != nil {
			d := &paho.Disconnect{ReasonCode: 0}
			err := me.Client.Disconnect(d)
			if err != nil {
				resp <- MqttPubSubResponse{}
			}
		}
	}

	go func() {
		var msg string
		buf := new(bytes.Buffer)
		jenc := json.NewEncoder(buf)

		for {
			select {
			case outbox := <-me.PublishChan:
				switch outbox.Type {
				case "text":
					msg = outbox.Msg
					log.Printf("Publisher: received text msg: %s", msg)

				case "data":
					log.Printf("Publisher: received raw data: %v", outbox.Data)
					buf.Reset()
					err = jenc.Encode(outbox.Data)
					if err != nil {
						log.Printf("Error from json.NewEncoder: %v", err)
						continue
					}
					msg = buf.String()
				}

				signedMessage, err := jws.Sign([]byte(msg), jws.WithJSON(),
					jws.WithKey(jwa.ES256, me.PrivKey))
				if err != nil {
					log.Printf("failed to create JWS message: %s", err)
				}

				if _, err = me.Client.Publish(context.Background(), &paho.Publish{
					Topic:   me.Topic,
					Payload: signedMessage,
				}); err != nil {
					log.Println("error sending message:", err)
					continue
				}
				if GlobalCF.Debug {
				   log.Printf("sent signed JWS: %s", string(signedMessage))
				}

			case inbox := <-me.MsgChan:
			     	if GlobalCF.Debug {
				   log.Println("received message:", string(inbox.Payload))
				}
				verified, err := jws.Verify(inbox.Payload, jws.WithKey(jwa.ES256, me.PubKey))
				if err != nil {
					log.Fatalf("failed to verify message: %s", err)
				}
				log.Printf("verified message: %s", verified)

			case cmd := <-me.CmdChan:
				fmt.Printf("Publisher: %s command received", cmd.Cmd)
				switch cmd.Cmd {
				case "stop":
					StopEngine(cmd.Resp)
				case "start":
					StartEngine(cmd.Resp)
				default:
					log.Printf("Publisher: Error: unknown command: %s", cmd.Cmd)
				}
			}
		}
	}()

	//	return msgCh, nil

	return me, nil
}

func (me *MqttEngine) StartEngine() (chan MqttPubSubCmd, chan MqttPublish, error) {
	resp := make(chan MqttPubSubResponse, 1)
	me.CmdChan <- MqttPubSubCmd{Cmd: "start", Resp: resp}
	r := <-resp
	if r.Error {
		log.Printf("Error: error: %s", r.ErrorMsg)
		return me.CmdChan, me.PublishChan, fmt.Errorf(r.ErrorMsg)
	}
	return me.CmdChan, me.PublishChan, nil
}

func (me *MqttEngine) StopEngine() (chan MqttPubSubCmd, error) {
	resp := make(chan MqttPubSubResponse, 1)
	me.CmdChan <- MqttPubSubCmd{Cmd: "stop", Resp: resp}
	r := <-resp
	if r.Error {
		log.Printf("Error: error: %s", r.ErrorMsg)
		return me.CmdChan, fmt.Errorf(r.ErrorMsg)
	}
	return me.CmdChan, nil
}

func NewMqttSubscriber(clientid string) (*MqttEngine, error) {
	me, err := newMqttEngine()
	if err != nil {
		return me, err
	}

	if clientid == "" {
		return nil, fmt.Errorf("MQTT client id not specified")
	}
	me.ClientID = clientid

	me.QoS = viper.GetInt("mqtt.sub.qos")
	if me.QoS == 0 {
		fmt.Printf("MQTT subscribe quality-of-service not specified in config, using 0")
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
	me.PubKey, err = x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("PubKey is of type %t", me.PubKey)

	// Setup connection to the MQTT bus
	conn, err := tls.Dial("tcp", me.Server, &tls.Config{
		RootCAs:      me.CaCertPool,
		Certificates: []tls.Certificate{me.ClientCert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		log.Fatal(err)
	}

	logger := log.New(os.Stdout, fmt.Sprintf("SUB (%s): ", me.ClientID), log.LstdFlags)

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

type MqttPubSubCmd struct {
	Cmd  string
	Resp chan MqttPubSubResponse
}

type MqttPubSubResponse struct {
	Status   string
	Error    bool
	ErrorMsg string
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
