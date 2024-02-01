/*
 * Copyright (c) DNS TAPIR
 */

package tapir

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

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

func NewMqttEngine(clientid string, pub, sub bool) (*MqttEngine, error) {
        if !pub && !sub {
	   return nil, fmt.Errorf("Either (or both) pub or sub support must be requested for MQTT Engine")
	}
	
	if clientid == "" {
		return nil, fmt.Errorf("MQTT client id not specified")
	}

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
		return nil, fmt.Errorf("MQTT client cert file not specified in config")
	}

	clientKeyFile := viper.GetString("mqtt.clientkey")
	if clientKeyFile == "" {
		return nil, fmt.Errorf("MQTT client key file not specified in config")
	}

	cacertFile := viper.GetString("mqtt.cacert")
	if cacertFile == "" {
		return nil, fmt.Errorf("MQTT CA cert file not specified in config")
	}

	// Setup CA cert for validating the MQTT connection
	caCert, err := os.ReadFile(cacertFile)
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	ok := caCertPool.AppendCertsFromPEM([]byte(caCert))
	if !ok {
		return nil, fmt.Errorf("failed to parse CA certificate in file %s", cacertFile)
	}

	// Setup client cert/key for mTLS authentication
	clientCert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
	if err != nil {
		return nil, err
	}

	me := MqttEngine{
		Topic:      topic,
		Server:     server,
		ClientID:   clientid,
		ClientCert: clientCert,
		CaCertPool: caCertPool,
	}

	signingKeyFile := viper.GetString("mqtt.signingkey")
	if !pub {
		log.Printf("MQTT pub support not requested, only sub possible")
	} else if signingKeyFile == "" {
		log.Printf("MQTT signing key file not specified in config, publish not possible")
	} else {
		signingKey, err := os.ReadFile(signingKeyFile)
		if err != nil {
			return nil, err
		}

		// Setup key used for creating the JWS
		pemBlock, _ := pem.Decode(signingKey)
		if pemBlock == nil || pemBlock.Type != "EC PRIVATE KEY" {
			return nil, fmt.Errorf("failed to decode PEM block containing private key")
		}
		me.PrivKey, err = x509.ParseECPrivateKey(pemBlock.Bytes)
		if err != nil {
			return nil, err
		}
		me.CanPublish = true
	}

	me.QoS = viper.GetInt("mqtt.qos")
	if me.QoS == 0 {
		fmt.Printf("MQTT subscribe quality-of-service not specified in config, using 0")
	}

	signingPubFile := viper.GetString("mqtt.validatorkey")
	if !sub {
		log.Printf("MQTT sub support not requested, only pub possible")
	} else if signingPubFile == "" {
		log.Printf("MQTT validator pub file not specified in config, subscribe not possible")
	} else {
		signingPub, err := os.ReadFile(signingPubFile)
		if err != nil {
			return nil, err
		}

		// Setup key used for creating the JWS
		pemBlock, _ := pem.Decode(signingPub)
		if pemBlock == nil || pemBlock.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("failed to decode PEM block containing public key")
		}
		me.PubKey, err = x509.ParsePKIXPublicKey(pemBlock.Bytes)
		if err != nil {
			return nil, err
		}
		// log.Printf("PubKey is of type %t", me.PubKey)
		me.CanSubscribe = true
	}

	// Setup connection to the MQTT bus
	conn, err := tls.Dial("tcp", me.Server, &tls.Config{
		RootCAs:      me.CaCertPool,
		Certificates: []tls.Certificate{me.ClientCert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		return nil, err
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

	if GlobalCF.Debug {
	   c.SetDebugLogger(logger)
	}
	c.SetErrorLogger(logger)

	me.Client = c

	me.CmdChan = make(chan MqttEngineCmd, 1)
	me.PublishChan = make(chan MqttPkg, 10)   // Here clients send us messages to pub
	me.SubscribeChan = make(chan MqttPkg, 10) // Here we send clients messages that arrived via sub

	StartEngine := func(resp chan MqttEngineResponse) {
		cp := &paho.Connect{
			KeepAlive:  30,
			ClientID:   me.ClientID,
			CleanStart: true,
		}

		ca, err := me.Client.Connect(context.Background(), cp)
		if err != nil {
			resp <- MqttEngineResponse{
				Error:    true,
				ErrorMsg: fmt.Sprintf("Error from mp.Client.Connect: %v", err),
			}
			return
		}
		if ca.ReasonCode != 0 {
			resp <- MqttEngineResponse{
				Error: true,
				ErrorMsg: fmt.Sprintf("Failed to connect to %s: %d - %s", me.Server,
					ca.ReasonCode, ca.Properties.ReasonString),
			}
			return
		}
		fmt.Printf("Connected to %s\n", me.Server)

		if me.CanSubscribe {
			sa, err := me.Client.Subscribe(context.Background(), &paho.Subscribe{
				Subscriptions: []paho.SubscribeOptions{
					{Topic: me.Topic, QoS: byte(me.QoS)},
				},
			})
			if err != nil {
				resp <- MqttEngineResponse{
						Error:    true,
						ErrorMsg: fmt.Sprintf("Error from mp.Client.Subscribe: %v", err),
				     	}
				return
			}
			fmt.Println(string(sa.Reasons))
			if sa.Reasons[0] != byte(me.QoS) {
				resp <- MqttEngineResponse{
						Error:    true,
						ErrorMsg: fmt.Sprintf("Failed to subscribe to topic: %s reasons: %d",
							  		      me.Topic, sa.Reasons[0]),
				     	}
				return
			}
			log.Printf("Subscribed to %s", me.Topic)
		}
		resp <- MqttEngineResponse{
			Error:  false,
			Status: "all ok",
		}
	}

	StopEngine := func(resp chan MqttEngineResponse) {
		if me.Client != nil {
			d := &paho.Disconnect{ReasonCode: 0}
			err := me.Client.Disconnect(d)
			if err != nil {
				resp <- MqttEngineResponse{
						Error:	true,
						ErrorMsg:	err.Error(),
				     	}
			} else {
				resp <- MqttEngineResponse{
						Status:	"connection to MQTT broker closed",
				     	}
			}
		}
	}

	go func() {
		buf := new(bytes.Buffer)
		jenc := json.NewEncoder(buf)

		for {
			select {
			case outbox := <-me.PublishChan:
				if !me.CanPublish {
					log.Printf("Error: pub request but this engine is unable to publish messages")
					continue
				}

				switch outbox.Type {
				case "text":
					buf.Reset()
					_, err = buf.WriteString(outbox.Msg)
					if err != nil {
						log.Printf("Error from buf.Writestring(): %v", err)
					}
					if GlobalCF.Debug {
					   log.Printf("MQTT Engine: received text msg: %s", outbox.Msg)
					}

				case "data":
				        if GlobalCF.Debug {
					   log.Printf("MQTT Engine: received raw data: %v", outbox.Data)
					}
					buf.Reset()
					outbox.TimeStamp = time.Now()
					err = jenc.Encode(outbox.Data)
					if err != nil {
						log.Printf("Error from json.NewEncoder: %v", err)
						continue
					}
				}

				sMsg, err := jws.Sign(buf.Bytes(), jws.WithJSON(), jws.WithKey(jwa.ES256, me.PrivKey))
				if err != nil {
					log.Printf("failed to create JWS message: %s", err)
				}

				if _, err = me.Client.Publish(context.Background(), &paho.Publish{
					Topic:   me.Topic,
					Payload: sMsg,
				}); err != nil {
					log.Println("error sending message:", err)
					continue
				}
				if GlobalCF.Debug {
					log.Printf("sent signed JWS: %s", string(sMsg))
				}

			case inbox := <-me.MsgChan:
				if GlobalCF.Debug {
					log.Println("MQTT Engine: received message:", string(inbox.Payload))
				}
				pkg := MqttPkg{TimeStamp: time.Now(), Data: TapirMsg{}}
				payload, err := jws.Verify(inbox.Payload, jws.WithKey(jwa.ES256, me.PubKey))
				if err != nil {
					pkg.Error = true
					pkg.ErrorMsg = fmt.Sprintf("failed to verify message: %v", err)
				} else {
					// log.Printf("verified message: %s", payload)
					r := bytes.NewReader(payload)
					err = json.NewDecoder(r).Decode(&pkg.Data)
					if err != nil {
						pkg.Error = true
						pkg.ErrorMsg = fmt.Sprintf("failed to decide json: %v", err)
					}
				}

				me.SubscribeChan <- pkg

			case cmd := <-me.CmdChan:
				fmt.Printf("MQTT Engine: %s command received\n", cmd.Cmd)
				switch cmd.Cmd {
				case "stop":
					StopEngine(cmd.Resp)
				case "start":
					StartEngine(cmd.Resp)
				default:
					log.Printf("MQTT Engine: Error: unknown command: %s", cmd.Cmd)
				}
				fmt.Printf("MQTT Engine: cmd %s handled.\n", cmd.Cmd)
			}
		}
	}()

	return &me, nil
}

func (me *MqttEngine) StartEngine() (chan MqttEngineCmd, chan MqttPkg, chan MqttPkg, error) {
	resp := make(chan MqttEngineResponse, 1)
	me.CmdChan <- MqttEngineCmd{Cmd: "start", Resp: resp}
	r := <-resp
	if r.Error {
		log.Printf("Error: error: %s", r.ErrorMsg)
		return me.CmdChan, me.PublishChan, me.SubscribeChan, fmt.Errorf(r.ErrorMsg)
	}
	return me.CmdChan, me.PublishChan, me.SubscribeChan, nil
}

func (me *MqttEngine) StopEngine() (chan MqttEngineCmd, error) {
	resp := make(chan MqttEngineResponse, 1)
	me.CmdChan <- MqttEngineCmd{Cmd: "stop", Resp: resp}
	r := <-resp
	if r.Error {
		log.Printf("Error: error: %s", r.ErrorMsg)
		return me.CmdChan, fmt.Errorf(r.ErrorMsg)
	}
	return me.CmdChan, nil
}

// Trivial interrupt handler to catch SIGTERM and stop the MQTT engine nicely
func (me *MqttEngine) SetupInterruptHandler() {
//        respch := make(chan MqttEngineResponse, 2)

        ic := make(chan os.Signal, 1)
        signal.Notify(ic, os.Interrupt, syscall.SIGTERM)
        go func() {
                for {
                        select {
                        case <-ic:
                                fmt.Println("SIGTERM interrupt received, sending stop signal to MQTT Engine")
				me.StopEngine()
//                                os.Exit(1)
                        }
                }
        }()
}
