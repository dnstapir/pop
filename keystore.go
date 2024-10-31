package main

import (
	"crypto/ecdsa"
    "log"
    "os"

    "github.com/dnstapir/tapir"
	"gopkg.in/yaml.v3"
)

func genKeyStore() map[string]string {
    var ks = make(map[string]string)
	keyStoreData, err := os.ReadFile(Gconfig.KeyStore.Path)

	if err != nil {
		log.Fatalf("Error from ReadFile(%s): %v", Gconfig.KeyStore.Path, err)
	}

	err = yaml.Unmarshal(keyStoreData, &ks)
	if err != nil {
		log.Fatalf("Error when unmarshaling keystore contents: %v", err)
	}

    return ks
}

func GetValidationKeyByKeyName(keyname string) *ecdsa.PublicKey {
    ks := genKeyStore()


    key, err := tapir.FetchMqttValidatorKey("KEYSTORE: "+ keyname, ks[keyname])

    if err != nil {
        log.Printf("Error getting key %s from keystore", keyname)
        return nil
    }

    return key
}

// Unused, for now
func GetSigningKeyByKeyName(keyname string) *ecdsa.PrivateKey {
    ks := genKeyStore()

    key, err := tapir.FetchMqttSigningKey("KEYSTORE: "+ keyname, ks[keyname])

    if err != nil {
        log.Printf("Error getting key %s from keystore", keyname)
        return nil
    }

    return key
}
