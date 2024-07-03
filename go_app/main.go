package main

import (
	"encoding/base64"
	"go_app/tools/rsa_crypto"
	"log"
	"os"
)

func main() {
	fPath := "../"
	rsa_crypto.GenRsaKey(2048, fPath)

	var publicKeyPath = fPath + "public.pem"
	var privateKeyPath = fPath + "private.pem"

	publicKey, err := os.ReadFile(publicKeyPath)
	if err != nil {
		log.Fatal(err)
	}

	privateKey, err := os.ReadFile(privateKeyPath)
	if err != nil {
		log.Fatal(err)
	}

	cryp, err := rsa_crypto.NewRsaCrypto(privateKey, publicKey)

	if err != nil {
		log.Fatal(err)
	}

	plainData := "Simple string"

	encrypt, err := cryp.RsaEncrypt([]byte(plainData))
	if err != nil {
		log.Fatal(err)
	}

	stringEncode := base64.StdEncoding.EncodeToString(encrypt)

	fo, err := os.Create(fPath + "encripted_string.txt")
	if err != nil {
		panic(err)
	}
	// close fo on exit and check for its returned error
	defer func() {
		if err := fo.Close(); err != nil {
			panic(err)
		}
	}()

	_, err2 := fo.WriteString(stringEncode)
	if err2 != nil {
		log.Fatal(err2)
	}

}
