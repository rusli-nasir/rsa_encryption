package rsa_crypto

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"reflect"
	"testing"
)

var publicKeyPath = "../../../public.pem"
var privateKeyPath = "../../../private.pem"

func TestNewRsaCrypto(t *testing.T) {

	publicKey, err := os.ReadFile(publicKeyPath)
	if err != nil {
		log.Fatal(err)
	}

	privateKey, err := os.ReadFile(privateKeyPath)
	if err != nil {
		log.Fatal(err)
	}

	xRsa, err := NewRsaCrypto(privateKey, publicKey)
	if err != nil {
		log.Fatal(err)
	}

	type args struct {
		privateKey []byte
		publicKey  []byte
	}
	tests := []struct {
		name    string
		args    args
		want    *rsaCrypto
		wantErr bool
	}{
		{
			name: "Test Read key pem",
			args: args{
				privateKey: privateKey,
				publicKey:  publicKey,
			},
			want:    xRsa,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewRsaCrypto(tt.args.privateKey, tt.args.publicKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewRsaCrypto() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewRsaCrypto() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_rsaCrypto_ParsePrivateKey(t *testing.T) {
	type fields struct {
		PrivateKey *rsa.PrivateKey
		PublicKey  *rsa.PublicKey
	}
	type args struct {
		pemData []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *rsa.PrivateKey
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &rsaCrypto{
				PrivateKey: tt.fields.PrivateKey,
				PublicKey:  tt.fields.PublicKey,
			}
			got, err := r.ParsePrivateKey(tt.args.pemData)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePrivateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParsePrivateKey() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_rsaCrypto_ParsePublicKey(t *testing.T) {
	type fields struct {
		PrivateKey *rsa.PrivateKey
		PublicKey  *rsa.PublicKey
	}
	type args struct {
		pemData []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *rsa.PublicKey
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &rsaCrypto{
				PrivateKey: tt.fields.PrivateKey,
				PublicKey:  tt.fields.PublicKey,
			}
			got, err := r.ParsePublicKey(tt.args.pemData)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePublicKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParsePublicKey() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_rsaCrypto_RsaEncrypt_RsaDecrypt(t *testing.T) {

	publicKey, err := os.ReadFile(publicKeyPath)
	if err != nil {
		log.Fatal(err)
	}

	privateKey, err := os.ReadFile(privateKeyPath)
	if err != nil {
		log.Fatal(err)
	}

	xRsa, err := NewRsaCrypto(privateKey, publicKey)
	if err != nil {
		log.Fatal(err)
	}

	plaintext := "Hello world!"

	type fields struct {
		PrivateKey *rsa.PrivateKey
		PublicKey  *rsa.PublicKey
	}

	type args struct {
		origData        []byte
		customPublicKey []*rsa.PublicKey
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "Test RSA Encrypt",
			fields: fields{
				PrivateKey: xRsa.PrivateKey,
				PublicKey:  xRsa.PublicKey,
			},
			args: args{
				origData: []byte(plaintext),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &rsaCrypto{
				PrivateKey: tt.fields.PrivateKey,
				PublicKey:  tt.fields.PublicKey,
			}
			got, err := r.RsaEncrypt(tt.args.origData, tt.args.customPublicKey...)
			encoding := base64.StdEncoding.EncodeToString(got)

			if (err != nil) != tt.wantErr {
				t.Errorf("RsaEncrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Decode the encrypted data from base64
			encryptedData, err := base64.StdEncoding.DecodeString(encoding)
			if err != nil {
				t.Fatalf("Failed to decode encrypted data: %v", err)
			}

			decryptedData, err := r.RsaDecrypt(encryptedData)
			if err != nil {
				t.Fatalf("Failed to decrypt data: %v", err)
			}

			fmt.Printf("String:   = %v \n", plaintext)
			fmt.Printf("Byte Data:   = %v \n", tt.args.origData)
			fmt.Printf("Encript:   = %v \n", encoding)
			fmt.Printf("Decript:   = %v \n", string(decryptedData))

			if !reflect.DeepEqual(decryptedData, tt.args.origData) {
				t.Errorf("RsaEncrypt() got = %v, want %v", encoding, string(decryptedData))
			}
		})
	}
}
