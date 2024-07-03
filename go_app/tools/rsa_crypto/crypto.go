package rsa_crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

const PrivateKeyType = "RSA PRIVATE KEY"
const PublicKeyType = "PUBLIC KEY"

type rsaCrypto struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

func NewRsaCrypto(privateKey []byte, publicKey []byte) (*rsaCrypto, error) {

	var xRsa = new(rsaCrypto)

	pKey, err := xRsa.ParsePrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	xRsa.PrivateKey = pKey

	pubKey, err := xRsa.ParsePublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	xRsa.PublicKey = pubKey

	return xRsa, nil
}

func (r *rsaCrypto) RsaEncrypt(origData []byte, customPublicKey ...*rsa.PublicKey) ([]byte, error) {
	pubKey := r.PublicKey

	if len(customPublicKey) > 0 {
		pubKey = customPublicKey[0]
	}

	encryptedData, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, origData)
	if err != nil {
		return nil, err
	}

	return encryptedData, nil
}

func (r *rsaCrypto) RsaDecrypt(ciphertext []byte, customPrivateKey ...*rsa.PrivateKey) ([]byte, error) {
	privKey := r.PrivateKey

	if len(customPrivateKey) > 0 {
		privKey = customPrivateKey[0]
	}

	decryptedData, err := rsa.DecryptPKCS1v15(rand.Reader, privKey, ciphertext)
	if err != nil {
		return nil, err
	}

	return decryptedData, nil
}

func (r *rsaCrypto) ParsePublicKey(pemData []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != PublicKeyType {
		return nil, errors.New("public key error")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	return rsaPub, nil
}

func (r *rsaCrypto) ParsePrivateKey(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != PrivateKeyType {
		return nil, errors.New("private key error")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

func GenRsaKey(bits int, path ...string) error {
	filePath := ""
	if len(path) > 0 {
		filePath = path[0]
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	derStream := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  PrivateKeyType,
		Bytes: derStream,
	}
	pkFile := fmt.Sprintf("%sprivate.pem", filePath)
	file, err := os.Create(pkFile)
	if err != nil {
		return err
	}
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	block = &pem.Block{
		Type:  PublicKeyType,
		Bytes: derPkix,
	}
	pubkFile := fmt.Sprintf("%spublic.pem", filePath)
	file, err = os.Create(pubkFile)
	if err != nil {
		return err
	}
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	return nil
}
