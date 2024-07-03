package rsa_crypto

import "crypto/rsa"

type IRsaCrypto interface {
	RsaEncrypt(origData []byte, customPublicKey ...*rsa.PublicKey) ([]byte, error)
	RsaDecrypt(ciphertext []byte, customPrivateKey ...*rsa.PrivateKey) ([]byte, error)
	ParsePublicKey(pemData []byte) (*rsa.PublicKey, error)
	ParsePrivateKey(pemData []byte) (*rsa.PrivateKey, error)
}
