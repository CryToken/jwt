package jwt

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

func LoadPubKeyFromPEM(path string) (*ecdsa.PublicKey, error) {
	//Read the public key file
	pubKeyBytes, err := os.ReadFile(path)
	if err != nil {
		msg := fmt.Sprintf("err to Read file %s", path)
		return nil, errors.New(msg)
	}

	//Decode it to the PEM Blocks
	block, _ := pem.Decode(pubKeyBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		msg := "error decoding public key"
		return nil, errors.New(msg)
	}

	//Parsing public key
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		msg := "failed parsing public key"
		return nil, errors.New(msg)
	}

	// Use type assertion to justify this is a ecdsa.PublicKey
	var ok bool
	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		msg := "tye error: not a ECDSA Public key type"
		return nil, errors.New(msg)
	}

	return ecdsaPubKey, nil
}
