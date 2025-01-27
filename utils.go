package jwt

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

func base64UrlEncode(input []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(input), "=")
}

func Base64UrlDecode(input string) ([]byte, error) {
	if len(input)%4 != 0 {
		input = input + strings.Repeat("=", 4-len(input)%4)
	}
	return base64.URLEncoding.DecodeString(input)
}

func LoadECDSAPubKeY(path string) (*ecdsa.PublicKey, error) {
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

func LoadRSApublicKey(path string) (*rsa.PublicKey, error) {
	publicKeyBytes, err := os.ReadFile(path)
	if err != nil {
		msg := "failed to read rsa oublic key file"
		return nil, errors.New(msg)
	}

	block, _ := pem.Decode(publicKeyBytes)
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

	// Type assertion
	rsaPublicKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		msg := "inbalid key type"
		return nil, errors.New(msg)
	}
	return rsaPublicKey, nil
}

func isAvailableAlgorithm(algo string) bool {
	algo = strings.ToUpper(algo)
	algorithms := map[string]bool{
		"HS256": true,
		"RS256": true,
		"ES256": true,
	}
	return algorithms[algo]
}

func isEcdsaPrivKey(key interface{}) bool {
	_, ok := key.(*ecdsa.PrivateKey)
	return ok
}
