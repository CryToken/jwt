package jwt

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
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

func (token *Token) String() string {
	var result string
	headerBytes, _ := json.Marshal(token.Header)
	payloadBytes, _ := json.Marshal(token.Payload)

	//Encode to Base64Url
	base64Header := base64UrlEncode(headerBytes)
	base64Payload := base64UrlEncode(payloadBytes)

	// Assmeble final string
	if token.Signature == "" {
		result = base64Header + "." + base64Payload
	} else {
		result = base64Header + "." + base64Payload + "." + token.Signature
	}
	return result
}

func (token *Token) BearerString() string {
	baseStr := token.String()
	result := "Bearer" + " " + baseStr
	return result
}
