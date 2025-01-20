package jwt

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

func ParseToken(token string, pubKey *ecdsa.PublicKey) (*Token, error) {
	var resultToken Token
	authHeader := strings.Split(token, " ")
	if len(authHeader) != 2 && authHeader[0] != "Bearer" {
		msg := fmt.Sprintf("invalid auth header: %s", token)
		return nil, errors.New(msg)
	}

	tokenParts := strings.Split(authHeader[1], ".")
	if len(tokenParts) != 3 {
		msg := "invalid token format"
		return nil, errors.New(msg)
	}

	//Parse header
	headerBytes, err := Base64UrlDecode(tokenParts[0])
	if err != nil {
		msg := "failed decoding header"
		return nil, errors.New(msg)
	}
	err = json.Unmarshal(headerBytes, &resultToken.Header)
	if err != nil {
		msg := "failed to unmarshal token header"
		return nil, errors.New(msg)
	}

	// Parse token payload
	payloadBytes, err := Base64UrlDecode(tokenParts[1])
	if err != nil {
		msg := "failed decoding payload"
		return nil, errors.New(msg)
	}
	err = json.Unmarshal(payloadBytes, &resultToken.Payload)
	if err != nil {
		msg := "failed to unmarshal payload"
		return nil, errors.New(msg)
	}
	isExpired := resultToken.Payload.IsExpired()
	if isExpired {
		msg := "token expired"
		return nil, errors.New(msg)
	}

	//Decode and verify signatire
	signatureBytes, err := Base64UrlDecode(tokenParts[2])
	if err != nil {
		msg := "failed decoding signature"
		return nil, errors.New(msg)
	}

	dataToVerify := tokenParts[0] + "." + tokenParts[1]
	dataToVerifyHash := sha256.Sum256([]byte(dataToVerify))

	r := new(big.Int).SetBytes(signatureBytes[:len(signatureBytes)/2])
	s := new(big.Int).SetBytes(signatureBytes[len(signatureBytes)/2:])

	if !ecdsa.Verify(pubKey, dataToVerifyHash[:], r, s) {
		msg := "signature not valid"
		return nil, errors.New(msg)
	}
	resultToken.Signature = tokenParts[2]
	return &resultToken, nil

}
