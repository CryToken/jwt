package jwt

import (
	"encoding/json"
	"errors"
	"strings"
)

// Token represents a JWT with its Header, Payload, and Signature.
type Token struct {
	Header    Header
	Payload   Payload
	Signature string
}

// Header represents the JWT header.
type Header struct {
	Algorithm string `json:"alg,omitempty"` // Algorithm used to sign the token
	Type      string `json:"typ,omitempty"` // Type of token, typically "JWT"
}

// Payload represents the JWT payload (claims).
// Fields use zero values to handle optionality gracefully.
type Payload struct {
	Exp uint64 `json:"exp,omitempty"` // Expiration time (Unix timestamp)
	Iss string `json:"iss,omitempty"` // Issuer of the token
	Sub string `json:"sub,omitempty"` // Subject of the token
	Aud string `json:"aud,omitempty"` // Audience for the token
	Iat uint64 `json:"iat,omitempty"` // Issued at (Unix timestamp)
	Nbf uint64 `json:"nbf,omitempty"` // Not before (Unix timestamp)
}

func New(algo string) (*Token, error) {
	algo = strings.ToUpper(algo)
	if !isAvailableAlgorithm(algo) {
		msg := "not available algorithm"
		return nil, errors.New(msg)
	}
	var token Token
	const tokenType = "JWT"
	token.Header.Algorithm = algo
	token.Header.Type = tokenType

	return &token, nil
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
