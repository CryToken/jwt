package jwt

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

func ParseString(token string) (*Token, error) {
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

	resultToken.Signature = tokenParts[2]
	return &resultToken, nil

}
