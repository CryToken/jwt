package jwt

import (
	"errors"
	"strings"
)

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
