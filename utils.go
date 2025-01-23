package jwt

import (
	"crypto/ecdsa"
	"encoding/base64"
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
