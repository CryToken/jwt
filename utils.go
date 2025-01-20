package jwt

import (
	"encoding/base64"
	"strings"
)

func Base64UrlDecode(input string) ([]byte, error) {
	if len(input)%4 != 0 {
		input = input + strings.Repeat("=", 4-len(input)%4)
	}
	return base64.URLEncoding.DecodeString(input)
}
