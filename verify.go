package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"math/big"
	"strings"
)

func (token *Token) VerifySignature(key interface{}) error {
	switch token.Header.Algorithm {
	case "ES256":
		ecdsaKey, ok := key.(*ecdsa.PublicKey)
		if !ok {
			msg := "not valid key"
			return errors.New(msg)
		}
		return token.verifyECDSA(ecdsaKey)

	case "RS256":
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			msg := "not valid key"
			return errors.New(msg)
		}
		return token.verifyRSA(rsaKey)

	default:
		msg := "unknown algorithm"
		return errors.New(msg)
	}
}
func (token *Token) verifyECDSA(pubkey *ecdsa.PublicKey) error {
	tokenStr := token.String()
	parts := strings.Split(tokenStr, ".")
	signatureBytes, err := Base64UrlDecode(parts[2])
	if err != nil {
		return err
	}

	dataToVerify := parts[0] + "." + parts[1]
	dataHash := sha256.Sum256([]byte(dataToVerify))

	r := new(big.Int).SetBytes(signatureBytes[:len(signatureBytes)/2])
	s := new(big.Int).SetBytes(signatureBytes[len(signatureBytes)/2:])

	if !ecdsa.Verify(pubkey, dataHash[:], r, s) {
		msg := "signature not valid"
		return errors.New(msg)
	}
	return nil
}

func (token *Token) verifyRSA(pubkey *rsa.PublicKey) error {
	tokenStr := token.String()
	parts := strings.Split(tokenStr, ".")
	signatureBytes, err := Base64UrlDecode(parts[2])
	if err != nil {
		return err
	}

	dataToVerify := parts[0] + "." + parts[1]
	dataHash := sha256.Sum256([]byte(dataToVerify))

	err = rsa.VerifyPKCS1v15(pubkey, crypto.SHA256, dataHash[:], signatureBytes)
	if err != nil {
		return err
	}
	return nil
}
