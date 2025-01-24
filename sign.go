package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
)

func (token *Token) Sign(key interface{}) error {

	token.Signature = ""
	dataToSign := token.String()

	switch token.Header.Algorithm {
	case "ES256":
		var err error
		if !isEcdsaPrivKey(key) {
			msg := "for es256 , kry should be ecdsa.privatekey"
			return errors.New(msg)
		}
		ecKey, _ := key.(*ecdsa.PrivateKey)
		token.Signature, err = signECDSA(dataToSign, ecKey)
		if err != nil {
			return err
		}
		return nil
	case "RS256":
		var err error
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			msg := "invalid rsa private key"
			return errors.New(msg)
		}
		token.Signature, err = signRSA(dataToSign, rsaKey)
		if err != nil {
			return err
		}
		return nil

	case "HS256":
		var err error
		hmacKey, ok := key.([]byte)
		if !ok {
			msg := "not valid hmac secret key"
			return errors.New(msg)
		}
		token.Signature, err = signHS256(dataToSign, hmacKey)
		if err != nil {
			return err
		}
		return nil
	}

	return nil
}

func signECDSA(data string, key *ecdsa.PrivateKey) (string, error) {
	//We sign data Hash
	hash := sha256.Sum256([]byte(data))

	// Sign by using standart lib ecdsa
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		return "", err
	}
	signature := r.Bytes()
	signature = append(signature, s.Bytes()...)
	return base64UrlEncode(signature), nil
}

func signRSA(data string, key *rsa.PrivateKey) (string, error) {
	//Hash data
	hash := sha256.Sum256([]byte(data))

	//Signing data
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		return "", err
	}
	return base64UrlEncode(signature), nil
}

func signHS256(data string, key []byte) (string, error) {
	hash := hmac.New(sha256.New, key)
	hash.Write([]byte(data))
	return base64UrlEncode(hash.Sum(nil)), nil
}
