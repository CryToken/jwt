package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/crytoken/go-jwt"
)

func main() {

	// Create ,valisate and sign new token
	tokrn, err := jwt.New("es256")
	if err != nil {
		fmt.Println(err)
	}

	tokrn.Payload.Exp = uint64(time.Now().Add(10 * time.Minute).Unix())
	tokrn.Payload.Sub = "jw1Afy6w"
	tokrn.Payload.Iss = "auth.trusty.com"

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	err = tokrn.Sign(key)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Printf("token %+v\n", tokrn.String())

	t3, err := jwt.ParseString(tokrn.BearerString())
	if err != nil {
		fmt.Println(err)
	}
	err = t3.VerifySignature(&key.PublicKey)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Verified")

	//New token ,signed by RSA
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	token2, _ := jwt.New("rs256")
	token2.Payload.Exp = uint64(time.Now().Add(12 * time.Minute).Unix())
	token2.Payload.Sub = "crytoken"

	err = token2.Sign(rsaKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	//Display token
	fmt.Println(token2.BearerString())

	//
	parsedToken, err := jwt.ParseString(token2.BearerString())
	if err != nil {
		fmt.Println(err)
		return
	}
	err = parsedToken.VerifySignature(&rsaKey.PublicKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Signatire valid")
}
