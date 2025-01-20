package main

import (
	"fmt"

	"github.com/crytoken/go-jwt"
)

func main() {
	path := "/home/fedor/golang/go-jwt/keys/public.pem"
	pubkey, err := jwt.LoadPubKeyFromPEM(path)
	if err != nil {
		fmt.Println(err)
	}

	token1 := "Bearer eyJhbGciOiJFUzI1NiIsInR5cGUiOiJKV1QifQ.eyJzdWIiOiJQaWZVZVduSGciLCJyb2xlIjoidXNlciIsImV4cCI6MTczNzA4MjI5MH0.8kYoQQLZKxO8_vMzbZDoTn8pOMhamHaXikmBd6nwyTVuh9JsbIfCvDCx1bjohdkhFGkiqyKY2mC4znEZg1Uv3w"
	token2 := "Bearer eyJhbGciOiJFUzI1NiIsInR5cGUiOiJKV1QifQ.eyJzdWIiOiJQaWZVZVduSGciLCJyb2xlIjoidXNlciIsImV4cCI6MTczNzI1MzI0MH0.X2SOS1TNm_mZSBNKwSBr8u2MiIFJByglYn7B4WDRlhCnyhScMk6HnBDKfZiOKhekIfKcAEh8j2bTTvEPwqmQEA"

	_, err = jwt.ParseToken(token1, pubkey)
	if err != nil {
		fmt.Println(err)
	}

	tok, err := jwt.ParseToken(token2, pubkey)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("tojen %+v\n", tok)
}
