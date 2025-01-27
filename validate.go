package jwt

import (
	"errors"
	"fmt"
	"time"
)

func (token *Token) Validate(key interface{}) error {
	if token.Payload.IsExpired() {
		msg := "not valid expiration value"
		return errors.New(msg)
	}
	if token.Signature == "" {
		msg := "no signature"
		return errors.New(msg)
	}

	err := token.VerifySignature(key)
	if err != nil {
		return err
	}

	return nil
}

// IsExpired checks if the token is expired based on the `exp` claim.
func (p *Payload) IsExpired() bool {
	if p.Exp == 0 {
		return true
	}
	now := time.Now().Unix()
	return now > int64(p.Exp)
}

// IsValid checks if the token satisfies basic validity conditions.
func (p *Payload) IsValid() error {
	if p.Nbf != 0 {
		notBeforeTime := time.Unix(int64(p.Nbf), 0)
		if time.Now().Before(notBeforeTime) {
			return fmt.Errorf("token not valid before %v", notBeforeTime)
		}
	}
	return nil
}
