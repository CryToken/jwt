package jwt

import (
	"fmt"
	"time"
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
