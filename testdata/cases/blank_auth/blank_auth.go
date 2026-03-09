// Package blank_auth tests PatternBlank on crypto and JWT-related packages.
//
// ErrSec expected findings (3 sites, all RISK: HIGH):
//   SITE-1  blank identifier  crypto/rand           GenerateToken    line 22
//   SITE-2  blank identifier  golang.org/x/crypto   HashPassword     line 34
//   SITE-3  blank identifier  crypto/rsa            EncryptData      line 44
package blank_auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
)

// SITE-1: crypto/rand.Read error discarded.
// Fail-open: if Read fails, token bytes are uninitialised (zero) — tokens
// become predictable, breaking authentication entropy guarantees.
func GenerateToken() []byte {
	token := make([]byte, 32)
	_, _ = rand.Read(token)
	return token
}

// SITE-2: pem.Decode does not return error, but x509.ParsePKCS1PrivateKey does.
// Error discarded — if parse fails, key is nil and Sign calls will panic.
func LoadPrivateKey(pemBytes []byte) *rsa.PrivateKey {
	block, _ := pem.Decode(pemBytes) // pem.Decode returns (block, rest) — no error
	if block == nil {
		return nil
	}
	// SITE-2: x509.ParsePKCS1PrivateKey error discarded
	key, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	return key
}

// SITE-3: rsa.EncryptOAEP error discarded.
// Fail-open: if encryption fails, ciphertext is nil — caller may store nil
// as "encrypted" data, fully bypassing confidentiality.
func EncryptData(pub *rsa.PublicKey, data []byte) []byte {
	ciphertext, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, data, nil)
	return ciphertext
}

// CORRECT: error checked and returned.
func SafeGenerateToken() ([]byte, error) {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return nil, err
	}
	return token, nil
}
