package did

import (
	"crypto/ecdsa"
	"encoding/json"

	"github.com/yourusername/did-char/pkg/crypto"
	"github.com/yourusername/did-char/pkg/keys"
)

// GenerateCommitment generates a commitment and reveal value from a key
// Returns (commitment, revealValue, error)
func GenerateCommitment(key *ecdsa.PrivateKey) (string, string, error) {
	// Convert key to JWK (without private part for reveal)
	jwk := keys.PublicKeyToJWK(&key.PublicKey, "")

	// Canonicalize JWK to JSON
	jwkBytes, err := json.Marshal(jwk)
	if err != nil {
		return "", "", err
	}

	// Step 1: Hash once to get reveal value
	revealValue := crypto.HashToBase64URL(jwkBytes)

	// Step 2: Hash again to get commitment
	revealBytes, _ := crypto.Base64URLDecode(revealValue)
	commitment := crypto.HashToBase64URL(revealBytes)

	return commitment, revealValue, nil
}

// VerifyReveal verifies that a reveal value matches an expected commitment
func VerifyReveal(revealValue, expectedCommitment string) bool {
	revealBytes, err := crypto.Base64URLDecode(revealValue)
	if err != nil {
		return false
	}

	actualCommitment := crypto.HashToBase64URL(revealBytes)
	return actualCommitment == expectedCommitment
}
