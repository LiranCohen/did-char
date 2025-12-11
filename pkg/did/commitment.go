package did

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"

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

// VerifyKeyMatchesReveal verifies that a JWK hashes to the expected reveal value
// This ensures the key in the signed data matches the commitment chain
func VerifyKeyMatchesReveal(jwk *keys.JWK, revealValue string) error {
	// Create public-only JWK for hashing (same as what was committed)
	pubJWK := &keys.JWK{
		ID:  jwk.ID,
		Kty: jwk.Kty,
		Crv: jwk.Crv,
		Alg: jwk.Alg,
		X:   jwk.X,
		Y:   jwk.Y,
		// D is intentionally omitted
	}

	// Serialize to JSON
	jwkBytes, err := json.Marshal(pubJWK)
	if err != nil {
		return fmt.Errorf("failed to marshal JWK: %w", err)
	}

	// Hash and compare to reveal value
	computedReveal := crypto.HashToBase64URL(jwkBytes)
	if computedReveal != revealValue {
		return fmt.Errorf("key hash mismatch: computed %s, expected %s", computedReveal, revealValue)
	}

	return nil
}

// GenerateCommitmentFromJWK generates a commitment from a JWK
// Returns (commitment, revealValue, error)
func GenerateCommitmentFromJWK(jwk *keys.JWK) (string, string, error) {
	// Create public-only JWK
	pubJWK := &keys.JWK{
		ID:  jwk.ID,
		Kty: jwk.Kty,
		Crv: jwk.Crv,
		Alg: jwk.Alg,
		X:   jwk.X,
		Y:   jwk.Y,
	}

	// Serialize to JSON
	jwkBytes, err := json.Marshal(pubJWK)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal JWK: %w", err)
	}

	// Step 1: Hash once to get reveal value
	revealValue := crypto.HashToBase64URL(jwkBytes)

	// Step 2: Hash again to get commitment
	revealBytes, _ := crypto.Base64URLDecode(revealValue)
	commitment := crypto.HashToBase64URL(revealBytes)

	return commitment, revealValue, nil
}
