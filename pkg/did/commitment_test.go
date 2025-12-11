package did

import (
	"testing"

	"github.com/yourusername/did-char/pkg/keys"
)

func TestGenerateCommitment(t *testing.T) {
	// Generate an ECDSA key
	privateKey, err := keys.GenerateSecp256k1Key()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	commitment, revealValue, err := GenerateCommitment(privateKey)
	if err != nil {
		t.Fatalf("GenerateCommitment failed: %v", err)
	}

	// Both should be non-empty base64url strings
	if commitment == "" {
		t.Error("commitment is empty")
	}
	if revealValue == "" {
		t.Error("revealValue is empty")
	}

	// Both should be 43 chars (SHA256 = 32 bytes = 43 base64url chars)
	if len(commitment) != 43 {
		t.Errorf("commitment length = %d, want 43", len(commitment))
	}
	if len(revealValue) != 43 {
		t.Errorf("revealValue length = %d, want 43", len(revealValue))
	}

	// Commitment != revealValue (they're different hashes)
	if commitment == revealValue {
		t.Error("commitment should not equal revealValue")
	}

	// Should be deterministic for same key
	commitment2, reveal2, _ := GenerateCommitment(privateKey)
	if commitment != commitment2 {
		t.Error("GenerateCommitment is not deterministic (commitment)")
	}
	if revealValue != reveal2 {
		t.Error("GenerateCommitment is not deterministic (revealValue)")
	}
}

func TestGenerateCommitmentDifferentKeys(t *testing.T) {
	key1, _ := keys.GenerateSecp256k1Key()
	key2, _ := keys.GenerateSecp256k1Key()

	commitment1, reveal1, _ := GenerateCommitment(key1)
	commitment2, reveal2, _ := GenerateCommitment(key2)

	if commitment1 == commitment2 {
		t.Error("different keys should produce different commitments")
	}
	if reveal1 == reveal2 {
		t.Error("different keys should produce different reveal values")
	}
}

func TestVerifyReveal(t *testing.T) {
	privateKey, _ := keys.GenerateSecp256k1Key()
	commitment, revealValue, _ := GenerateCommitment(privateKey)

	// Valid reveal
	if !VerifyReveal(revealValue, commitment) {
		t.Error("VerifyReveal should return true for valid reveal")
	}

	// Wrong reveal
	if VerifyReveal("wrong-reveal-value", commitment) {
		t.Error("VerifyReveal should return false for wrong reveal")
	}

	// Wrong commitment
	if VerifyReveal(revealValue, "wrong-commitment") {
		t.Error("VerifyReveal should return false for wrong commitment")
	}

	// Invalid base64url
	if VerifyReveal("not!valid!base64", commitment) {
		t.Error("VerifyReveal should return false for invalid base64")
	}
}

func TestVerifyKeyMatchesReveal(t *testing.T) {
	// Test with EC key - use GenerateCommitmentFromJWK for consistency
	ecKey, _ := keys.GenerateSecp256k1Key()
	ecJWK := keys.PrivateKeyToJWK(ecKey, "test")
	_, ecReveal, _ := GenerateCommitmentFromJWK(ecJWK)

	// Valid match
	err := VerifyKeyMatchesReveal(ecJWK, ecReveal)
	if err != nil {
		t.Errorf("VerifyKeyMatchesReveal should succeed: %v", err)
	}

	// Wrong reveal
	err = VerifyKeyMatchesReveal(ecJWK, "wrong-reveal")
	if err == nil {
		t.Error("VerifyKeyMatchesReveal should fail for wrong reveal")
	}

	// Different key
	ecKey2, _ := keys.GenerateSecp256k1Key()
	ecJWK2 := keys.PrivateKeyToJWK(ecKey2, "test")
	err = VerifyKeyMatchesReveal(ecJWK2, ecReveal)
	if err == nil {
		t.Error("VerifyKeyMatchesReveal should fail for different key")
	}
}

func TestVerifyKeyMatchesRevealEd25519(t *testing.T) {
	// Test with Ed25519 key
	edKey, _ := keys.GenerateEd25519Key()
	edJWK := keys.Ed25519PrivateKeyToJWK(edKey, "test")
	edCommitment, edReveal, _ := GenerateCommitmentFromJWK(edJWK)

	// Valid match
	err := VerifyKeyMatchesReveal(edJWK, edReveal)
	if err != nil {
		t.Errorf("VerifyKeyMatchesReveal should succeed for Ed25519: %v", err)
	}

	// Verify the commitment chain works
	if !VerifyReveal(edReveal, edCommitment) {
		t.Error("commitment chain should verify for Ed25519")
	}
}

func TestVerifyKeyMatchesRevealBLS(t *testing.T) {
	// Test with BLS key
	blsKey, _ := keys.GenerateBLSKey()
	blsJWK := keys.BLSPrivateKeyToJWK(blsKey, "test")
	blsCommitment, blsReveal, _ := GenerateCommitmentFromJWK(blsJWK)

	// Valid match
	err := VerifyKeyMatchesReveal(blsJWK, blsReveal)
	if err != nil {
		t.Errorf("VerifyKeyMatchesReveal should succeed for BLS: %v", err)
	}

	// Verify the commitment chain works
	if !VerifyReveal(blsReveal, blsCommitment) {
		t.Error("commitment chain should verify for BLS")
	}
}

func TestGenerateCommitmentFromJWK(t *testing.T) {
	tests := []struct {
		name       string
		generateFn func() (*keys.JWK, error)
	}{
		{
			name: "EC P-256",
			generateFn: func() (*keys.JWK, error) {
				key, err := keys.GenerateSecp256k1Key()
				if err != nil {
					return nil, err
				}
				return keys.PrivateKeyToJWK(key, "test"), nil
			},
		},
		{
			name: "Ed25519",
			generateFn: func() (*keys.JWK, error) {
				key, err := keys.GenerateEd25519Key()
				if err != nil {
					return nil, err
				}
				return keys.Ed25519PrivateKeyToJWK(key, "test"), nil
			},
		},
		{
			name: "BLS",
			generateFn: func() (*keys.JWK, error) {
				key, err := keys.GenerateBLSKey()
				if err != nil {
					return nil, err
				}
				return keys.BLSPrivateKeyToJWK(key, "test"), nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jwk, err := tt.generateFn()
			if err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}

			commitment, revealValue, err := GenerateCommitmentFromJWK(jwk)
			if err != nil {
				t.Fatalf("GenerateCommitmentFromJWK failed: %v", err)
			}

			// Both should be valid base64url hashes
			if len(commitment) != 43 {
				t.Errorf("commitment length = %d, want 43", len(commitment))
			}
			if len(revealValue) != 43 {
				t.Errorf("revealValue length = %d, want 43", len(revealValue))
			}

			// Reveal should verify against commitment
			if !VerifyReveal(revealValue, commitment) {
				t.Error("reveal should verify against commitment")
			}

			// Key should match reveal
			if err := VerifyKeyMatchesReveal(jwk, revealValue); err != nil {
				t.Errorf("key should match reveal: %v", err)
			}
		})
	}
}

func TestCommitmentChainIntegrity(t *testing.T) {
	// This test verifies the complete commitment chain:
	// key -> hash(key) = reveal -> hash(reveal) = commitment

	key, _ := keys.GenerateSecp256k1Key()
	jwk := keys.PrivateKeyToJWK(key, "test")

	commitment, revealValue, _ := GenerateCommitmentFromJWK(jwk)

	// Step 1: Verify key hashes to reveal
	if err := VerifyKeyMatchesReveal(jwk, revealValue); err != nil {
		t.Errorf("key -> reveal failed: %v", err)
	}

	// Step 2: Verify reveal hashes to commitment
	if !VerifyReveal(revealValue, commitment) {
		t.Error("reveal -> commitment failed")
	}

	// Step 3: Verify the chain is one-way (can't derive key from reveal)
	// This is implicit - we can only verify, not reverse
}

func TestPublicOnlyJWKCommitment(t *testing.T) {
	// Commitment should work the same for public-only JWK
	key, _ := keys.GenerateSecp256k1Key()
	privateJWK := keys.PrivateKeyToJWK(key, "test")
	publicJWK := keys.PublicKeyToJWK(&key.PublicKey, "test")

	// Both should produce the same commitment
	_, privateReveal, _ := GenerateCommitmentFromJWK(privateJWK)
	_, publicReveal, _ := GenerateCommitmentFromJWK(publicJWK)

	if privateReveal != publicReveal {
		t.Error("private and public JWK should produce same reveal")
	}
}
