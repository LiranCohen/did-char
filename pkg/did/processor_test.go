package did

import (
	"encoding/json"
	"testing"

	"github.com/yourusername/did-char/pkg/keys"
	"github.com/yourusername/did-char/pkg/signing"
)

func TestExtractJWSPayload(t *testing.T) {
	// Create a valid JWS for testing
	ecKey, _ := keys.GenerateSecp256k1Key()
	signer, _ := signing.NewES256Signer(ecKey)

	payload := []byte(`{"test":"data"}`)
	jws, _ := signer.Sign(payload)

	// Extract and verify
	extracted, err := extractJWSPayload(jws)
	if err != nil {
		t.Fatalf("extractJWSPayload failed: %v", err)
	}

	// Compare extracted with original
	if string(extracted) != string(payload) {
		t.Errorf("extracted = %q, want %q", string(extracted), string(payload))
	}
}

func TestExtractJWSPayloadInvalidFormat(t *testing.T) {
	tests := []struct {
		name string
		jws  string
	}{
		{"empty", ""},
		{"no dots", "abc123"},
		{"one dot", "abc.def"},
		{"too many dots", "a.b.c.d"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := extractJWSPayload(tt.jws)
			if err == nil {
				t.Error("expected error for invalid JWS format")
			}
		})
	}
}

func TestSplitJWS(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"a.b.c", []string{"a", "b", "c"}},
		{"header.payload.signature", []string{"header", "payload", "signature"}},
		{"...", []string{"", "", "", ""}},
		{"a", []string{"a"}},
		{"a.", []string{"a", ""}},
		{".b", []string{"", "b"}},
		{"eyJ.eyJ.sig", []string{"eyJ", "eyJ", "sig"}},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			parts := splitJWS(tt.input)
			if len(parts) != len(tt.expected) {
				t.Errorf("splitJWS(%q) = %d parts, want %d", tt.input, len(parts), len(tt.expected))
				return
			}
			for i, part := range parts {
				if part != tt.expected[i] {
					t.Errorf("splitJWS(%q)[%d] = %q, want %q", tt.input, i, part, tt.expected[i])
				}
			}
		})
	}
}

func TestVerifyUpdateSignature(t *testing.T) {
	// Generate key and create signed data
	ecKey, _ := keys.GenerateSecp256k1Key()
	jwk := keys.PrivateKeyToJWK(ecKey, "test")

	signedData := UpdateSignedData{
		UpdateKey: jwk,
		DeltaHash: "test-delta-hash",
	}

	payload, _ := json.Marshal(signedData)
	signer, _ := signing.NewES256Signer(ecKey)
	jws, _ := signer.Sign(payload)

	// Verify
	result, err := verifyUpdateSignature(jws)
	if err != nil {
		t.Fatalf("verifyUpdateSignature failed: %v", err)
	}

	if result.DeltaHash != "test-delta-hash" {
		t.Errorf("DeltaHash = %q, want %q", result.DeltaHash, "test-delta-hash")
	}
	if result.UpdateKey == nil {
		t.Error("UpdateKey should not be nil")
	}
}

func TestVerifyUpdateSignatureInvalidJWS(t *testing.T) {
	_, err := verifyUpdateSignature("invalid.jws.format")
	if err == nil {
		t.Error("expected error for invalid JWS")
	}
}

func TestVerifyRecoverSignature(t *testing.T) {
	// Generate key and create signed data
	ecKey, _ := keys.GenerateSecp256k1Key()
	jwk := keys.PrivateKeyToJWK(ecKey, "test")

	signedData := RecoverSignedData{
		RecoveryKey:        jwk,
		DeltaHash:          "recover-delta-hash",
		RecoveryCommitment: "new-recovery-commitment",
	}

	payload, _ := json.Marshal(signedData)
	signer, _ := signing.NewES256Signer(ecKey)
	jws, _ := signer.Sign(payload)

	// Verify
	result, err := verifyRecoverSignature(jws)
	if err != nil {
		t.Fatalf("verifyRecoverSignature failed: %v", err)
	}

	if result.DeltaHash != "recover-delta-hash" {
		t.Errorf("DeltaHash = %q, want %q", result.DeltaHash, "recover-delta-hash")
	}
	if result.RecoveryCommitment != "new-recovery-commitment" {
		t.Errorf("RecoveryCommitment = %q, want %q", result.RecoveryCommitment, "new-recovery-commitment")
	}
}

func TestVerifyDeactivateSignature(t *testing.T) {
	// Generate key and create signed data
	ecKey, _ := keys.GenerateSecp256k1Key()
	jwk := keys.PrivateKeyToJWK(ecKey, "test")

	signedData := DeactivateSignedData{
		RecoveryKey: jwk,
		DIDSuffix:   "test-suffix",
	}

	payload, _ := json.Marshal(signedData)
	signer, _ := signing.NewES256Signer(ecKey)
	jws, _ := signer.Sign(payload)

	// Verify
	result, err := verifyDeactivateSignature(jws)
	if err != nil {
		t.Fatalf("verifyDeactivateSignature failed: %v", err)
	}

	if result.DIDSuffix != "test-suffix" {
		t.Errorf("DIDSuffix = %q, want %q", result.DIDSuffix, "test-suffix")
	}
}

func TestVerifySignatureWithWrongKey(t *testing.T) {
	// Create signed data with one key, but include a different key in payload
	signingKey, _ := keys.GenerateSecp256k1Key()
	differentKey, _ := keys.GenerateSecp256k1Key()
	differentJWK := keys.PrivateKeyToJWK(differentKey, "test")

	// Include the different key in signed data (not the signing key)
	signedData := UpdateSignedData{
		UpdateKey: differentJWK,
		DeltaHash: "test-hash",
	}

	payload, _ := json.Marshal(signedData)
	signer, _ := signing.NewES256Signer(signingKey)
	jws, _ := signer.Sign(payload)

	// This should fail because the key in payload doesn't match the signing key
	_, err := verifyUpdateSignature(jws)
	if err == nil {
		t.Error("expected error when signature key doesn't match payload key")
	}
}

func TestCreateVerifierFromJWK(t *testing.T) {
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jwk, err := tt.generateFn()
			if err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}

			verifier, err := createVerifierFromJWK(jwk)
			if err != nil {
				t.Fatalf("createVerifierFromJWK failed: %v", err)
			}

			if verifier == nil {
				t.Error("verifier should not be nil")
			}
		})
	}
}

func TestStripWrappers(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "no wrapper - returns unchanged",
			input:    "0101036162630a7b7d",
			expected: "0101036162630a7b7d",
		},
		{
			name:     "too short - returns unchanged",
			input:    "00",
			expected: "00",
		},
		{
			name:     "invalid hex - returns unchanged",
			input:    "not-hex!",
			expected: "not-hex!",
		},
		{
			name:     "CHAR slot wrapper short length",
			input:    "000005" + "0101036162630a7b7d", // 0000 + length(5) + payload
			expected: "0101036162630a7b7d",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stripWrappers(tt.input)
			if result != tt.expected {
				t.Errorf("stripWrappers(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestStripSlotWrapper(t *testing.T) {
	// Test with different CompactSize lengths
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "1-byte length",
			input:    "000003616263", // 0000 + 03 + "abc"
			expected: "616263",
		},
		{
			name:     "too short",
			input:    "0000",
			expected: "0000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stripSlotWrapper(tt.input)
			if result != tt.expected {
				t.Errorf("stripSlotWrapper(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestBase64URLDecode(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		wantErr  bool
	}{
		{"dGVzdA", "test", false},
		{"SGVsbG8gV29ybGQ", "Hello World", false},
		{"", "", false},
		{"!!!invalid!!!", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := base64URLDecode(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(result) != tt.expected {
				t.Errorf("base64URLDecode(%q) = %q, want %q", tt.input, string(result), tt.expected)
			}
		})
	}
}

func TestVerifyUpdateSignatureWithEd25519(t *testing.T) {
	// Generate Ed25519 key and create signed data
	edKey, _ := keys.GenerateEd25519Key()
	jwk := keys.Ed25519PrivateKeyToJWK(edKey, "test")

	signedData := UpdateSignedData{
		UpdateKey: jwk,
		DeltaHash: "ed25519-delta-hash",
	}

	payload, _ := json.Marshal(signedData)
	signer, _ := signing.NewEdDSASigner(edKey)
	jws, _ := signer.Sign(payload)

	// Verify
	result, err := verifyUpdateSignature(jws)
	if err != nil {
		t.Fatalf("verifyUpdateSignature with Ed25519 failed: %v", err)
	}

	if result.DeltaHash != "ed25519-delta-hash" {
		t.Errorf("DeltaHash = %q, want %q", result.DeltaHash, "ed25519-delta-hash")
	}
}
