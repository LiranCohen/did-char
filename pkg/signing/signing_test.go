package signing

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestES256SignAndVerify(t *testing.T) {
	// Generate key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create signer
	signer, err := NewES256Signer(privateKey)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	// Sign
	payload := []byte(`{"test":"data","deltaHash":"abc123"}`)
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// Create verifier
	verifier, err := NewES256Verifier(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	// Verify
	err = verifier.Verify(jws, payload)
	if err != nil {
		t.Fatalf("failed to verify: %v", err)
	}

	// Verify with wrong payload should fail
	err = verifier.Verify(jws, []byte(`{"wrong":"payload"}`))
	if err == nil {
		t.Fatal("expected verification to fail with wrong payload")
	}
}

func TestES256VerifierFromJWK(t *testing.T) {
	// Generate key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create signer
	signer, err := NewES256Signer(privateKey)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	// Sign
	payload := []byte(`{"test":"data"}`)
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// Create verifier from JWK map
	jwkMap := signer.PublicKeyJWK()
	verifier, err := NewES256VerifierFromJWK(jwkMap)
	if err != nil {
		t.Fatalf("failed to create verifier from JWK: %v", err)
	}

	// Verify
	err = verifier.Verify(jws, payload)
	if err != nil {
		t.Fatalf("failed to verify: %v", err)
	}
}

func TestEdDSASignAndVerify(t *testing.T) {
	// Generate key
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create signer
	signer, err := NewEdDSASigner(privateKey)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	// Sign
	payload := []byte(`{"test":"data","deltaHash":"def456"}`)
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// Create verifier
	publicKey := privateKey.Public().(ed25519.PublicKey)
	verifier, err := NewEdDSAVerifier(publicKey)
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	// Verify
	err = verifier.Verify(jws, payload)
	if err != nil {
		t.Fatalf("failed to verify: %v", err)
	}

	// Verify with wrong payload should fail
	err = verifier.Verify(jws, []byte(`{"wrong":"payload"}`))
	if err == nil {
		t.Fatal("expected verification to fail with wrong payload")
	}
}

func TestEdDSAVerifierFromJWK(t *testing.T) {
	// Generate key
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create signer
	signer, err := NewEdDSASigner(privateKey)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	// Sign
	payload := []byte(`{"test":"data"}`)
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// Create verifier from JWK map
	jwkMap := signer.PublicKeyJWK()
	verifier, err := NewEdDSAVerifierFromJWK(jwkMap)
	if err != nil {
		t.Fatalf("failed to create verifier from JWK: %v", err)
	}

	// Verify
	err = verifier.Verify(jws, payload)
	if err != nil {
		t.Fatalf("failed to verify: %v", err)
	}
}

func TestBLSSignAndVerify(t *testing.T) {
	// Generate key
	privateKey, err := GenerateBLSKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create signer
	signer, err := NewBLSSigner(privateKey)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	// Sign
	payload := []byte(`{"test":"data","deltaHash":"ghi789"}`)
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// Create verifier
	publicKey := privateKey.PublicKey()
	verifier, err := NewBLSVerifier(publicKey)
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	// Verify
	err = verifier.Verify(jws, payload)
	if err != nil {
		t.Fatalf("failed to verify: %v", err)
	}

	// Verify with wrong payload should fail
	err = verifier.Verify(jws, []byte(`{"wrong":"payload"}`))
	if err == nil {
		t.Fatal("expected verification to fail with wrong payload")
	}
}

func TestBLSVerifierFromJWK(t *testing.T) {
	// Generate key
	privateKey, err := GenerateBLSKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create signer
	signer, err := NewBLSSigner(privateKey)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	// Sign
	payload := []byte(`{"test":"data"}`)
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// Create verifier from JWK map
	jwkMap := signer.PublicKeyJWK()
	verifier, err := NewBLSVerifierFromJWK(jwkMap)
	if err != nil {
		t.Fatalf("failed to create verifier from JWK: %v", err)
	}

	// Verify
	err = verifier.Verify(jws, payload)
	if err != nil {
		t.Fatalf("failed to verify: %v", err)
	}
}

func TestNewVerifierFromJWK(t *testing.T) {
	tests := []struct {
		name    string
		setup   func() (Signer, error)
		wantAlg SignatureAlgorithm
	}{
		{
			name: "ES256",
			setup: func() (Signer, error) {
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				return NewES256Signer(key)
			},
			wantAlg: AlgES256,
		},
		{
			name: "EdDSA",
			setup: func() (Signer, error) {
				_, key, _ := ed25519.GenerateKey(rand.Reader)
				return NewEdDSASigner(key)
			},
			wantAlg: AlgEdDSA,
		},
		{
			name: "BLS",
			setup: func() (Signer, error) {
				key, _ := GenerateBLSKey()
				return NewBLSSigner(key)
			},
			wantAlg: AlgBLS,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := tt.setup()
			if err != nil {
				t.Fatalf("failed to create signer: %v", err)
			}

			// Sign
			payload := []byte(`{"test":"auto-detect"}`)
			jws, err := signer.Sign(payload)
			if err != nil {
				t.Fatalf("failed to sign: %v", err)
			}

			// Create verifier using auto-detection
			jwkMap := signer.PublicKeyJWK()
			verifier, err := NewVerifierFromJWK(jwkMap)
			if err != nil {
				t.Fatalf("failed to create verifier: %v", err)
			}

			if verifier.Algorithm() != tt.wantAlg {
				t.Errorf("wrong algorithm: got %s, want %s", verifier.Algorithm(), tt.wantAlg)
			}

			// Verify
			err = verifier.Verify(jws, payload)
			if err != nil {
				t.Fatalf("failed to verify: %v", err)
			}
		})
	}
}

func TestDetectAlgorithm(t *testing.T) {
	tests := []struct {
		name    string
		jwk     map[string]interface{}
		wantAlg SignatureAlgorithm
		wantErr bool
	}{
		{
			name:    "ES256",
			jwk:     map[string]interface{}{"kty": "EC", "crv": "P-256", "x": "test", "y": "test"},
			wantAlg: AlgES256,
		},
		{
			name:    "EdDSA",
			jwk:     map[string]interface{}{"kty": "OKP", "crv": "Ed25519", "x": "test"},
			wantAlg: AlgEdDSA,
		},
		{
			name:    "BLS",
			jwk:     map[string]interface{}{"kty": "OKP", "crv": "BLS12-381-G1", "x": "test"},
			wantAlg: AlgBLS,
		},
		{
			name:    "unsupported",
			jwk:     map[string]interface{}{"kty": "RSA"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alg, err := DetectAlgorithm(tt.jwk)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if alg != tt.wantAlg {
				t.Errorf("wrong algorithm: got %s, want %s", alg, tt.wantAlg)
			}
		})
	}
}
