package signing

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cloudflare/circl/sign/bls"
)

// BLS uses KeyG1SigG2 scheme: public keys in G1, signatures in G2
// This is more efficient for signature aggregation use cases

// BLSSigner implements Signer for BLS12-381
type BLSSigner struct {
	privateKey *bls.PrivateKey[bls.KeyG1SigG2]
}

// NewBLSSigner creates a new BLS signer from a BLS private key
func NewBLSSigner(key interface{}) (*BLSSigner, error) {
	privateKey, ok := key.(*bls.PrivateKey[bls.KeyG1SigG2])
	if !ok {
		return nil, fmt.Errorf("expected *bls.PrivateKey[bls.KeyG1SigG2], got %T", key)
	}

	return &BLSSigner{
		privateKey: privateKey,
	}, nil
}

// Sign creates a JWS-like compact serialization for the given payload
// Format: <header>.<payload>.<signature> where all are base64url encoded
func (s *BLSSigner) Sign(payload []byte) (string, error) {
	// Create header
	header := map[string]interface{}{
		"alg": "BLS",
		"typ": "JWT",
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}

	// Sign the payload
	signature := bls.Sign(s.privateKey, payload)

	// Build compact serialization
	headerB64 := base64URLEncode(headerJSON)
	payloadB64 := base64URLEncode(payload)
	signatureB64 := base64URLEncode(signature)

	return headerB64 + "." + payloadB64 + "." + signatureB64, nil
}

// Algorithm returns the signature algorithm
func (s *BLSSigner) Algorithm() SignatureAlgorithm {
	return AlgBLS
}

// PublicKeyJWK returns the public key as a JWK map
func (s *BLSSigner) PublicKeyJWK() map[string]interface{} {
	publicKey := s.privateKey.PublicKey()
	pubBytes, _ := publicKey.MarshalBinary()

	return map[string]interface{}{
		"kty": "OKP",
		"crv": "BLS12-381-G1",
		"x":   base64URLEncode(pubBytes),
	}
}

// BLSVerifier implements Verifier for BLS12-381
type BLSVerifier struct {
	publicKey *bls.PublicKey[bls.KeyG1SigG2]
}

// NewBLSVerifier creates a new BLS verifier from a BLS public key
func NewBLSVerifier(key interface{}) (*BLSVerifier, error) {
	publicKey, ok := key.(*bls.PublicKey[bls.KeyG1SigG2])
	if !ok {
		return nil, fmt.Errorf("expected *bls.PublicKey[bls.KeyG1SigG2], got %T", key)
	}

	return &BLSVerifier{
		publicKey: publicKey,
	}, nil
}

// NewBLSVerifierFromJWK creates a BLS verifier from a JWK map
func NewBLSVerifierFromJWK(jwk map[string]interface{}) (*BLSVerifier, error) {
	kty, _ := jwk["kty"].(string)
	crv, _ := jwk["crv"].(string)

	if kty != "OKP" || crv != "BLS12-381-G1" {
		return nil, fmt.Errorf("invalid key type for BLS: kty=%s, crv=%s", kty, crv)
	}

	xStr, _ := jwk["x"].(string)
	xBytes, err := base64URLDecode(xStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode x: %w", err)
	}

	publicKey := new(bls.PublicKey[bls.KeyG1SigG2])
	if err := publicKey.UnmarshalBinary(xBytes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal BLS public key: %w", err)
	}

	return &BLSVerifier{
		publicKey: publicKey,
	}, nil
}

// Verify verifies a JWS-like compact serialization
func (v *BLSVerifier) Verify(compact string, expectedPayload []byte) error {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid BLS JWS format: expected 3 parts, got %d", len(parts))
	}

	// Decode header and verify algorithm
	headerJSON, err := base64URLDecode(parts[0])
	if err != nil {
		return fmt.Errorf("failed to decode header: %w", err)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return fmt.Errorf("failed to parse header: %w", err)
	}

	alg, _ := header["alg"].(string)
	if alg != "BLS" {
		return fmt.Errorf("invalid algorithm in header: %s", alg)
	}

	// Decode payload
	payload, err := base64URLDecode(parts[1])
	if err != nil {
		return fmt.Errorf("failed to decode payload: %w", err)
	}

	// Decode signature
	signature, err := base64URLDecode(parts[2])
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	// Verify signature
	if !bls.Verify(v.publicKey, payload, signature) {
		return fmt.Errorf("BLS signature verification failed")
	}

	// Optionally verify payload matches expected
	if expectedPayload != nil && string(payload) != string(expectedPayload) {
		return fmt.Errorf("payload mismatch")
	}

	return nil
}

// Algorithm returns the signature algorithm
func (v *BLSVerifier) Algorithm() SignatureAlgorithm {
	return AlgBLS
}

// GenerateBLSKey generates a new BLS key pair
func GenerateBLSKey() (*bls.PrivateKey[bls.KeyG1SigG2], error) {
	// Generate random seed
	ikm := make([]byte, 32)
	if _, err := rand.Read(ikm); err != nil {
		return nil, fmt.Errorf("failed to generate random seed: %w", err)
	}

	// Key generation parameters (can be empty)
	salt := []byte{}
	keyInfo := []byte{}

	privateKey, err := bls.KeyGen[bls.KeyG1SigG2](ikm, salt, keyInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to generate BLS key: %w", err)
	}

	return privateKey, nil
}
