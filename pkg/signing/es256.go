package signing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"

	"github.com/go-jose/go-jose/v4"
)

// ES256Signer implements Signer for ECDSA P-256
type ES256Signer struct {
	privateKey *ecdsa.PrivateKey
	signer     jose.Signer
}

// NewES256Signer creates a new ES256 signer from an ECDSA private key
func NewES256Signer(key interface{}) (*ES256Signer, error) {
	privateKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("expected *ecdsa.PrivateKey, got %T", key)
	}

	if privateKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("expected P-256 curve, got %s", privateKey.Curve.Params().Name)
	}

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       privateKey,
	}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			jose.HeaderType: "JWT",
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create jose signer: %w", err)
	}

	return &ES256Signer{
		privateKey: privateKey,
		signer:     signer,
	}, nil
}

// Sign creates a JWS compact serialization for the given payload
func (s *ES256Signer) Sign(payload []byte) (string, error) {
	jws, err := s.signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("failed to sign: %w", err)
	}

	compact, err := jws.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize: %w", err)
	}

	return compact, nil
}

// Algorithm returns the signature algorithm
func (s *ES256Signer) Algorithm() SignatureAlgorithm {
	return AlgES256
}

// PublicKeyJWK returns the public key as a JWK map
func (s *ES256Signer) PublicKeyJWK() map[string]interface{} {
	return map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64URLEncode(s.privateKey.PublicKey.X.Bytes()),
		"y":   base64URLEncode(s.privateKey.PublicKey.Y.Bytes()),
	}
}

// ES256Verifier implements Verifier for ECDSA P-256
type ES256Verifier struct {
	publicKey *ecdsa.PublicKey
}

// NewES256Verifier creates a new ES256 verifier from an ECDSA public key
func NewES256Verifier(key interface{}) (*ES256Verifier, error) {
	publicKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected *ecdsa.PublicKey, got %T", key)
	}

	if publicKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("expected P-256 curve, got %s", publicKey.Curve.Params().Name)
	}

	return &ES256Verifier{
		publicKey: publicKey,
	}, nil
}

// NewES256VerifierFromJWK creates an ES256 verifier from a JWK map
func NewES256VerifierFromJWK(jwk map[string]interface{}) (*ES256Verifier, error) {
	kty, _ := jwk["kty"].(string)
	crv, _ := jwk["crv"].(string)

	if kty != "EC" || crv != "P-256" {
		return nil, fmt.Errorf("invalid key type for ES256: kty=%s, crv=%s", kty, crv)
	}

	xStr, _ := jwk["x"].(string)
	yStr, _ := jwk["y"].(string)

	xBytes, err := base64URLDecode(xStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode x: %w", err)
	}

	yBytes, err := base64URLDecode(yStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode y: %w", err)
	}

	publicKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}

	return &ES256Verifier{
		publicKey: publicKey,
	}, nil
}

// Verify verifies a JWS compact serialization
func (v *ES256Verifier) Verify(compact string, expectedPayload []byte) error {
	jws, err := jose.ParseSigned(compact, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return fmt.Errorf("failed to parse JWS: %w", err)
	}

	payload, err := jws.Verify(v.publicKey)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	// Optionally verify payload matches expected
	if expectedPayload != nil && string(payload) != string(expectedPayload) {
		return fmt.Errorf("payload mismatch")
	}

	return nil
}

// Algorithm returns the signature algorithm
func (v *ES256Verifier) Algorithm() SignatureAlgorithm {
	return AlgES256
}

// Helper functions for base64url encoding/decoding
func base64URLEncode(data []byte) string {
	encoded := base64.URLEncoding.EncodeToString(data)
	return strings.TrimRight(encoded, "=")
}

func base64URLDecode(s string) ([]byte, error) {
	// Add padding if needed
	padding := (4 - len(s)%4) % 4
	s += strings.Repeat("=", padding)
	return base64.URLEncoding.DecodeString(s)
}
