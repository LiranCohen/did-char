package signing

import (
	"crypto/ed25519"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

// EdDSASigner implements Signer for Ed25519
type EdDSASigner struct {
	privateKey ed25519.PrivateKey
	signer     jose.Signer
}

// NewEdDSASigner creates a new EdDSA signer from an Ed25519 private key
func NewEdDSASigner(key interface{}) (*EdDSASigner, error) {
	privateKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("expected ed25519.PrivateKey, got %T", key)
	}

	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key size: %d", len(privateKey))
	}

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.EdDSA,
		Key:       privateKey,
	}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			jose.HeaderType: "JWT",
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create jose signer: %w", err)
	}

	return &EdDSASigner{
		privateKey: privateKey,
		signer:     signer,
	}, nil
}

// Sign creates a JWS compact serialization for the given payload
func (s *EdDSASigner) Sign(payload []byte) (string, error) {
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
func (s *EdDSASigner) Algorithm() SignatureAlgorithm {
	return AlgEdDSA
}

// PublicKeyJWK returns the public key as a JWK map
func (s *EdDSASigner) PublicKeyJWK() map[string]interface{} {
	publicKey := s.privateKey.Public().(ed25519.PublicKey)
	return map[string]interface{}{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   base64URLEncode(publicKey),
	}
}

// EdDSAVerifier implements Verifier for Ed25519
type EdDSAVerifier struct {
	publicKey ed25519.PublicKey
}

// NewEdDSAVerifier creates a new EdDSA verifier from an Ed25519 public key
func NewEdDSAVerifier(key interface{}) (*EdDSAVerifier, error) {
	publicKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected ed25519.PublicKey, got %T", key)
	}

	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key size: %d", len(publicKey))
	}

	return &EdDSAVerifier{
		publicKey: publicKey,
	}, nil
}

// NewEdDSAVerifierFromJWK creates an EdDSA verifier from a JWK map
func NewEdDSAVerifierFromJWK(jwk map[string]interface{}) (*EdDSAVerifier, error) {
	kty, _ := jwk["kty"].(string)
	crv, _ := jwk["crv"].(string)

	if kty != "OKP" || crv != "Ed25519" {
		return nil, fmt.Errorf("invalid key type for EdDSA: kty=%s, crv=%s", kty, crv)
	}

	xStr, _ := jwk["x"].(string)
	xBytes, err := base64URLDecode(xStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode x: %w", err)
	}

	if len(xBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key size: %d", len(xBytes))
	}

	return &EdDSAVerifier{
		publicKey: ed25519.PublicKey(xBytes),
	}, nil
}

// Verify verifies a JWS compact serialization
func (v *EdDSAVerifier) Verify(compact string, expectedPayload []byte) error {
	jws, err := jose.ParseSigned(compact, []jose.SignatureAlgorithm{jose.EdDSA})
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
func (v *EdDSAVerifier) Algorithm() SignatureAlgorithm {
	return AlgEdDSA
}
