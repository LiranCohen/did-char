package signing

import (
	"fmt"
)

// SignatureAlgorithm represents a supported JWS signature algorithm
type SignatureAlgorithm string

const (
	// AlgES256 is ECDSA using P-256 curve and SHA-256
	AlgES256 SignatureAlgorithm = "ES256"
	// AlgEdDSA is EdDSA using Ed25519 curve
	AlgEdDSA SignatureAlgorithm = "EdDSA"
	// AlgBLS is BLS12-381 signature scheme
	AlgBLS SignatureAlgorithm = "BLS"
)

// Signer creates JWS signatures
type Signer interface {
	// Sign creates a JWS compact serialization for the given payload
	Sign(payload []byte) (string, error)
	// Algorithm returns the signature algorithm used
	Algorithm() SignatureAlgorithm
	// PublicKeyJWK returns the public key as a JWK map
	PublicKeyJWK() map[string]interface{}
}

// Verifier verifies JWS signatures
type Verifier interface {
	// Verify verifies a JWS compact serialization against the expected payload
	Verify(jws string, expectedPayload []byte) error
	// Algorithm returns the signature algorithm expected
	Algorithm() SignatureAlgorithm
}

// NewSigner creates a new signer for the given algorithm and private key
func NewSigner(alg SignatureAlgorithm, privateKey interface{}) (Signer, error) {
	switch alg {
	case AlgES256:
		return NewES256Signer(privateKey)
	case AlgEdDSA:
		return NewEdDSASigner(privateKey)
	case AlgBLS:
		return NewBLSSigner(privateKey)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", alg)
	}
}

// NewVerifier creates a new verifier for the given algorithm and public key
func NewVerifier(alg SignatureAlgorithm, publicKey interface{}) (Verifier, error) {
	switch alg {
	case AlgES256:
		return NewES256Verifier(publicKey)
	case AlgEdDSA:
		return NewEdDSAVerifier(publicKey)
	case AlgBLS:
		return NewBLSVerifier(publicKey)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", alg)
	}
}

// NewVerifierFromJWK creates a verifier from a JWK map, auto-detecting the algorithm
func NewVerifierFromJWK(jwk map[string]interface{}) (Verifier, error) {
	kty, _ := jwk["kty"].(string)
	crv, _ := jwk["crv"].(string)

	switch {
	case kty == "EC" && crv == "P-256":
		return NewES256VerifierFromJWK(jwk)
	case kty == "OKP" && crv == "Ed25519":
		return NewEdDSAVerifierFromJWK(jwk)
	case kty == "OKP" && crv == "BLS12-381-G1":
		return NewBLSVerifierFromJWK(jwk)
	default:
		return nil, fmt.Errorf("unsupported key type: kty=%s, crv=%s", kty, crv)
	}
}

// DetectAlgorithm detects the signature algorithm from a JWK
func DetectAlgorithm(jwk map[string]interface{}) (SignatureAlgorithm, error) {
	kty, _ := jwk["kty"].(string)
	crv, _ := jwk["crv"].(string)

	switch {
	case kty == "EC" && crv == "P-256":
		return AlgES256, nil
	case kty == "OKP" && crv == "Ed25519":
		return AlgEdDSA, nil
	case kty == "OKP" && crv == "BLS12-381-G1":
		return AlgBLS, nil
	default:
		return "", fmt.Errorf("unsupported key type: kty=%s, crv=%s", kty, crv)
	}
}
