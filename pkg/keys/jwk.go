package keys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/yourusername/did-char/pkg/crypto"
)

// JWK represents a JSON Web Key supporting EC (P-256), OKP (Ed25519, BLS12-381)
type JWK struct {
	ID  string `json:"id,omitempty"`
	Kty string `json:"kty"`           // "EC" for ECDSA, "OKP" for Ed25519/BLS
	Crv string `json:"crv"`           // "P-256", "Ed25519", or "BLS12-381-G1"
	Alg string `json:"alg,omitempty"` // "ES256", "EdDSA", or "BLS"
	X   string `json:"x"`
	Y   string `json:"y,omitempty"`   // Not used for Ed25519/BLS
	D   string `json:"d,omitempty"`   // Private key (omit for public)
}

// GenerateSecp256k1Key generates a new secp256k1 key pair
func GenerateSecp256k1Key() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// PrivateKeyToJWK converts an ECDSA private key to JWK
func PrivateKeyToJWK(key *ecdsa.PrivateKey, keyID string) *JWK {
	return &JWK{
		ID:  keyID,
		Kty: "EC",
		Crv: "P-256",
		X:   crypto.Base64URLEncode(key.PublicKey.X.Bytes()),
		Y:   crypto.Base64URLEncode(key.PublicKey.Y.Bytes()),
		D:   crypto.Base64URLEncode(key.D.Bytes()),
	}
}

// PublicKeyToJWK converts an ECDSA public key to JWK
func PublicKeyToJWK(key *ecdsa.PublicKey, keyID string) *JWK {
	return &JWK{
		ID:  keyID,
		Kty: "EC",
		Crv: "P-256",
		X:   crypto.Base64URLEncode(key.X.Bytes()),
		Y:   crypto.Base64URLEncode(key.Y.Bytes()),
	}
}

// JWKToPrivateKey converts a JWK to an ECDSA private key
func JWKToPrivateKey(jwk *JWK) (*ecdsa.PrivateKey, error) {
	if jwk.D == "" {
		return nil, fmt.Errorf("JWK does not contain private key (d)")
	}

	xBytes, err := crypto.Base64URLDecode(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode X: %w", err)
	}

	yBytes, err := crypto.Base64URLDecode(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Y: %w", err)
	}

	dBytes, err := crypto.Base64URLDecode(jwk.D)
	if err != nil {
		return nil, fmt.Errorf("failed to decode D: %w", err)
	}

	curve := elliptic.P256()
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	d := new(big.Int).SetBytes(dBytes)

	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: d,
	}, nil
}

// JWKToPublicKey converts a JWK to an ECDSA public key
func JWKToPublicKey(jwk *JWK) (*ecdsa.PublicKey, error) {
	xBytes, err := crypto.Base64URLDecode(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode X: %w", err)
	}

	yBytes, err := crypto.Base64URLDecode(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Y: %w", err)
	}

	curve := elliptic.P256()
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// MarshalJWK marshals a JWK to JSON
func MarshalJWK(jwk *JWK) ([]byte, error) {
	return json.MarshalIndent(jwk, "", "  ")
}

// UnmarshalJWK unmarshals a JWK from JSON
func UnmarshalJWK(data []byte) (*JWK, error) {
	var jwk JWK
	if err := json.Unmarshal(data, &jwk); err != nil {
		return nil, err
	}
	return &jwk, nil
}

// Ed25519 Key Functions

// GenerateEd25519Key generates a new Ed25519 key pair
func GenerateEd25519Key() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, err
}

// Ed25519PrivateKeyToJWK converts an Ed25519 private key to JWK
func Ed25519PrivateKeyToJWK(key ed25519.PrivateKey, keyID string) *JWK {
	return &JWK{
		ID:  keyID,
		Kty: "OKP",
		Crv: "Ed25519",
		Alg: "EdDSA",
		X:   crypto.Base64URLEncode(key.Public().(ed25519.PublicKey)),
		D:   crypto.Base64URLEncode(key.Seed()),
	}
}

// Ed25519PublicKeyToJWK converts an Ed25519 public key to JWK
func Ed25519PublicKeyToJWK(key ed25519.PublicKey, keyID string) *JWK {
	return &JWK{
		ID:  keyID,
		Kty: "OKP",
		Crv: "Ed25519",
		Alg: "EdDSA",
		X:   crypto.Base64URLEncode(key),
	}
}

// JWKToEd25519PrivateKey converts a JWK to an Ed25519 private key
func JWKToEd25519PrivateKey(jwk *JWK) (ed25519.PrivateKey, error) {
	if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" {
		return nil, fmt.Errorf("JWK is not an Ed25519 key: kty=%s, crv=%s", jwk.Kty, jwk.Crv)
	}
	if jwk.D == "" {
		return nil, fmt.Errorf("JWK does not contain private key (d)")
	}

	seed, err := crypto.Base64URLDecode(jwk.D)
	if err != nil {
		return nil, fmt.Errorf("failed to decode D: %w", err)
	}

	return ed25519.NewKeyFromSeed(seed), nil
}

// JWKToEd25519PublicKey converts a JWK to an Ed25519 public key
func JWKToEd25519PublicKey(jwk *JWK) (ed25519.PublicKey, error) {
	if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" {
		return nil, fmt.Errorf("JWK is not an Ed25519 key: kty=%s, crv=%s", jwk.Kty, jwk.Crv)
	}

	xBytes, err := crypto.Base64URLDecode(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode X: %w", err)
	}

	if len(xBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key size: %d", len(xBytes))
	}

	return ed25519.PublicKey(xBytes), nil
}

// JWKToMap converts a JWK struct to a map for signing operations
func JWKToMap(jwk *JWK) map[string]interface{} {
	m := map[string]interface{}{
		"kty": jwk.Kty,
		"crv": jwk.Crv,
		"x":   jwk.X,
	}
	if jwk.ID != "" {
		m["id"] = jwk.ID
	}
	if jwk.Alg != "" {
		m["alg"] = jwk.Alg
	}
	if jwk.Y != "" {
		m["y"] = jwk.Y
	}
	if jwk.D != "" {
		m["d"] = jwk.D
	}
	return m
}

// MapToJWK converts a map to a JWK struct
func MapToJWK(m map[string]interface{}) *JWK {
	jwk := &JWK{}
	if v, ok := m["id"].(string); ok {
		jwk.ID = v
	}
	if v, ok := m["kty"].(string); ok {
		jwk.Kty = v
	}
	if v, ok := m["crv"].(string); ok {
		jwk.Crv = v
	}
	if v, ok := m["alg"].(string); ok {
		jwk.Alg = v
	}
	if v, ok := m["x"].(string); ok {
		jwk.X = v
	}
	if v, ok := m["y"].(string); ok {
		jwk.Y = v
	}
	if v, ok := m["d"].(string); ok {
		jwk.D = v
	}
	return jwk
}
