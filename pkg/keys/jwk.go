package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/yourusername/did-char/pkg/crypto"
)

// JWK represents a JSON Web Key
type JWK struct {
	ID  string `json:"id,omitempty"`
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	D   string `json:"d,omitempty"` // Private key (omit for public)
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
