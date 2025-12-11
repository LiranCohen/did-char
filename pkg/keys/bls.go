package keys

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/sign/bls"
	"github.com/yourusername/did-char/pkg/crypto"
)

// BLS uses KeyG1SigG2 scheme: public keys in G1, signatures in G2
// This is efficient for signature aggregation

// GenerateBLSKey generates a new BLS key pair
func GenerateBLSKey() (*bls.PrivateKey[bls.KeyG1SigG2], error) {
	// Generate random seed
	ikm := make([]byte, 32)
	if _, err := rand.Read(ikm); err != nil {
		return nil, fmt.Errorf("failed to generate random seed: %w", err)
	}

	// Key generation parameters (can be empty for basic usage)
	salt := []byte{}
	keyInfo := []byte{}

	privateKey, err := bls.KeyGen[bls.KeyG1SigG2](ikm, salt, keyInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to generate BLS key: %w", err)
	}

	return privateKey, nil
}

// BLSPrivateKeyToJWK converts a BLS private key to JWK
func BLSPrivateKeyToJWK(key *bls.PrivateKey[bls.KeyG1SigG2], keyID string) *JWK {
	pubKey := key.PublicKey()
	pubBytes, _ := pubKey.MarshalBinary()
	privBytes, _ := key.MarshalBinary()

	return &JWK{
		ID:  keyID,
		Kty: "OKP",
		Crv: "BLS12-381-G1",
		Alg: "BLS",
		X:   crypto.Base64URLEncode(pubBytes),
		D:   crypto.Base64URLEncode(privBytes),
	}
}

// BLSPublicKeyToJWK converts a BLS public key to JWK
func BLSPublicKeyToJWK(key *bls.PublicKey[bls.KeyG1SigG2], keyID string) *JWK {
	pubBytes, _ := key.MarshalBinary()

	return &JWK{
		ID:  keyID,
		Kty: "OKP",
		Crv: "BLS12-381-G1",
		Alg: "BLS",
		X:   crypto.Base64URLEncode(pubBytes),
	}
}

// JWKToBLSPrivateKey converts a JWK to a BLS private key
func JWKToBLSPrivateKey(jwk *JWK) (*bls.PrivateKey[bls.KeyG1SigG2], error) {
	if jwk.Kty != "OKP" || jwk.Crv != "BLS12-381-G1" {
		return nil, fmt.Errorf("JWK is not a BLS key: kty=%s, crv=%s", jwk.Kty, jwk.Crv)
	}
	if jwk.D == "" {
		return nil, fmt.Errorf("JWK does not contain private key (d)")
	}

	privBytes, err := crypto.Base64URLDecode(jwk.D)
	if err != nil {
		return nil, fmt.Errorf("failed to decode D: %w", err)
	}

	privateKey := new(bls.PrivateKey[bls.KeyG1SigG2])
	if err := privateKey.UnmarshalBinary(privBytes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal BLS private key: %w", err)
	}

	return privateKey, nil
}

// JWKToBLSPublicKey converts a JWK to a BLS public key
func JWKToBLSPublicKey(jwk *JWK) (*bls.PublicKey[bls.KeyG1SigG2], error) {
	if jwk.Kty != "OKP" || jwk.Crv != "BLS12-381-G1" {
		return nil, fmt.Errorf("JWK is not a BLS key: kty=%s, crv=%s", jwk.Kty, jwk.Crv)
	}

	xBytes, err := crypto.Base64URLDecode(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode X: %w", err)
	}

	publicKey := new(bls.PublicKey[bls.KeyG1SigG2])
	if err := publicKey.UnmarshalBinary(xBytes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal BLS public key: %w", err)
	}

	return publicKey, nil
}
