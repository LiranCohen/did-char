package encoding

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/yourusername/did-char/pkg/crypto"
	"github.com/yourusername/did-char/pkg/keys"
)

// JWKToCompactKey converts a JWK to compact key format
func JWKToCompactKey(jwk *keys.JWK, id string, purposes byte) (*CompactPublicKey, error) {
	keyType, err := JWKToKeyType(jwk)
	if err != nil {
		return nil, err
	}

	keyBytes, err := JWKToCompressedBytes(jwk)
	if err != nil {
		return nil, err
	}

	return &CompactPublicKey{
		ID:       id,
		KeyType:  keyType,
		KeyBytes: keyBytes,
		Purposes: purposes,
	}, nil
}

// JWKToKeyType returns the key type byte for a JWK
func JWKToKeyType(jwk *keys.JWK) (byte, error) {
	switch {
	case jwk.Kty == "OKP" && jwk.Crv == "Ed25519":
		return KeyTypeEd25519, nil
	case jwk.Kty == "EC" && jwk.Crv == "secp256k1":
		return KeyTypeSecp256k1, nil
	case jwk.Kty == "EC" && jwk.Crv == "P-256":
		return KeyTypeP256, nil
	case jwk.Kty == "OKP" && jwk.Crv == "BLS12-381-G1":
		return KeyTypeBLS12381G1, nil
	default:
		return 0, fmt.Errorf("unsupported key type: kty=%s, crv=%s", jwk.Kty, jwk.Crv)
	}
}

// JWKToCompressedBytes converts a JWK public key to compressed bytes
func JWKToCompressedBytes(jwk *keys.JWK) ([]byte, error) {
	switch {
	case jwk.Kty == "OKP" && jwk.Crv == "Ed25519":
		// Ed25519 is already 32 bytes
		return crypto.Base64URLDecode(jwk.X)

	case jwk.Kty == "EC" && (jwk.Crv == "P-256" || jwk.Crv == "secp256k1"):
		// EC keys need compression
		xBytes, err := crypto.Base64URLDecode(jwk.X)
		if err != nil {
			return nil, fmt.Errorf("failed to decode X: %w", err)
		}
		yBytes, err := crypto.Base64URLDecode(jwk.Y)
		if err != nil {
			return nil, fmt.Errorf("failed to decode Y: %w", err)
		}

		x := new(big.Int).SetBytes(xBytes)
		y := new(big.Int).SetBytes(yBytes)
		return CompressECPublicKey(x, y), nil

	case jwk.Kty == "OKP" && jwk.Crv == "BLS12-381-G1":
		// BLS keys - assuming already compressed in JWK
		return crypto.Base64URLDecode(jwk.X)

	default:
		return nil, fmt.Errorf("unsupported key type: kty=%s, crv=%s", jwk.Kty, jwk.Crv)
	}
}

// CompactKeyToJWK converts a compact key back to JWK format
func CompactKeyToJWK(ck *CompactPublicKey) (*keys.JWK, error) {
	jwk := &keys.JWK{
		ID: ck.ID,
	}

	switch ck.KeyType {
	case KeyTypeEd25519:
		jwk.Kty = "OKP"
		jwk.Crv = "Ed25519"
		jwk.Alg = "EdDSA"
		jwk.X = crypto.Base64URLEncode(ck.KeyBytes)

	case KeyTypeSecp256k1:
		jwk.Kty = "EC"
		jwk.Crv = "secp256k1"
		jwk.Alg = "ES256K"
		// Decompress to get X, Y
		// Note: secp256k1 curve not in stdlib, would need external lib
		// For now, store compressed and handle in verification
		jwk.X = crypto.Base64URLEncode(ck.KeyBytes)

	case KeyTypeP256:
		jwk.Kty = "EC"
		jwk.Crv = "P-256"
		jwk.Alg = "ES256"
		// Decompress
		pubKey, err := DecompressECPublicKey(elliptic.P256(), ck.KeyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to decompress P-256 key: %w", err)
		}
		jwk.X = crypto.Base64URLEncode(pubKey.X.Bytes())
		jwk.Y = crypto.Base64URLEncode(pubKey.Y.Bytes())

	case KeyTypeBLS12381G1:
		jwk.Kty = "OKP"
		jwk.Crv = "BLS12-381-G1"
		jwk.Alg = "BLS"
		jwk.X = crypto.Base64URLEncode(ck.KeyBytes)

	default:
		return nil, fmt.Errorf("unknown key type: %d", ck.KeyType)
	}

	return jwk, nil
}

// KeyTypeToCurve returns the elliptic curve for EC key types
func KeyTypeToCurve(keyType byte) (elliptic.Curve, error) {
	switch keyType {
	case KeyTypeP256:
		return elliptic.P256(), nil
	case KeyTypeSecp256k1:
		// secp256k1 not in stdlib - would need btcec or similar
		return nil, fmt.Errorf("secp256k1 requires external library")
	default:
		return nil, fmt.Errorf("not an EC key type: %d", keyType)
	}
}

// ComputeDeltaHash computes the hash of compact-encoded delta
func ComputeDeltaHash(delta *CompactDelta) ([]byte, error) {
	e := NewEncoder()
	if err := e.WriteDelta(*delta); err != nil {
		return nil, err
	}
	hash := sha256.Sum256(e.Bytes())
	return hash[:], nil
}

// ComputeRevealFromKey computes H(publicKey) for the reveal value
func ComputeRevealFromKey(publicKey []byte) []byte {
	hash := sha256.Sum256(publicKey)
	return hash[:]
}

// ComputeCommitmentFromReveal computes H(reveal) for the commitment
func ComputeCommitmentFromReveal(reveal []byte) []byte {
	hash := sha256.Sum256(reveal)
	return hash[:]
}

// SignatureToRaw extracts raw signature bytes from various formats
func SignatureToRaw(keyType byte, signature []byte) ([]byte, error) {
	// If it's already raw bytes of expected size, return as-is
	sigSize := KeySizes[keyType].Sig
	if len(signature) == sigSize {
		return signature, nil
	}

	// Handle DER-encoded ECDSA signatures
	if keyType == KeyTypeP256 || keyType == KeyTypeSecp256k1 {
		r, s, err := parseDERSignature(signature)
		if err != nil {
			return nil, err
		}
		// Convert to fixed-size raw format (32 bytes each for r, s)
		raw := make([]byte, 64)
		rBytes := r.Bytes()
		sBytes := s.Bytes()
		copy(raw[32-len(rBytes):32], rBytes)
		copy(raw[64-len(sBytes):], sBytes)
		return raw, nil
	}

	return nil, fmt.Errorf("unexpected signature size %d for key type %d", len(signature), keyType)
}

// RawToSignature converts raw signature bytes to the format needed for verification
func RawToSignature(keyType byte, raw []byte) ([]byte, error) {
	sigSize := KeySizes[keyType].Sig
	if len(raw) != sigSize {
		return nil, fmt.Errorf("invalid raw signature size: got %d, want %d", len(raw), sigSize)
	}
	return raw, nil
}

// parseDERSignature parses a DER-encoded ECDSA signature
func parseDERSignature(sig []byte) (*big.Int, *big.Int, error) {
	if len(sig) < 8 {
		return nil, nil, fmt.Errorf("signature too short")
	}
	if sig[0] != 0x30 {
		return nil, nil, fmt.Errorf("invalid signature format")
	}

	// Parse SEQUENCE
	totalLen := int(sig[1])
	if len(sig) < totalLen+2 {
		return nil, nil, fmt.Errorf("signature truncated")
	}

	idx := 2

	// Parse R
	if sig[idx] != 0x02 {
		return nil, nil, fmt.Errorf("expected INTEGER for R")
	}
	idx++
	rLen := int(sig[idx])
	idx++
	r := new(big.Int).SetBytes(sig[idx : idx+rLen])
	idx += rLen

	// Parse S
	if sig[idx] != 0x02 {
		return nil, nil, fmt.Errorf("expected INTEGER for S")
	}
	idx++
	sLen := int(sig[idx])
	idx++
	s := new(big.Int).SetBytes(sig[idx : idx+sLen])

	return r, s, nil
}

// Ed25519PublicKeyToCompact converts an Ed25519 public key to compact format
func Ed25519PublicKeyToCompact(pub ed25519.PublicKey) []byte {
	return []byte(pub)
}

// CompactToEd25519PublicKey converts compact bytes to Ed25519 public key
func CompactToEd25519PublicKey(b []byte) (ed25519.PublicKey, error) {
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key size: %d", len(b))
	}
	return ed25519.PublicKey(b), nil
}

// ECDSAPublicKeyToCompact converts an ECDSA public key to compressed format
func ECDSAPublicKeyToCompact(pub *ecdsa.PublicKey) []byte {
	return CompressECPublicKey(pub.X, pub.Y)
}

// CompactToECDSAPublicKey converts compressed bytes to ECDSA public key
func CompactToECDSAPublicKey(b []byte, curve elliptic.Curve) (*ecdsa.PublicKey, error) {
	return DecompressECPublicKey(curve, b)
}

// Base64URLToRaw decodes base64url to raw bytes
func Base64URLToRaw(s string) ([]byte, error) {
	return crypto.Base64URLDecode(s)
}

// RawToBase64URL encodes raw bytes to base64url
func RawToBase64URL(b []byte) string {
	return crypto.Base64URLEncode(b)
}
