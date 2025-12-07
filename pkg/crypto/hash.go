package crypto

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

// SHA256 computes SHA-256 hash of data
func SHA256(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// Base64URLEncode encodes bytes to base64url without padding
func Base64URLEncode(data []byte) string {
	encoded := base64.URLEncoding.EncodeToString(data)
	// Remove padding
	return strings.TrimRight(encoded, "=")
}

// Base64URLDecode decodes base64url string
func Base64URLDecode(encoded string) ([]byte, error) {
	// Add padding if needed
	padding := (4 - len(encoded)%4) % 4
	encoded += strings.Repeat("=", padding)
	return base64.URLEncoding.DecodeString(encoded)
}

// HashToBase64URL computes SHA-256 and returns base64url encoded string
func HashToBase64URL(data []byte) string {
	hash := SHA256(data)
	return Base64URLEncode(hash)
}
