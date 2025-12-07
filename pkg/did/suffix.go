package did

import (
	"encoding/json"
	"fmt"

	"github.com/yourusername/did-char/pkg/crypto"
)

// GenerateDIDSuffix generates a DID suffix from initial state
func GenerateDIDSuffix(initialState interface{}) (string, error) {
	// Canonicalize to JSON
	canonical, err := json.Marshal(initialState)
	if err != nil {
		return "", fmt.Errorf("failed to marshal initial state: %w", err)
	}

	// Hash and encode
	suffix := crypto.HashToBase64URL(canonical)
	return suffix, nil
}

// FormatDID formats a suffix as a full DID URI
func FormatDID(suffix string) string {
	return fmt.Sprintf("did:char:%s", suffix)
}

// ParseDID extracts the suffix from a DID URI
func ParseDID(did string) (string, error) {
	if len(did) < 10 || did[:9] != "did:char:" {
		return "", fmt.Errorf("invalid DID format: %s", did)
	}
	return did[9:], nil
}
