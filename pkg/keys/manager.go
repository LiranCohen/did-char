package keys

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// KeyFile represents the key file for a DID
type KeyFile struct {
	DID                   string `json:"did"`
	UpdateKey             *JWK   `json:"updateKey"`
	RecoveryKey           *JWK   `json:"recoveryKey"`
	NextUpdateCommitment  string `json:"nextUpdateCommitment"`
	NextRecoveryCommitment string `json:"nextRecoveryCommitment"`
	CreatedAtBallot       int    `json:"createdAtBallot"`
	LastOperationBallot   int    `json:"lastOperationBallot"`
}

// GetKeyFilePath returns the path for a DID's key file
// If keysDir is empty, uses current directory
func GetKeyFilePath(did string, keysDir string) string {
	// Extract suffix from did:char:<suffix>
	suffix := did
	if len(did) > 9 && did[:9] == "did:char:" {
		suffix = did[9:]
	}
	filename := fmt.Sprintf("did_char_%s.json", suffix)

	if keysDir == "" {
		return filename
	}
	return filepath.Join(keysDir, filename)
}

// SaveKeyFile saves a key file to disk
func SaveKeyFile(keyFile *KeyFile, keysDir string) error {
	path := GetKeyFilePath(keyFile.DID, keysDir)

	data, err := json.MarshalIndent(keyFile, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal key file: %w", err)
	}

	// Ensure directory exists
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil { // More restrictive for keys
			return fmt.Errorf("failed to create directory: %w", err)
		}
	}

	// Write with restricted permissions (owner read/write only)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	return nil
}

// LoadKeyFile loads a key file from disk
func LoadKeyFile(did string, keysDir string) (*KeyFile, error) {
	path := GetKeyFilePath(did, keysDir)

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("key file not found: %s", path)
		}
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	var keyFile KeyFile
	if err := json.Unmarshal(data, &keyFile); err != nil {
		return nil, fmt.Errorf("failed to parse key file: %w", err)
	}

	return &keyFile, nil
}

// KeyFileExists checks if a key file exists for a DID
func KeyFileExists(did string, keysDir string) bool {
	path := GetKeyFilePath(did, keysDir)
	_, err := os.Stat(path)
	return err == nil
}
