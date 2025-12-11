package did

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/yourusername/did-char/pkg/char"
	"github.com/yourusername/did-char/pkg/config"
	"github.com/yourusername/did-char/pkg/crypto"
	"github.com/yourusername/did-char/pkg/encoding"
	"github.com/yourusername/did-char/pkg/keys"
	"github.com/yourusername/did-char/pkg/signing"
	"github.com/yourusername/did-char/pkg/storage"
)

// CreateDIDRequest contains parameters for creating a DID
type CreateDIDRequest struct {
	Services  []Service
	Algorithm signing.SignatureAlgorithm // ES256, EdDSA, or BLS (default: ES256)
}

// CreateDIDResult contains the result of creating a DID
type CreateDIDResult struct {
	DID          string
	KeyFile      *keys.KeyFile
	Document     *Document
	BallotNumber int
}

// CreateDID creates a new DID with the specified algorithm
func CreateDID(
	req *CreateDIDRequest,
	cfg *config.Config,
	store *storage.Store,
	charClient *char.Client,
) (*CreateDIDResult, error) {

	// Default to ES256 if no algorithm specified
	algorithm := req.Algorithm
	if algorithm == "" {
		algorithm = signing.AlgES256
	}

	// Generate update and recovery keys based on algorithm
	updateKey, err := generateKeyForAlgorithm(algorithm, "updateKey")
	if err != nil {
		return nil, fmt.Errorf("failed to generate update key: %w", err)
	}

	recoveryKey, err := generateKeyForAlgorithm(algorithm, "recoveryKey")
	if err != nil {
		return nil, fmt.Errorf("failed to generate recovery key: %w", err)
	}

	// Generate commitments
	updateCommitment, _, err := GenerateCommitmentFromJWK(updateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate update commitment: %w", err)
	}

	recoveryCommitment, _, err := GenerateCommitmentFromJWK(recoveryKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate recovery commitment: %w", err)
	}

	// Create initial document (without DID yet)
	doc := NewDocument("")

	// Add initial public key based on algorithm
	verificationKeyType := getVerificationKeyType(algorithm)
	doc.AddPublicKey(PublicKey{
		ID:           "#key-1",
		Type:         verificationKeyType,
		PublicKeyJwk: getPublicJWK(updateKey),
	})
	doc.AddAuthentication("#key-1")

	// Add services if any
	for i, svc := range req.Services {
		if svc.ID == "" {
			svc.ID = fmt.Sprintf("#service-%d", i+1)
		}
		doc.AddService(svc)
	}

	// Create operation
	createOp := &CreateOperation{
		Type:               "create",
		InitialDocument:    doc,
		UpdateCommitment:   updateCommitment,
		RecoveryCommitment: recoveryCommitment,
	}

	// Generate DID suffix from initial state
	suffix, err := GenerateDIDSuffix(createOp)
	if err != nil {
		return nil, fmt.Errorf("failed to generate DID suffix: %w", err)
	}

	did := FormatDID(suffix)
	doc.ID = did
	createOp.InitialDocument.ID = did

	// Update public key controller
	if len(doc.PublicKeys) > 0 {
		doc.PublicKeys[0].Controller = did
	}

	// Get next available ballot number from CHAR
	// Use last synced ballot as starting point (not last operation ballot)
	lastSyncedStr, err := store.GetSyncState("last_synced_ballot")
	if err != nil {
		return nil, fmt.Errorf("failed to get sync state: %w", err)
	}

	startBallot := 0
	if lastSyncedStr != "" {
		startBallot, err = strconv.Atoi(lastSyncedStr)
		if err != nil {
			return nil, fmt.Errorf("invalid last synced ballot in sync state: %w", err)
		}
	}

	// Search for next empty ballot starting from last synced
	ballotNumber, err := charClient.GetNextAvailableBallot(cfg.CHAR.AppPreimage, startBallot)
	if err != nil {
		return nil, fmt.Errorf("failed to find available ballot: %w", err)
	}

	// Encode payload
	payloadHex, err := encoding.EncodePayload(encoding.OperationTypeCreate, suffix, createOp)
	if err != nil {
		return nil, fmt.Errorf("failed to encode payload: %w", err)
	}

	// Submit to CHAR and wait for confirmation
	if err := charClient.SubmitAndWaitForConfirmation(
		cfg.CHAR.AppPreimage,
		payloadHex,
		ballotNumber,
		cfg.Polling,
	); err != nil {
		return nil, fmt.Errorf("failed to submit and confirm: %w", err)
	}

	// Now process the ballot to write to SQLite
	processor := NewProcessor(store, charClient, cfg.CHAR.AppPreimage)
	if err := processor.ProcessBallot(ballotNumber); err != nil {
		return nil, fmt.Errorf("failed to process ballot: %w", err)
	}

	// Create key file
	keyFile := &keys.KeyFile{
		DID:                    did,
		UpdateKey:              updateKey,
		RecoveryKey:            recoveryKey,
		NextUpdateCommitment:   updateCommitment,
		NextRecoveryCommitment: recoveryCommitment,
		CreatedAtBallot:        ballotNumber,
		LastOperationBallot:    ballotNumber,
	}

	// Save key file
	if err := keys.SaveKeyFile(keyFile, cfg.DataDir.KeysDir); err != nil {
		return nil, fmt.Errorf("failed to save key file: %w", err)
	}

	return &CreateDIDResult{
		DID:          did,
		KeyFile:      keyFile,
		Document:     doc,
		BallotNumber: ballotNumber,
	}, nil
}

// generateKeyForAlgorithm generates a key pair for the specified algorithm
func generateKeyForAlgorithm(algorithm signing.SignatureAlgorithm, keyID string) (*keys.JWK, error) {
	switch algorithm {
	case signing.AlgES256:
		key, err := keys.GenerateSecp256k1Key()
		if err != nil {
			return nil, err
		}
		return keys.PrivateKeyToJWK(key, keyID), nil

	case signing.AlgEdDSA:
		key, err := keys.GenerateEd25519Key()
		if err != nil {
			return nil, err
		}
		return keys.Ed25519PrivateKeyToJWK(key, keyID), nil

	case signing.AlgBLS:
		key, err := keys.GenerateBLSKey()
		if err != nil {
			return nil, err
		}
		return keys.BLSPrivateKeyToJWK(key, keyID), nil

	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// getVerificationKeyType returns the appropriate verification key type for the algorithm
func getVerificationKeyType(algorithm signing.SignatureAlgorithm) string {
	switch algorithm {
	case signing.AlgES256:
		return "EcdsaSecp256k1VerificationKey2019"
	case signing.AlgEdDSA:
		return "Ed25519VerificationKey2020"
	case signing.AlgBLS:
		return "Bls12381G1Key2020"
	default:
		return "JsonWebKey2020"
	}
}

// GenerateNextCommitmentForJWK generates a new key of the same type and its commitment
// This is a helper for operations that need to rotate keys
func GenerateNextCommitmentForJWK(currentKey *keys.JWK) (*keys.JWK, string, string, error) {
	newKey, commitment, err := generateNextKeyAndCommitment(currentKey)
	if err != nil {
		return nil, "", "", err
	}

	// Compute reveal value
	pubJWK := getPublicJWK(newKey)
	pubJWKJSON, _ := json.Marshal(pubJWK)
	revealValue := crypto.HashToBase64URL(pubJWKJSON)

	return newKey, commitment, revealValue, nil
}
