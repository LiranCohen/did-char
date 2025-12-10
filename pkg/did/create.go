package did

import (
	"crypto/ecdsa"
	"fmt"
	"strconv"

	"github.com/yourusername/did-char/pkg/char"
	"github.com/yourusername/did-char/pkg/config"
	"github.com/yourusername/did-char/pkg/encoding"
	"github.com/yourusername/did-char/pkg/keys"
	"github.com/yourusername/did-char/pkg/storage"
)

// CreateDIDRequest contains parameters for creating a DID
type CreateDIDRequest struct {
	Services []Service
}

// CreateDIDResult contains the result of creating a DID
type CreateDIDResult struct {
	DID          string
	KeyFile      *keys.KeyFile
	Document     *Document
	BallotNumber int
}

// CreateDID creates a new DID
func CreateDID(
	req *CreateDIDRequest,
	cfg *config.Config,
	store *storage.Store,
	charClient *char.Client,
) (*CreateDIDResult, error) {

	// Generate update and recovery keys
	updateKey, err := keys.GenerateSecp256k1Key()
	if err != nil {
		return nil, fmt.Errorf("failed to generate update key: %w", err)
	}

	recoveryKey, err := keys.GenerateSecp256k1Key()
	if err != nil {
		return nil, fmt.Errorf("failed to generate recovery key: %w", err)
	}

	// Generate commitments
	updateCommitment, _, err := GenerateCommitment(updateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate update commitment: %w", err)
	}

	recoveryCommitment, _, err := GenerateCommitment(recoveryKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate recovery commitment: %w", err)
	}

	// Create initial document (without DID yet)
	doc := NewDocument("")

	// Add initial public key (from update key)
	updateJWK := keys.PublicKeyToJWK(&updateKey.PublicKey, "#key-1")
	doc.AddPublicKey(PublicKey{
		ID:           "#key-1",
		Type:         "EcdsaSecp256k1VerificationKey2019",
		PublicKeyJwk: updateJWK,
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
		UpdateKey:              keys.PrivateKeyToJWK(updateKey, "updateKey"),
		RecoveryKey:            keys.PrivateKeyToJWK(recoveryKey, "recoveryKey"),
		NextUpdateCommitment:   updateCommitment,
		NextRecoveryCommitment: recoveryCommitment,
		CreatedAtBallot:        ballotNumber,
		LastOperationBallot:    ballotNumber,
	}

	// Save key file
	if err := keys.SaveKeyFile(keyFile); err != nil {
		return nil, fmt.Errorf("failed to save key file: %w", err)
	}

	return &CreateDIDResult{
		DID:          did,
		KeyFile:      keyFile,
		Document:     doc,
		BallotNumber: ballotNumber,
	}, nil
}

// Helper to generate a new commitment for next operation
func GenerateNextCommitment(currentKey *ecdsa.PrivateKey) (string, string, *ecdsa.PrivateKey, error) {
	newKey, err := keys.GenerateSecp256k1Key()
	if err != nil {
		return "", "", nil, err
	}

	commitment, reveal, err := GenerateCommitment(newKey)
	if err != nil {
		return "", "", nil, err
	}

	return commitment, reveal, newKey, nil
}
