package did

import (
	"encoding/json"
	"fmt"

	"github.com/yourusername/did-char/pkg/char"
	"github.com/yourusername/did-char/pkg/config"
	"github.com/yourusername/did-char/pkg/encoding"
	"github.com/yourusername/did-char/pkg/keys"
	"github.com/yourusername/did-char/pkg/storage"
)

// DeactivateDIDRequest contains parameters for deactivating a DID
type DeactivateDIDRequest struct {
	DID string
}

// DeactivateDID deactivates an existing DID
func DeactivateDID(
	req *DeactivateDIDRequest,
	cfg *config.Config,
	store *storage.Store,
	charClient *char.Client,
) error {

	// Load key file
	keyFile, err := keys.LoadKeyFile(req.DID, cfg.DataDir.KeysDir)
	if err != nil {
		return fmt.Errorf("failed to load key file: %w", err)
	}

	// Load current DID state
	didRecord, err := store.GetDID(req.DID)
	if err != nil {
		return fmt.Errorf("failed to load DID: %w", err)
	}
	if didRecord == nil {
		return fmt.Errorf("DID not found: %s", req.DID)
	}
	if didRecord.Status != "active" {
		return fmt.Errorf("DID is not active: %s", didRecord.Status)
	}

	// Generate reveal value and get signer based on recovery key type
	revealValue, signer, err := GetSignerAndReveal(keyFile.RecoveryKey)
	if err != nil {
		return fmt.Errorf("failed to create signer: %w", err)
	}

	// Verify reveal matches stored recovery commitment
	if !VerifyReveal(revealValue, didRecord.RecoveryCommitment) {
		return fmt.Errorf("reveal value does not match recovery commitment")
	}

	// Extract DID suffix
	suffix, err := ParseDID(req.DID)
	if err != nil {
		return fmt.Errorf("failed to parse DID: %w", err)
	}

	// Build signed data payload
	signedDataPayload := &DeactivateSignedData{
		RecoveryKey: getPublicJWK(keyFile.RecoveryKey),
		DIDSuffix:   suffix,
	}

	signedDataJSON, err := json.Marshal(signedDataPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal signed data: %w", err)
	}

	// Sign the payload
	signedData, err := signer.Sign(signedDataJSON)
	if err != nil {
		return fmt.Errorf("failed to sign deactivate data: %w", err)
	}

	// Create deactivate operation
	deactivateOp := &DeactivateOperation{
		Type:        "deactivate",
		DID:         req.DID,
		RevealValue: revealValue,
		SignedData:  signedData,
	}

	// Get next available ballot number from CHAR
	lastSyncedStr, err := store.GetSyncState("last_synced_ballot")
	if err != nil {
		return fmt.Errorf("failed to get sync state: %w", err)
	}

	startBallot := 0
	if lastSyncedStr != "" {
		fmt.Sscanf(lastSyncedStr, "%d", &startBallot)
	}

	// Search for next empty ballot starting from last synced
	ballotNumber, err := charClient.GetNextAvailableBallot(cfg.CHAR.AppPreimage, startBallot)
	if err != nil {
		return fmt.Errorf("failed to find available ballot: %w", err)
	}

	// Encode payload
	payloadHex, err := encoding.EncodePayload(encoding.OperationTypeDeactivate, suffix, deactivateOp)
	if err != nil {
		return fmt.Errorf("failed to encode payload: %w", err)
	}

	// Submit to CHAR and wait for confirmation
	if err := charClient.SubmitAndWaitForConfirmation(
		cfg.CHAR.AppPreimage,
		payloadHex,
		ballotNumber,
		cfg.Polling,
	); err != nil {
		return fmt.Errorf("failed to submit and confirm: %w", err)
	}

	// Now process the ballot to write to SQLite
	processor := NewProcessor(store, charClient, cfg.CHAR.AppPreimage)
	if err := processor.ProcessBallot(ballotNumber); err != nil {
		return fmt.Errorf("failed to process ballot: %w", err)
	}

	// Update key file
	keyFile.LastOperationBallot = ballotNumber

	if err := keys.SaveKeyFile(keyFile, cfg.DataDir.KeysDir); err != nil {
		return fmt.Errorf("failed to update key file: %w", err)
	}

	return nil
}

