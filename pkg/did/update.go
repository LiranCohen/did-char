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

// UpdateDIDRequest contains parameters for updating a DID
type UpdateDIDRequest struct {
	DID              string
	AddPublicKeys    []PublicKey
	RemovePublicKeys []string
	AddServices      []Service
	RemoveServices   []string
}

// UpdateDID updates an existing DID
func UpdateDID(
	req *UpdateDIDRequest,
	cfg *config.Config,
	store *storage.Store,
	charClient *char.Client,
) error {

	// Load key file
	keyFile, err := keys.LoadKeyFile(req.DID)
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

	// Parse current document
	var currentDoc Document
	if err := json.Unmarshal([]byte(didRecord.Document), &currentDoc); err != nil {
		return fmt.Errorf("failed to parse DID document: %w", err)
	}

	// Convert update key from JWK
	updateKey, err := keys.JWKToPrivateKey(keyFile.UpdateKey)
	if err != nil {
		return fmt.Errorf("failed to convert update key: %w", err)
	}

	// Generate reveal value for current commitment
	_, revealValue, err := GenerateCommitment(updateKey)
	if err != nil {
		return fmt.Errorf("failed to generate reveal value: %w", err)
	}

	// Verify reveal matches stored commitment
	if !VerifyReveal(revealValue, didRecord.UpdateCommitment) {
		return fmt.Errorf("reveal value does not match commitment")
	}

	// Generate new commitment for next update
	newCommitment, _, newUpdateKey, err := GenerateNextCommitment(updateKey)
	if err != nil {
		return fmt.Errorf("failed to generate new commitment: %w", err)
	}

	// Build patches
	patches := []Patch{}
	if len(req.AddPublicKeys) > 0 {
		patches = append(patches, Patch{
			Action:     "add-public-keys",
			PublicKeys: req.AddPublicKeys,
		})
	}
	if len(req.RemovePublicKeys) > 0 {
		patches = append(patches, Patch{
			Action:       "remove-public-keys",
			PublicKeyIDs: req.RemovePublicKeys,
		})
	}
	if len(req.AddServices) > 0 {
		patches = append(patches, Patch{
			Action:   "add-services",
			Services: req.AddServices,
		})
	}
	if len(req.RemoveServices) > 0 {
		patches = append(patches, Patch{
			Action:     "remove-services",
			ServiceIDs: req.RemoveServices,
		})
	}

	// Create update operation
	updateOp := &UpdateOperation{
		Type:          "update",
		DID:           req.DID,
		RevealValue:   revealValue,
		UpdateKey:     keys.PublicKeyToJWK(&updateKey.PublicKey, ""),
		NewCommitment: newCommitment,
		Patches:       patches,
	}

	// Apply patches to document
	updatedDoc := currentDoc
	for _, patch := range patches {
		switch patch.Action {
		case "add-public-keys":
			for _, pk := range patch.PublicKeys {
				updatedDoc.AddPublicKey(pk)
			}
		case "remove-public-keys":
			for _, pkID := range patch.PublicKeyIDs {
				updatedDoc.RemovePublicKey(pkID)
			}
		case "add-services":
			for _, svc := range patch.Services {
				updatedDoc.AddService(svc)
			}
		case "remove-services":
			for _, svcID := range patch.ServiceIDs {
				updatedDoc.RemoveService(svcID)
			}
		}
	}

	// Get next ballot number
	lastBallot, err := store.GetLastBallotNumber()
	if err != nil {
		return fmt.Errorf("failed to get last ballot: %w", err)
	}
	ballotNumber := lastBallot + 1

	// Encode payload
	suffix, _ := ParseDID(req.DID)
	payloadHex, err := encoding.EncodePayload(encoding.OperationTypeUpdate, suffix, updateOp)
	if err != nil {
		return fmt.Errorf("failed to encode payload: %w", err)
	}

	// Submit to CHAR and wait for confirmation
	roll, err := charClient.SubmitAndWaitForConfirmation(
		cfg.CHAR.AppPreimage,
		payloadHex,
		ballotNumber,
		cfg.Polling,
	)
	if err != nil {
		return fmt.Errorf("failed to submit and confirm: %w", err)
	}

	if !roll.Found {
		return fmt.Errorf("ballot %d not confirmed", ballotNumber)
	}

	// Update database
	docJSON, _ := json.Marshal(updatedDoc)
	didRecord.Document = string(docJSON)
	didRecord.UpdateCommitment = newCommitment
	didRecord.LastOperationBallot = ballotNumber

	if err := store.SaveDID(didRecord); err != nil {
		return fmt.Errorf("failed to update DID: %w", err)
	}

	// Save operation
	opJSON, _ := json.Marshal(updateOp)
	opRecord := &storage.OperationRecord{
		DID:           req.DID,
		BallotNumber:  ballotNumber,
		OperationType: "update",
		OperationData: string(opJSON),
	}

	if err := store.SaveOperation(opRecord); err != nil {
		return fmt.Errorf("failed to save operation: %w", err)
	}

	// Update key file with new commitment
	keyFile.UpdateKey = keys.PrivateKeyToJWK(newUpdateKey, "updateKey")
	keyFile.NextUpdateCommitment = newCommitment
	keyFile.LastOperationBallot = ballotNumber

	if err := keys.SaveKeyFile(keyFile); err != nil {
		return fmt.Errorf("failed to update key file: %w", err)
	}

	return nil
}
