package did

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"

	"github.com/yourusername/did-char/pkg/char"
	"github.com/yourusername/did-char/pkg/encoding"
	"github.com/yourusername/did-char/pkg/storage"
)

// Processor processes decision rolls and applies them to storage
type Processor struct {
	store      *storage.Store
	charClient *char.Client
	appDomain  string
}

// NewProcessor creates a new decision roll processor
func NewProcessor(store *storage.Store, charClient *char.Client, appDomain string) *Processor {
	return &Processor{
		store:      store,
		charClient: charClient,
		appDomain:  appDomain,
	}
}

// ProcessBallot fetches and processes a single ballot
func (p *Processor) ProcessBallot(ballotNumber int) error {
	// Query decision roll
	roll, err := p.charClient.GetReferendumDecisionRoll(p.appDomain, ballotNumber, 1)
	if err != nil {
		return fmt.Errorf("failed to get decision roll: %w", err)
	}

	// If ballot not found, it hasn't been decided yet
	if !roll.Found {
		return nil
	}

	// Decode payload
	if roll.DecisionRoll == nil || roll.DecisionRoll.Data == "" {
		// Empty ballot, skip
		return nil
	}

	payloadHex := roll.DecisionRoll.Data

	// Skip empty/null ballots (length <= 8 hex chars = 4 bytes)
	if len(payloadHex) <= 8 {
		return nil
	}

	payloadHex = stripWrappers(payloadHex)

	version, opType, didSuffix, operationJSON, err := encoding.DecodePayload(payloadHex)
	if err != nil {
		log.Printf("Failed to decode payload for ballot %d: %v", ballotNumber, err)
		// Invalid or empty payload, skip this ballot
		return nil
	}

	if version != encoding.PayloadVersion {
		fmt.Printf("Unsupported payload version %d for ballot %d\n", version, ballotNumber)
		// Unsupported version, skip this ballot (likely non-DID data)
		return nil
	}

	did := FormatDID(didSuffix)
	fmt.Printf("Processing DID %s operation type %d on ballot %d\n", did, opType, ballotNumber)

	// Process based on operation type
	switch opType {
	case encoding.OperationTypeCreate:
		return p.processCreate(did, operationJSON, ballotNumber)
	case encoding.OperationTypeUpdate:
		return p.processUpdate(did, operationJSON, ballotNumber)
	case encoding.OperationTypeRecover:
		return p.processRecover(did, operationJSON, ballotNumber)
	case encoding.OperationTypeDeactivate:
		return p.processDeactivate(did, operationJSON, ballotNumber)
	default:
		fmt.Printf("Unknown operation type %d for ballot %d\n", opType, ballotNumber)
		return fmt.Errorf("unknown operation type: %d", opType)
	}
}

// processCreate handles CREATE operations
func (p *Processor) processCreate(did string, operationJSON []byte, ballotNumber int) error {
	var op CreateOperation
	if err := json.Unmarshal(operationJSON, &op); err != nil {
		return fmt.Errorf("failed to unmarshal CREATE operation: %w", err)
	}

	// Check if DID already exists
	exists, err := p.store.DIDExists(did)
	if err != nil {
		return fmt.Errorf("failed to check DID existence: %w", err)
	}
	if exists {
		// DID already created, skip
		return nil
	}

	// Save DID to database
	docJSON, _ := json.Marshal(op.InitialDocument)
	didRecord := &storage.DIDRecord{
		DID:                 did,
		Status:              "active",
		Document:            string(docJSON),
		UpdateCommitment:    op.UpdateCommitment,
		RecoveryCommitment:  op.RecoveryCommitment,
		CreatedAtBallot:     ballotNumber,
		LastOperationBallot: ballotNumber,
	}

	if err := p.store.SaveDID(didRecord); err != nil {
		return fmt.Errorf("failed to save DID: %w", err)
	}

	// Save operation
	opRecord := &storage.OperationRecord{
		DID:           did,
		BallotNumber:  ballotNumber,
		OperationType: "create",
		OperationData: string(operationJSON),
	}

	if err := p.store.SaveOperation(opRecord); err != nil {
		return fmt.Errorf("failed to save operation: %w", err)
	}

	return nil
}

// processUpdate handles UPDATE operations
func (p *Processor) processUpdate(did string, operationJSON []byte, ballotNumber int) error {
	var op UpdateOperation
	if err := json.Unmarshal(operationJSON, &op); err != nil {
		return fmt.Errorf("failed to unmarshal UPDATE operation: %w", err)
	}

	// Load current DID state
	didRecord, err := p.store.GetDID(did)
	if err != nil {
		return fmt.Errorf("failed to load DID: %w", err)
	}
	if didRecord == nil {
		// DID doesn't exist, skip
		return nil
	}
	if didRecord.Status != "active" {
		// DID is not active, skip
		return nil
	}

	// Verify reveal matches commitment
	if !VerifyReveal(op.RevealValue, didRecord.UpdateCommitment) {
		return fmt.Errorf("reveal value does not match commitment")
	}

	// Parse current document
	var currentDoc Document
	if err := json.Unmarshal([]byte(didRecord.Document), &currentDoc); err != nil {
		return fmt.Errorf("failed to parse DID document: %w", err)
	}

	// Apply patches
	updatedDoc := currentDoc
	for _, patch := range op.Patches {
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

	// Update database
	docJSON, _ := json.Marshal(updatedDoc)
	didRecord.Document = string(docJSON)
	didRecord.UpdateCommitment = op.NewCommitment
	didRecord.LastOperationBallot = ballotNumber

	if err := p.store.SaveDID(didRecord); err != nil {
		return fmt.Errorf("failed to update DID: %w", err)
	}

	// Save operation
	opRecord := &storage.OperationRecord{
		DID:           did,
		BallotNumber:  ballotNumber,
		OperationType: "update",
		OperationData: string(operationJSON),
	}

	if err := p.store.SaveOperation(opRecord); err != nil {
		return fmt.Errorf("failed to save operation: %w", err)
	}

	return nil
}

// processRecover handles RECOVER operations
func (p *Processor) processRecover(did string, operationJSON []byte, ballotNumber int) error {
	var op RecoverOperation
	if err := json.Unmarshal(operationJSON, &op); err != nil {
		return fmt.Errorf("failed to unmarshal RECOVER operation: %w", err)
	}

	// Load current DID state
	didRecord, err := p.store.GetDID(did)
	if err != nil {
		return fmt.Errorf("failed to load DID: %w", err)
	}
	if didRecord == nil {
		return nil
	}
	if didRecord.Status != "active" {
		return nil
	}

	// Verify reveal matches recovery commitment
	if !VerifyReveal(op.RevealValue, didRecord.RecoveryCommitment) {
		return fmt.Errorf("reveal value does not match recovery commitment")
	}

	// Replace entire document
	docJSON, _ := json.Marshal(op.NewDocument)
	didRecord.Document = string(docJSON)
	didRecord.UpdateCommitment = op.NewUpdateCommitment
	didRecord.RecoveryCommitment = op.NewRecoveryCommitment
	didRecord.LastOperationBallot = ballotNumber

	if err := p.store.SaveDID(didRecord); err != nil {
		return fmt.Errorf("failed to update DID: %w", err)
	}

	// Save operation
	opRecord := &storage.OperationRecord{
		DID:           did,
		BallotNumber:  ballotNumber,
		OperationType: "recover",
		OperationData: string(operationJSON),
	}

	if err := p.store.SaveOperation(opRecord); err != nil {
		return fmt.Errorf("failed to save operation: %w", err)
	}

	return nil
}

// processDeactivate handles DEACTIVATE operations
func (p *Processor) processDeactivate(did string, operationJSON []byte, ballotNumber int) error {
	var op DeactivateOperation
	if err := json.Unmarshal(operationJSON, &op); err != nil {
		return fmt.Errorf("failed to unmarshal DEACTIVATE operation: %w", err)
	}

	// Load current DID state
	didRecord, err := p.store.GetDID(did)
	if err != nil {
		return fmt.Errorf("failed to load DID: %w", err)
	}
	if didRecord == nil {
		return nil
	}
	if didRecord.Status != "active" {
		return nil
	}

	// Verify reveal matches recovery commitment
	if !VerifyReveal(op.RevealValue, didRecord.RecoveryCommitment) {
		return fmt.Errorf("reveal value does not match recovery commitment")
	}

	// Deactivate
	didRecord.Status = "deactivated"
	didRecord.LastOperationBallot = ballotNumber

	if err := p.store.SaveDID(didRecord); err != nil {
		return fmt.Errorf("failed to update DID: %w", err)
	}

	// Save operation
	opRecord := &storage.OperationRecord{
		DID:           did,
		BallotNumber:  ballotNumber,
		OperationType: "deactivate",
		OperationData: string(operationJSON),
	}

	if err := p.store.SaveOperation(opRecord); err != nil {
		return fmt.Errorf("failed to save operation: %w", err)
	}

	return nil
}

// SyncFromBallot syncs all ballots starting from a given ballot number
func (p *Processor) SyncFromBallot(startBallot int, maxBallots int) (int, error) {
	processedCount := 0

	for i := 0; i < maxBallots; i++ {
		ballotNum := startBallot + i

		err := p.ProcessBallot(ballotNum)
		if err != nil {
			return processedCount, fmt.Errorf("failed to process ballot %d: %w", ballotNum, err)
		}

		// Update sync state
		if err := p.store.SetSyncState("last_synced_ballot", fmt.Sprintf("%d", ballotNum)); err != nil {
			return processedCount, fmt.Errorf("failed to update sync state: %w", err)
		}

		processedCount++
	}

	return processedCount, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// stripWrappers removes CHAR slot wrapper or referendum vote wrapper from payload hex
func stripWrappers(hexData string) string {
	data, err := hex.DecodeString(hexData)
	if err != nil || len(data) < 3 {
		return hexData
	}

	// Check if it starts with CHAR slot wrapper: 0000
	if data[0] == 0x00 && data[1] == 0x00 {
		// CHAR slot format: [0x00][0x00][CompactSize length][payload]
		return stripSlotWrapper(hexData)
	}

	// Check if it starts with referendum vote wrapper: 0x00 (leaf type)
	if data[0] == 0x00 {
		// Referendum vote format: [0x00][varint ballot][compact_size length][payload]
		return stripReferendumVoteWrapper(hexData)
	}

	// No recognized wrapper, return as-is
	return hexData
}

// stripSlotWrapper removes CHAR slot format wrapper
func stripSlotWrapper(hexData string) string {
	data, _ := hex.DecodeString(hexData)
	if len(data) < 3 {
		return hexData
	}

	// Parse CompactSize at position 2
	if data[2] < 0xfd {
		return hexData[6:] // Skip 0000 + 1 byte = 3 bytes = 6 hex chars
	} else if data[2] == 0xfd {
		return hexData[10:] // Skip 0000 + fd + 2 bytes = 5 bytes = 10 hex chars
	} else if data[2] == 0xfe {
		return hexData[14:] // Skip 0000 + fe + 4 bytes = 7 bytes = 14 hex chars
	} else {
		return hexData[22:] // Skip 0000 + ff + 8 bytes = 11 bytes = 22 hex chars
	}
}

// stripReferendumVoteWrapper removes referendum vote wrapper
func stripReferendumVoteWrapper(hexData string) string {
	data, _ := hex.DecodeString(hexData)
	if len(data) < 3 {
		return hexData
	}

	offset := 1 // Skip leaf type byte

	// Skip Go varint ballot number (we need to read it to know its length)
	for offset < len(data) {
		if data[offset] < 0x80 {
			offset++ // Last byte of varint
			break
		}
		offset++ // Continue reading varint
	}

	if offset >= len(data) {
		return hexData // Invalid
	}

	// Skip CompactSize payload length
	if data[offset] < 0xfd {
		offset += 1
	} else if data[offset] == 0xfd {
		offset += 3
	} else if data[offset] == 0xfe {
		offset += 5
	} else {
		offset += 9
	}

	// Return payload after all wrappers
	return hexData[offset*2:]
}
