package did

import (
	"encoding/json"
	"fmt"

	"github.com/yourusername/did-char/pkg/char"
	"github.com/yourusername/did-char/pkg/config"
	"github.com/yourusername/did-char/pkg/crypto"
	"github.com/yourusername/did-char/pkg/encoding"
	"github.com/yourusername/did-char/pkg/keys"
	"github.com/yourusername/did-char/pkg/signing"
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

	// Parse current document
	var currentDoc Document
	if err := json.Unmarshal([]byte(didRecord.Document), &currentDoc); err != nil {
		return fmt.Errorf("failed to parse DID document: %w", err)
	}

	// Generate reveal value and get signer based on key type
	revealValue, signer, err := GetSignerAndReveal(keyFile.UpdateKey)
	if err != nil {
		return fmt.Errorf("failed to create signer: %w", err)
	}

	// Verify reveal matches stored commitment
	if !VerifyReveal(revealValue, didRecord.UpdateCommitment) {
		return fmt.Errorf("reveal value does not match commitment")
	}

	// Generate new key and commitment for next update (same algorithm as current)
	newUpdateKey, newCommitment, err := generateNextKeyAndCommitment(keyFile.UpdateKey)
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

	// Build delta
	delta := &Delta{
		Patches:          patches,
		UpdateCommitment: newCommitment,
	}

	// Compute delta hash
	deltaJSON, err := json.Marshal(delta)
	if err != nil {
		return fmt.Errorf("failed to marshal delta: %w", err)
	}
	deltaHash := crypto.HashToBase64URL(deltaJSON)

	// Build signed data payload
	signedDataPayload := &UpdateSignedData{
		UpdateKey: getPublicJWK(keyFile.UpdateKey),
		DeltaHash: deltaHash,
	}

	signedDataJSON, err := json.Marshal(signedDataPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal signed data: %w", err)
	}

	// Sign the payload
	signedData, err := signer.Sign(signedDataJSON)
	if err != nil {
		return fmt.Errorf("failed to sign update data: %w", err)
	}

	// Create update operation
	updateOp := &UpdateOperation{
		Type:        "update",
		DID:         req.DID,
		RevealValue: revealValue,
		SignedData:  signedData,
		Delta:       delta,
	}

	// Apply patches to document (for local state update)
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
	suffix, err := ParseDID(req.DID)
	if err != nil {
		return fmt.Errorf("failed to parse DID: %w", err)
	}
	payloadHex, err := encoding.EncodePayload(encoding.OperationTypeUpdate, suffix, updateOp)
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

	// Update key file with new key and commitment
	keyFile.UpdateKey = newUpdateKey
	keyFile.NextUpdateCommitment = newCommitment
	keyFile.LastOperationBallot = ballotNumber

	if err := keys.SaveKeyFile(keyFile, cfg.DataDir.KeysDir); err != nil {
		return fmt.Errorf("failed to update key file: %w", err)
	}

	return nil
}

// GetSignerAndReveal creates a signer and computes the reveal value for a key
// The reveal value is a hash of the public JWK, used in the commitment scheme
func GetSignerAndReveal(jwk *keys.JWK) (string, signing.Signer, error) {
	// Compute reveal value from public key JWK
	pubJWK := getPublicJWK(jwk)
	pubJWKJSON, err := json.Marshal(pubJWK)
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal public JWK: %w", err)
	}
	revealValue := crypto.HashToBase64URL(pubJWKJSON)

	// Create signer based on key type
	var signer signing.Signer
	switch {
	case jwk.Kty == "EC" && jwk.Crv == "P-256":
		privateKey, err := keys.JWKToPrivateKey(jwk)
		if err != nil {
			return "", nil, fmt.Errorf("failed to convert EC key: %w", err)
		}
		signer, err = signing.NewES256Signer(privateKey)
		if err != nil {
			return "", nil, fmt.Errorf("failed to create ES256 signer: %w", err)
		}
	case jwk.Kty == "OKP" && jwk.Crv == "Ed25519":
		privateKey, err := keys.JWKToEd25519PrivateKey(jwk)
		if err != nil {
			return "", nil, fmt.Errorf("failed to convert Ed25519 key: %w", err)
		}
		signer, err = signing.NewEdDSASigner(privateKey)
		if err != nil {
			return "", nil, fmt.Errorf("failed to create EdDSA signer: %w", err)
		}
	case jwk.Kty == "OKP" && jwk.Crv == "BLS12-381-G1":
		privateKey, err := keys.JWKToBLSPrivateKey(jwk)
		if err != nil {
			return "", nil, fmt.Errorf("failed to convert BLS key: %w", err)
		}
		signer, err = signing.NewBLSSigner(privateKey)
		if err != nil {
			return "", nil, fmt.Errorf("failed to create BLS signer: %w", err)
		}
	default:
		return "", nil, fmt.Errorf("unsupported key type: kty=%s, crv=%s", jwk.Kty, jwk.Crv)
	}

	return revealValue, signer, nil
}

// getPublicJWK returns a copy of the JWK without the private key component
func getPublicJWK(jwk *keys.JWK) *keys.JWK {
	return &keys.JWK{
		ID:  jwk.ID,
		Kty: jwk.Kty,
		Crv: jwk.Crv,
		Alg: jwk.Alg,
		X:   jwk.X,
		Y:   jwk.Y,
		// D is intentionally omitted (private key)
	}
}

// generateNextKeyAndCommitment generates a new key of the same type and its commitment
func generateNextKeyAndCommitment(currentKey *keys.JWK) (*keys.JWK, string, error) {
	var newJWK *keys.JWK

	switch {
	case currentKey.Kty == "EC" && currentKey.Crv == "P-256":
		newKey, err := keys.GenerateSecp256k1Key()
		if err != nil {
			return nil, "", fmt.Errorf("failed to generate EC key: %w", err)
		}
		newJWK = keys.PrivateKeyToJWK(newKey, currentKey.ID)

	case currentKey.Kty == "OKP" && currentKey.Crv == "Ed25519":
		newKey, err := keys.GenerateEd25519Key()
		if err != nil {
			return nil, "", fmt.Errorf("failed to generate Ed25519 key: %w", err)
		}
		newJWK = keys.Ed25519PrivateKeyToJWK(newKey, currentKey.ID)

	case currentKey.Kty == "OKP" && currentKey.Crv == "BLS12-381-G1":
		newKey, err := keys.GenerateBLSKey()
		if err != nil {
			return nil, "", fmt.Errorf("failed to generate BLS key: %w", err)
		}
		newJWK = keys.BLSPrivateKeyToJWK(newKey, currentKey.ID)

	default:
		return nil, "", fmt.Errorf("unsupported key type: kty=%s, crv=%s", currentKey.Kty, currentKey.Crv)
	}

	// Compute commitment from new public key
	pubJWK := getPublicJWK(newJWK)
	pubJWKJSON, err := json.Marshal(pubJWK)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal public JWK: %w", err)
	}

	// Reveal = hash(key), Commitment = hash(reveal)
	revealValue := crypto.HashToBase64URL(pubJWKJSON)
	revealBytes, _ := crypto.Base64URLDecode(revealValue)
	commitment := crypto.HashToBase64URL(revealBytes)

	return newJWK, commitment, nil
}
