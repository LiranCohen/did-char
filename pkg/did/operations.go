package did

import "github.com/yourusername/did-char/pkg/keys"

// Patch action constants
const (
	PatchActionAddPublicKeys    = "add-public-keys"
	PatchActionRemovePublicKeys = "remove-public-keys"
	PatchActionAddServices      = "add-services"
	PatchActionRemoveServices   = "remove-services"
)

// Operation type constants
const (
	OperationTypeCreate     = "create"
	OperationTypeUpdate     = "update"
	OperationTypeRecover    = "recover"
	OperationTypeDeactivate = "deactivate"
)

// CreateOperation represents a CREATE operation
type CreateOperation struct {
	Type               string    `json:"type"`
	InitialDocument    *Document `json:"initialDocument"`
	UpdateCommitment   string    `json:"updateCommitment"`
	RecoveryCommitment string    `json:"recoveryCommitment"`
}

// Delta represents the changes to apply in an update/recover operation
// This follows the Sidetree spec structure
type Delta struct {
	Patches          []Patch `json:"patches"`
	UpdateCommitment string  `json:"updateCommitment"`
}

// UpdateSignedData represents the data that is signed in an update operation
// The signature binds the reveal key to specific delta contents
type UpdateSignedData struct {
	UpdateKey *keys.JWK `json:"updateKey"`
	DeltaHash string    `json:"deltaHash"`
}

// UpdateOperation represents an UPDATE operation with JWS signature
// This follows the Sidetree spec structure
type UpdateOperation struct {
	Type        string `json:"type"`
	DID         string `json:"didSuffix"`
	RevealValue string `json:"revealValue"`
	SignedData  string `json:"signedData"` // Compact JWS containing UpdateSignedData
	Delta       *Delta `json:"delta"`
}

// Patch represents a change to apply to a DID document
type Patch struct {
	Action       string      `json:"action"` // "add-public-keys", "remove-public-keys", "add-services", "remove-services"
	PublicKeys   []PublicKey `json:"publicKeys,omitempty"`
	PublicKeyIDs []string    `json:"publicKeyIds,omitempty"`
	Services     []Service   `json:"services,omitempty"`
	ServiceIDs   []string    `json:"serviceIds,omitempty"`
}

// RecoverSignedData represents the data that is signed in a recover operation
type RecoverSignedData struct {
	RecoveryKey        *keys.JWK `json:"recoveryKey"`
	DeltaHash          string    `json:"deltaHash"`
	RecoveryCommitment string    `json:"recoveryCommitment"`
}

// RecoverDelta represents the delta for a recover operation
type RecoverDelta struct {
	Patches          []Patch `json:"patches"`
	UpdateCommitment string  `json:"updateCommitment"`
}

// RecoverOperation represents a RECOVER operation with JWS signature
type RecoverOperation struct {
	Type        string        `json:"type"`
	DID         string        `json:"didSuffix"`
	RevealValue string        `json:"revealValue"`
	SignedData  string        `json:"signedData"` // Compact JWS containing RecoverSignedData
	Delta       *RecoverDelta `json:"delta"`
}

// DeactivateSignedData represents the data that is signed in a deactivate operation
type DeactivateSignedData struct {
	RecoveryKey *keys.JWK `json:"recoveryKey"`
	DIDSuffix   string    `json:"didSuffix"`
}

// DeactivateOperation represents a DEACTIVATE operation with JWS signature
type DeactivateOperation struct {
	Type        string `json:"type"`
	DID         string `json:"didSuffix"`
	RevealValue string `json:"revealValue"`
	SignedData  string `json:"signedData"` // Compact JWS containing DeactivateSignedData
}

