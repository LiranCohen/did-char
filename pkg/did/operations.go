package did

import "github.com/yourusername/did-char/pkg/keys"

// OperationType represents the type of DID operation
type OperationType byte

const (
	OperationTypeCreate     OperationType = 0x01
	OperationTypeUpdate     OperationType = 0x02
	OperationTypeRecover    OperationType = 0x03
	OperationTypeDeactivate OperationType = 0x04
)

// CreateOperation represents a CREATE operation
type CreateOperation struct {
	Type                   string      `json:"type"`
	InitialDocument        *Document   `json:"initialDocument"`
	UpdateCommitment       string      `json:"updateCommitment"`
	RecoveryCommitment     string      `json:"recoveryCommitment"`
}

// UpdateOperation represents an UPDATE operation
type UpdateOperation struct {
	Type            string          `json:"type"`
	DID             string          `json:"did"`
	RevealValue     string          `json:"revealValue"`
	UpdateKey       *keys.JWK       `json:"updateKey"`
	NewCommitment   string          `json:"newCommitment"`
	Patches         []Patch         `json:"patches"`
}

// Patch represents a change to apply to a DID document
type Patch struct {
	Action         string      `json:"action"` // "add-public-keys", "remove-public-keys", "add-services", "remove-services"
	PublicKeys     []PublicKey `json:"publicKeys,omitempty"`
	PublicKeyIDs   []string    `json:"publicKeyIds,omitempty"`
	Services       []Service   `json:"services,omitempty"`
	ServiceIDs     []string    `json:"serviceIds,omitempty"`
}

// DeactivateOperation represents a DEACTIVATE operation
type DeactivateOperation struct {
	Type        string    `json:"type"`
	DID         string    `json:"did"`
	RevealValue string    `json:"revealValue"`
	RecoveryKey *keys.JWK `json:"recoveryKey"`
}

// RecoverOperation represents a RECOVER operation
type RecoverOperation struct {
	Type                   string    `json:"type"`
	DID                    string    `json:"did"`
	RevealValue            string    `json:"revealValue"`
	RecoveryKey            *keys.JWK `json:"recoveryKey"`
	NewDocument            *Document `json:"newDocument"`
	NewUpdateCommitment    string    `json:"newUpdateCommitment"`
	NewRecoveryCommitment  string    `json:"newRecoveryCommitment"`
}
