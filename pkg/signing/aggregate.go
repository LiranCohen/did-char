package signing

import (
	"fmt"

	"github.com/cloudflare/circl/sign/bls"
)

// AggregateSignatures combines multiple BLS signatures into a single aggregate signature.
// All signatures must be over different messages for security.
// Returns the aggregated signature bytes.
func AggregateSignatures(signatures [][]byte) ([]byte, error) {
	if len(signatures) == 0 {
		return nil, fmt.Errorf("no signatures to aggregate")
	}

	if len(signatures) == 1 {
		// Single signature, return as-is
		return signatures[0], nil
	}

	// Convert raw bytes to bls.Signature type
	// The circl library's Aggregate function requires a KeyGroup instance
	var keyGroup bls.KeyG1SigG2
	aggSig, err := bls.Aggregate(keyGroup, signatures)
	if err != nil {
		return nil, fmt.Errorf("failed to aggregate signatures: %w", err)
	}

	return aggSig, nil
}

// VerifyAggregateSignature verifies an aggregated BLS signature against multiple
// public keys and their corresponding messages.
// Each pubKeys[i] must have signed messages[i].
func VerifyAggregateSignature(pubKeys []*bls.PublicKey[bls.KeyG1SigG2], messages [][]byte, aggSig []byte) error {
	if len(pubKeys) != len(messages) {
		return fmt.Errorf("pubKeys and messages length mismatch: %d vs %d", len(pubKeys), len(messages))
	}

	if len(pubKeys) == 0 {
		return fmt.Errorf("no public keys provided")
	}

	// For a single signature, use regular verification
	if len(pubKeys) == 1 {
		if !bls.Verify(pubKeys[0], messages[0], aggSig) {
			return fmt.Errorf("signature verification failed")
		}
		return nil
	}

	// Verify the aggregate signature
	valid := bls.VerifyAggregate(pubKeys, messages, aggSig)
	if !valid {
		return fmt.Errorf("aggregate signature verification failed")
	}

	return nil
}

// AggregatableOperation represents a single operation that can be aggregated with others.
// Used for collecting operations before creating a batch.
type AggregatableOperation struct {
	// Type is the operation type (update, recover, deactivate)
	Type string

	// DIDSuffix is the DID being operated on
	DIDSuffix string

	// RevealValue is the reveal value for commitment verification
	RevealValue string

	// Delta contains the patches and new commitment
	Delta interface{}

	// DeltaHash is the hash of the delta (the signed message)
	DeltaHash []byte

	// Signature is the raw BLS signature bytes (not JWS format)
	Signature []byte

	// PublicKey is the BLS public key that created the signature
	PublicKey *bls.PublicKey[bls.KeyG1SigG2]
}

// AggregateOperations takes multiple BLS-signed operations and creates an aggregate signature.
// Returns the aggregate signature bytes and the list of public keys (in order).
func AggregateOperations(ops []AggregatableOperation) ([]byte, []*bls.PublicKey[bls.KeyG1SigG2], [][]byte, error) {
	if len(ops) == 0 {
		return nil, nil, nil, fmt.Errorf("no operations to aggregate")
	}

	signatures := make([][]byte, len(ops))
	pubKeys := make([]*bls.PublicKey[bls.KeyG1SigG2], len(ops))
	messages := make([][]byte, len(ops))

	for i, op := range ops {
		if op.Signature == nil {
			return nil, nil, nil, fmt.Errorf("operation %d has no signature", i)
		}
		if op.PublicKey == nil {
			return nil, nil, nil, fmt.Errorf("operation %d has no public key", i)
		}
		if op.DeltaHash == nil {
			return nil, nil, nil, fmt.Errorf("operation %d has no delta hash", i)
		}

		signatures[i] = op.Signature
		pubKeys[i] = op.PublicKey
		messages[i] = op.DeltaHash
	}

	aggSig, err := AggregateSignatures(signatures)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to aggregate: %w", err)
	}

	return aggSig, pubKeys, messages, nil
}

// SignForAggregation signs a message with a BLS private key and returns the raw signature bytes.
// Unlike Sign(), this returns raw bytes suitable for aggregation, not JWS format.
func SignForAggregation(privateKey *bls.PrivateKey[bls.KeyG1SigG2], message []byte) []byte {
	return bls.Sign(privateKey, message)
}

// VerifyBeforeAggregation verifies a single signature before adding it to an aggregate.
// This is useful for validating individual signatures before combining them.
func VerifyBeforeAggregation(publicKey *bls.PublicKey[bls.KeyG1SigG2], message, signature []byte) bool {
	return bls.Verify(publicKey, message, signature)
}
