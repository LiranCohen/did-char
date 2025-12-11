package did

import (
	"encoding/json"
	"testing"

	"github.com/yourusername/did-char/pkg/keys"
)

func TestCreateOperationJSON(t *testing.T) {
	doc := NewDocument("did:char:test")
	doc.AddPublicKey(PublicKey{ID: "#key-1", Type: "test"})

	op := CreateOperation{
		Type:               "create",
		InitialDocument:    doc,
		UpdateCommitment:   "update-commitment-hash",
		RecoveryCommitment: "recovery-commitment-hash",
	}

	data, err := json.Marshal(op)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var decoded CreateOperation
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if decoded.Type != "create" {
		t.Errorf("decoded.Type = %q, want \"create\"", decoded.Type)
	}
	if decoded.UpdateCommitment != op.UpdateCommitment {
		t.Errorf("UpdateCommitment mismatch")
	}
	if decoded.RecoveryCommitment != op.RecoveryCommitment {
		t.Errorf("RecoveryCommitment mismatch")
	}
	if decoded.InitialDocument == nil {
		t.Error("InitialDocument is nil")
	}
}

func TestDeltaJSON(t *testing.T) {
	delta := Delta{
		Patches: []Patch{
			{Action: "add-public-keys", PublicKeys: []PublicKey{{ID: "#key-1"}}},
			{Action: "add-services", Services: []Service{{ID: "#svc-1", Type: "test", ServiceEndpoint: "https://test.com"}}},
		},
		UpdateCommitment: "new-commitment",
	}

	data, err := json.Marshal(delta)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var decoded Delta
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if len(decoded.Patches) != 2 {
		t.Errorf("expected 2 patches, got %d", len(decoded.Patches))
	}
	if decoded.UpdateCommitment != "new-commitment" {
		t.Errorf("UpdateCommitment = %q, want \"new-commitment\"", decoded.UpdateCommitment)
	}
}

func TestUpdateOperationJSON(t *testing.T) {
	op := UpdateOperation{
		Type:        "update",
		DID:         "did:char:test123",
		RevealValue: "reveal-value-hash",
		SignedData:  "eyJhbGciOiJFUzI1NiJ9.eyJ0ZXN0IjoiZGF0YSJ9.signature",
		Delta: &Delta{
			Patches:          []Patch{{Action: "add-services"}},
			UpdateCommitment: "next-commitment",
		},
	}

	data, err := json.Marshal(op)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var decoded UpdateOperation
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if decoded.Type != "update" {
		t.Errorf("decoded.Type = %q, want \"update\"", decoded.Type)
	}
	if decoded.SignedData != op.SignedData {
		t.Errorf("SignedData mismatch")
	}
	if decoded.Delta == nil {
		t.Error("Delta is nil")
	}
}

func TestUpdateSignedDataJSON(t *testing.T) {
	signedData := UpdateSignedData{
		UpdateKey: &keys.JWK{
			Kty: "EC",
			Crv: "P-256",
			X:   "x-value",
			Y:   "y-value",
		},
		DeltaHash: "delta-hash-value",
	}

	data, err := json.Marshal(signedData)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var decoded UpdateSignedData
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if decoded.DeltaHash != "delta-hash-value" {
		t.Errorf("DeltaHash mismatch")
	}
	if decoded.UpdateKey == nil {
		t.Error("UpdateKey is nil")
	}
	if decoded.UpdateKey.Kty != "EC" {
		t.Errorf("UpdateKey.Kty = %q, want \"EC\"", decoded.UpdateKey.Kty)
	}
}

func TestRecoverOperationJSON(t *testing.T) {
	op := RecoverOperation{
		Type:        "recover",
		DID:         "did:char:test",
		RevealValue: "recovery-reveal",
		SignedData:  "signed-jws-data",
		Delta: &RecoverDelta{
			Patches:          []Patch{{Action: "add-public-keys"}},
			UpdateCommitment: "new-update-commitment",
		},
	}

	data, err := json.Marshal(op)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var decoded RecoverOperation
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if decoded.Type != "recover" {
		t.Errorf("decoded.Type = %q, want \"recover\"", decoded.Type)
	}
}

func TestRecoverSignedDataJSON(t *testing.T) {
	signedData := RecoverSignedData{
		RecoveryKey: &keys.JWK{
			Kty: "OKP",
			Crv: "Ed25519",
			X:   "ed-public-key",
		},
		DeltaHash:          "delta-hash",
		RecoveryCommitment: "new-recovery-commitment",
	}

	data, err := json.Marshal(signedData)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var decoded RecoverSignedData
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if decoded.RecoveryCommitment != "new-recovery-commitment" {
		t.Errorf("RecoveryCommitment mismatch")
	}
}

func TestDeactivateOperationJSON(t *testing.T) {
	op := DeactivateOperation{
		Type:        "deactivate",
		DID:         "did:char:deactivate-test",
		RevealValue: "deactivate-reveal",
		SignedData:  "signed-deactivate-data",
	}

	data, err := json.Marshal(op)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var decoded DeactivateOperation
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if decoded.Type != "deactivate" {
		t.Errorf("decoded.Type = %q, want \"deactivate\"", decoded.Type)
	}
	if decoded.DID != "did:char:deactivate-test" {
		t.Errorf("DID mismatch")
	}
}

func TestDeactivateSignedDataJSON(t *testing.T) {
	signedData := DeactivateSignedData{
		RecoveryKey: &keys.JWK{
			Kty: "OKP",
			Crv: "BLS12-381-G1",
			X:   "bls-public-key",
		},
		DIDSuffix: "test-suffix",
	}

	data, err := json.Marshal(signedData)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var decoded DeactivateSignedData
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if decoded.DIDSuffix != "test-suffix" {
		t.Errorf("DIDSuffix = %q, want \"test-suffix\"", decoded.DIDSuffix)
	}
}

func TestPatchJSON(t *testing.T) {
	tests := []struct {
		name  string
		patch Patch
	}{
		{
			name: "add-public-keys",
			patch: Patch{
				Action: "add-public-keys",
				PublicKeys: []PublicKey{
					{ID: "#key-1", Type: "test"},
					{ID: "#key-2", Type: "test2"},
				},
			},
		},
		{
			name: "remove-public-keys",
			patch: Patch{
				Action:       "remove-public-keys",
				PublicKeyIDs: []string{"#key-1", "#key-2"},
			},
		},
		{
			name: "add-services",
			patch: Patch{
				Action: "add-services",
				Services: []Service{
					{ID: "#svc-1", Type: "LinkedDomains", ServiceEndpoint: "https://test.com"},
				},
			},
		},
		{
			name: "remove-services",
			patch: Patch{
				Action:     "remove-services",
				ServiceIDs: []string{"#svc-1"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.patch)
			if err != nil {
				t.Fatalf("json.Marshal failed: %v", err)
			}

			var decoded Patch
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("json.Unmarshal failed: %v", err)
			}

			if decoded.Action != tt.patch.Action {
				t.Errorf("Action = %q, want %q", decoded.Action, tt.patch.Action)
			}
		})
	}
}

func TestPatchOmitEmpty(t *testing.T) {
	// Test that empty fields are omitted
	patch := Patch{
		Action:     "add-public-keys",
		PublicKeys: []PublicKey{{ID: "#key-1"}},
		// Other fields left empty
	}

	data, _ := json.Marshal(patch)
	jsonStr := string(data)

	// Should not contain empty fields
	if containsString(jsonStr, "publicKeyIds") {
		t.Error("empty publicKeyIds should be omitted")
	}
	if containsString(jsonStr, "services") {
		t.Error("empty services should be omitted")
	}
	if containsString(jsonStr, "serviceIds") {
		t.Error("empty serviceIds should be omitted")
	}
}

func containsString(haystack, needle string) bool {
	return len(haystack) > len(needle) &&
		(haystack[0:len(needle)] == needle || containsString(haystack[1:], needle))
}

