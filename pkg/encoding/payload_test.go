package encoding

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		opType    OperationType
		didSuffix string
		opData    interface{}
	}{
		{
			name:      "create operation",
			opType:    OperationTypeCreate,
			didSuffix: "EiDtest123suffix",
			opData:    map[string]interface{}{"type": "create", "data": "test"},
		},
		{
			name:      "update operation",
			opType:    OperationTypeUpdate,
			didSuffix: "abc123",
			opData:    map[string]interface{}{"type": "update", "patches": []string{"p1", "p2"}},
		},
		{
			name:      "recover operation",
			opType:    OperationTypeRecover,
			didSuffix: "xyz789",
			opData:    map[string]interface{}{"type": "recover"},
		},
		{
			name:      "deactivate operation",
			opType:    OperationTypeDeactivate,
			didSuffix: "deactivate_suffix",
			opData:    map[string]interface{}{"type": "deactivate", "did": "test"},
		},
		{
			name:      "empty suffix",
			opType:    OperationTypeCreate,
			didSuffix: "",
			opData:    map[string]interface{}{},
		},
		{
			name:      "long suffix",
			opType:    OperationTypeCreate,
			didSuffix: strings.Repeat("a", 1000),
			opData:    map[string]interface{}{"test": true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode
			encoded, err := EncodePayload(tt.opType, tt.didSuffix, tt.opData)
			if err != nil {
				t.Fatalf("EncodePayload failed: %v", err)
			}

			// Verify it's valid hex
			if _, err := hex.DecodeString(encoded); err != nil {
				t.Fatalf("encoded payload is not valid hex: %v", err)
			}

			// Decode
			version, opType, didSuffix, opJSON, err := DecodePayload(encoded)
			if err != nil {
				t.Fatalf("DecodePayload failed: %v", err)
			}

			// Verify version
			if version != PayloadVersion {
				t.Errorf("version = %d, want %d", version, PayloadVersion)
			}

			// Verify operation type
			if opType != tt.opType {
				t.Errorf("opType = %d, want %d", opType, tt.opType)
			}

			// Verify suffix
			if didSuffix != tt.didSuffix {
				t.Errorf("didSuffix = %q, want %q", didSuffix, tt.didSuffix)
			}

			// Verify JSON can be unmarshaled
			var decoded map[string]interface{}
			if err := json.Unmarshal(opJSON, &decoded); err != nil {
				t.Errorf("failed to unmarshal operation JSON: %v", err)
			}
		})
	}
}

func TestDecodePayloadErrors(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{
			name:    "invalid hex",
			input:   "not-hex!",
			wantErr: "invalid hex",
		},
		{
			name:    "empty payload",
			input:   "",
			wantErr: "failed to read version",
		},
		{
			name:    "only version",
			input:   "01",
			wantErr: "failed to read operation type",
		},
		{
			name:    "no suffix length",
			input:   "0101",
			wantErr: "failed to read suffix length",
		},
		{
			name:    "truncated suffix",
			input:   "010105", // version=1, opType=1, suffixLen=5, but no suffix data
			wantErr: "failed to read suffix",
		},
		{
			name:    "no json length",
			input:   "0101036162630a7b7d", // version=1, opType=1, suffixLen=3, suffix="abc", jsonLen=10 (too long), json="{}"
			wantErr: "failed to read JSON",
		},
		{
			name:    "truncated json",
			input:   "0101036162630a", // suffix="abc", jsonLen=10, but no JSON data
			wantErr: "failed to read JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, _, err := DecodePayload(tt.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want to contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestOperationTypes(t *testing.T) {
	// Verify operation type constants
	if OperationTypeCreate != 0x01 {
		t.Errorf("OperationTypeCreate = %d, want 1", OperationTypeCreate)
	}
	if OperationTypeUpdate != 0x02 {
		t.Errorf("OperationTypeUpdate = %d, want 2", OperationTypeUpdate)
	}
	if OperationTypeRecover != 0x03 {
		t.Errorf("OperationTypeRecover = %d, want 3", OperationTypeRecover)
	}
	if OperationTypeDeactivate != 0x04 {
		t.Errorf("OperationTypeDeactivate = %d, want 4", OperationTypeDeactivate)
	}
}

func TestPayloadVersion(t *testing.T) {
	if PayloadVersion != 0x01 {
		t.Errorf("PayloadVersion = %d, want 1", PayloadVersion)
	}
}

func TestVarintEdgeCases(t *testing.T) {
	// Test varint encoding at boundary values
	// Varint uses 7 bits per byte, so boundaries are at 2^7, 2^14, 2^21, etc.
	tests := []struct {
		name      string
		suffixLen int
	}{
		{name: "zero", suffixLen: 0},
		{name: "one", suffixLen: 1},
		{name: "127 (max 1-byte)", suffixLen: 127},
		{name: "128 (min 2-byte)", suffixLen: 128},
		{name: "16383 (max 2-byte)", suffixLen: 16383},
		{name: "16384 (min 3-byte)", suffixLen: 16384},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suffix := strings.Repeat("x", tt.suffixLen)
			opData := map[string]interface{}{"test": true}

			encoded, err := EncodePayload(OperationTypeCreate, suffix, opData)
			if err != nil {
				t.Fatalf("EncodePayload failed: %v", err)
			}

			_, _, decodedSuffix, _, err := DecodePayload(encoded)
			if err != nil {
				t.Fatalf("DecodePayload failed: %v", err)
			}

			if len(decodedSuffix) != tt.suffixLen {
				t.Errorf("decoded suffix length = %d, want %d", len(decodedSuffix), tt.suffixLen)
			}
		})
	}
}

func TestLargePayload(t *testing.T) {
	// Test with large operation data
	largeData := make(map[string]interface{})
	for i := 0; i < 100; i++ {
		largeData[strings.Repeat("key", 10)] = strings.Repeat("value", 100)
	}

	encoded, err := EncodePayload(OperationTypeUpdate, "test-suffix", largeData)
	if err != nil {
		t.Fatalf("EncodePayload failed: %v", err)
	}

	version, opType, suffix, opJSON, err := DecodePayload(encoded)
	if err != nil {
		t.Fatalf("DecodePayload failed: %v", err)
	}

	if version != PayloadVersion {
		t.Errorf("version mismatch")
	}
	if opType != OperationTypeUpdate {
		t.Errorf("opType mismatch")
	}
	if suffix != "test-suffix" {
		t.Errorf("suffix mismatch")
	}
	if len(opJSON) == 0 {
		t.Error("opJSON is empty")
	}
}

func TestEncodePayloadMarshalError(t *testing.T) {
	// Test with unmarshallable data (channels can't be marshaled)
	ch := make(chan int)
	_, err := EncodePayload(OperationTypeCreate, "test", ch)
	if err == nil {
		t.Error("expected error for unmarshallable data")
	}
	if !strings.Contains(err.Error(), "failed to marshal") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPayloadBinaryFormat(t *testing.T) {
	// Test the exact binary format
	encoded, err := EncodePayload(OperationTypeCreate, "abc", map[string]string{"k": "v"})
	if err != nil {
		t.Fatalf("EncodePayload failed: %v", err)
	}

	data, _ := hex.DecodeString(encoded)

	// Check version byte
	if data[0] != 0x01 {
		t.Errorf("version byte = %x, want 01", data[0])
	}

	// Check operation type byte
	if data[1] != 0x01 {
		t.Errorf("opType byte = %x, want 01", data[1])
	}

	// Check suffix length varint (3 for "abc")
	if data[2] != 0x03 {
		t.Errorf("suffix length = %x, want 03", data[2])
	}

	// Check suffix bytes
	if string(data[3:6]) != "abc" {
		t.Errorf("suffix = %q, want \"abc\"", string(data[3:6]))
	}
}

func TestDecodePayloadWithDifferentVersions(t *testing.T) {
	// Manually create a payload with a different version
	// [version=0x02][opType=0x01][suffixLen=0x01][suffix="x"][jsonLen=0x02][json="{}"]
	payload := "02010178027b7d"

	version, opType, suffix, opJSON, err := DecodePayload(payload)
	if err != nil {
		t.Fatalf("DecodePayload failed: %v", err)
	}

	// Should still decode, but version will be different
	if version != 0x02 {
		t.Errorf("version = %d, want 2", version)
	}
	if opType != OperationTypeCreate {
		t.Errorf("opType = %d, want 1", opType)
	}
	if suffix != "x" {
		t.Errorf("suffix = %q, want \"x\"", suffix)
	}
	if string(opJSON) != "{}" {
		t.Errorf("opJSON = %q, want \"{}\"", string(opJSON))
	}
}

func TestEncodePayloadDeterminism(t *testing.T) {
	opData := map[string]interface{}{
		"type":   "create",
		"suffix": "test123",
	}

	// Note: Go's json.Marshal is deterministic for the same input structure,
	// but map iteration order isn't guaranteed. For this test, we use the same
	// map instance repeatedly.
	encoded1, _ := EncodePayload(OperationTypeCreate, "suffix", opData)
	encoded2, _ := EncodePayload(OperationTypeCreate, "suffix", opData)

	if encoded1 != encoded2 {
		t.Error("EncodePayload is not deterministic")
	}
}
