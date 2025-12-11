package did

import (
	"strings"
	"testing"
)

func TestGenerateDIDSuffix(t *testing.T) {
	tests := []struct {
		name  string
		input interface{}
	}{
		{
			name:  "simple map",
			input: map[string]string{"key": "value"},
		},
		{
			name:  "empty map",
			input: map[string]interface{}{},
		},
		{
			name:  "nested structure",
			input: map[string]interface{}{"outer": map[string]string{"inner": "value"}},
		},
		{
			name: "create operation-like",
			input: map[string]interface{}{
				"type":               "create",
				"updateCommitment":   "abc123",
				"recoveryCommitment": "def456",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suffix, err := GenerateDIDSuffix(tt.input)
			if err != nil {
				t.Fatalf("GenerateDIDSuffix failed: %v", err)
			}

			// Suffix should be non-empty base64url string
			if suffix == "" {
				t.Error("suffix is empty")
			}

			// Should be 43 chars (SHA256 = 32 bytes = 43 base64url chars without padding)
			if len(suffix) != 43 {
				t.Errorf("suffix length = %d, want 43", len(suffix))
			}

			// Should not contain padding
			if strings.Contains(suffix, "=") {
				t.Error("suffix should not contain padding")
			}

			// Should be deterministic
			suffix2, _ := GenerateDIDSuffix(tt.input)
			if suffix != suffix2 {
				t.Error("GenerateDIDSuffix is not deterministic")
			}
		})
	}
}

func TestGenerateDIDSuffixDifferentInputs(t *testing.T) {
	// Different inputs should produce different suffixes
	input1 := map[string]string{"key": "value1"}
	input2 := map[string]string{"key": "value2"}

	suffix1, _ := GenerateDIDSuffix(input1)
	suffix2, _ := GenerateDIDSuffix(input2)

	if suffix1 == suffix2 {
		t.Error("different inputs should produce different suffixes")
	}
}

func TestGenerateDIDSuffixError(t *testing.T) {
	// Test with unmarshallable data
	ch := make(chan int)
	_, err := GenerateDIDSuffix(ch)
	if err == nil {
		t.Error("expected error for unmarshallable input")
	}
}

func TestFormatDID(t *testing.T) {
	tests := []struct {
		suffix   string
		expected string
	}{
		{
			suffix:   "abc123",
			expected: "did:char:abc123",
		},
		{
			suffix:   "EiDtest-suffix_123",
			expected: "did:char:EiDtest-suffix_123",
		},
		{
			suffix:   "x",
			expected: "did:char:x",
		},
		{
			suffix:   strings.Repeat("x", 43),
			expected: "did:char:" + strings.Repeat("x", 43),
		},
	}

	for _, tt := range tests {
		t.Run(tt.suffix, func(t *testing.T) {
			result := FormatDID(tt.suffix)
			if result != tt.expected {
				t.Errorf("FormatDID(%q) = %q, want %q", tt.suffix, result, tt.expected)
			}
		})
	}
}

func TestParseDID(t *testing.T) {
	tests := []struct {
		name       string
		did        string
		wantSuffix string
		wantErr    bool
	}{
		{
			name:       "valid DID",
			did:        "did:char:abc123",
			wantSuffix: "abc123",
		},
		{
			name:       "long suffix",
			did:        "did:char:EiD" + strings.Repeat("x", 40),
			wantSuffix: "EiD" + strings.Repeat("x", 40),
		},
		{
			name:    "empty suffix",
			did:     "did:char:",
			wantErr: true, // Implementation requires non-empty suffix
		},
		{
			name:       "suffix with special chars",
			did:        "did:char:abc-123_XYZ",
			wantSuffix: "abc-123_XYZ",
		},
		{
			name:    "wrong method",
			did:     "did:ion:abc123",
			wantErr: true,
		},
		{
			name:    "missing method",
			did:     "did:abc123",
			wantErr: true,
		},
		{
			name:    "not a DID",
			did:     "abc123",
			wantErr: true,
		},
		{
			name:    "empty string",
			did:     "",
			wantErr: true,
		},
		{
			name:    "too short",
			did:     "did:char",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suffix, err := ParseDID(tt.did)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if suffix != tt.wantSuffix {
				t.Errorf("ParseDID(%q) = %q, want %q", tt.did, suffix, tt.wantSuffix)
			}
		})
	}
}

func TestFormatParseDIDRoundTrip(t *testing.T) {
	suffixes := []string{
		"abc123",
		"EiDtest-suffix_123",
		strings.Repeat("x", 43),
		"a",
	}

	for _, suffix := range suffixes {
		did := FormatDID(suffix)
		parsedSuffix, err := ParseDID(did)
		if err != nil {
			t.Errorf("ParseDID(FormatDID(%q)) failed: %v", suffix, err)
			continue
		}
		if parsedSuffix != suffix {
			t.Errorf("round-trip failed: %q -> %q -> %q", suffix, did, parsedSuffix)
		}
	}
}

func TestGenerateFormatRoundTrip(t *testing.T) {
	// Generate a suffix, format as DID, parse back
	input := map[string]interface{}{
		"type":             "create",
		"updateCommitment": "test123",
	}

	suffix, err := GenerateDIDSuffix(input)
	if err != nil {
		t.Fatalf("GenerateDIDSuffix failed: %v", err)
	}

	did := FormatDID(suffix)
	parsedSuffix, err := ParseDID(did)
	if err != nil {
		t.Fatalf("ParseDID failed: %v", err)
	}

	if parsedSuffix != suffix {
		t.Errorf("round-trip failed: suffix=%q, parsed=%q", suffix, parsedSuffix)
	}
}
