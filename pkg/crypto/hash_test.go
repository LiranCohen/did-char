package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestSHA256(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string // hex encoded
	}{
		{
			name:     "empty input",
			input:    []byte{},
			expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:     "hello world",
			input:    []byte("hello world"),
			expected: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
		},
		{
			name:     "single byte",
			input:    []byte{0x00},
			expected: "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
		},
		{
			name:     "JSON-like data",
			input:    []byte(`{"kty":"EC","crv":"P-256","x":"test","y":"test"}`),
			expected: "", // computed dynamically
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SHA256(tt.input)

			// For known test vectors
			if tt.expected != "" {
				expectedBytes, _ := hex.DecodeString(tt.expected)
				if !bytes.Equal(result, expectedBytes) {
					t.Errorf("SHA256(%q) = %x, want %s", tt.input, result, tt.expected)
				}
			}

			// Verify length is always 32 bytes
			if len(result) != 32 {
				t.Errorf("SHA256 output length = %d, want 32", len(result))
			}

			// Verify determinism
			result2 := SHA256(tt.input)
			if !bytes.Equal(result, result2) {
				t.Error("SHA256 is not deterministic")
			}
		})
	}
}

func TestSHA256MatchesStdLib(t *testing.T) {
	inputs := [][]byte{
		[]byte("test"),
		[]byte("another test"),
		[]byte{0x01, 0x02, 0x03},
		make([]byte, 1000), // large input
	}

	for _, input := range inputs {
		got := SHA256(input)
		want := sha256.Sum256(input)

		if !bytes.Equal(got, want[:]) {
			t.Errorf("SHA256(%x) doesn't match stdlib", input)
		}
	}
}

func TestBase64URLEncode(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "empty",
			input:    []byte{},
			expected: "",
		},
		{
			name:     "single byte",
			input:    []byte{0x00},
			expected: "AA",
		},
		{
			name:     "two bytes",
			input:    []byte{0x00, 0x01},
			expected: "AAE",
		},
		{
			name:     "three bytes",
			input:    []byte{0x00, 0x01, 0x02},
			expected: "AAEC",
		},
		{
			name:     "URL-safe characters needed",
			input:    []byte{0xfb, 0xff}, // would be +/ in standard base64
			expected: "-_8",
		},
		{
			name:     "hello",
			input:    []byte("hello"),
			expected: "aGVsbG8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Base64URLEncode(tt.input)
			if result != tt.expected {
				t.Errorf("Base64URLEncode(%x) = %q, want %q", tt.input, result, tt.expected)
			}

			// Verify no padding
			if len(result) > 0 && result[len(result)-1] == '=' {
				t.Error("Base64URLEncode should not include padding")
			}
		})
	}
}

func TestBase64URLDecode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []byte
		wantErr  bool
	}{
		{
			name:     "empty",
			input:    "",
			expected: []byte{},
		},
		{
			name:     "single byte",
			input:    "AA",
			expected: []byte{0x00},
		},
		{
			name:     "two bytes no padding",
			input:    "AAE",
			expected: []byte{0x00, 0x01},
		},
		{
			name:     "three bytes",
			input:    "AAEC",
			expected: []byte{0x00, 0x01, 0x02},
		},
		{
			name:     "with padding",
			input:    "AAE=",
			expected: []byte{0x00, 0x01},
		},
		{
			name:     "URL-safe characters",
			input:    "-_8",
			expected: []byte{0xfb, 0xff},
		},
		{
			name:     "hello",
			input:    "aGVsbG8",
			expected: []byte("hello"),
		},
		{
			name:    "invalid characters",
			input:   "!!!",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Base64URLDecode(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if !bytes.Equal(result, tt.expected) {
				t.Errorf("Base64URLDecode(%q) = %x, want %x", tt.input, result, tt.expected)
			}
		})
	}
}

func TestBase64URLRoundTrip(t *testing.T) {
	inputs := [][]byte{
		{},
		{0x00},
		{0x00, 0x01},
		{0x00, 0x01, 0x02},
		{0x00, 0x01, 0x02, 0x03},
		[]byte("hello world"),
		[]byte(`{"key":"value"}`),
		make([]byte, 100),
		{0xff, 0xfe, 0xfd, 0xfc}, // high bytes
	}

	for i, input := range inputs {
		encoded := Base64URLEncode(input)
		decoded, err := Base64URLDecode(encoded)
		if err != nil {
			t.Errorf("case %d: decode error: %v", i, err)
			continue
		}
		if !bytes.Equal(input, decoded) {
			t.Errorf("case %d: round-trip failed: %x -> %q -> %x", i, input, encoded, decoded)
		}
	}
}

func TestHashToBase64URL(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{name: "empty", input: []byte{}},
		{name: "hello", input: []byte("hello")},
		{name: "json", input: []byte(`{"test":"data"}`)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HashToBase64URL(tt.input)

			// Should be base64url encoded SHA256 (32 bytes = 43 chars without padding)
			if len(result) != 43 {
				t.Errorf("HashToBase64URL output length = %d, want 43", len(result))
			}

			// Should not have padding
			if len(result) > 0 && result[len(result)-1] == '=' {
				t.Error("HashToBase64URL should not include padding")
			}

			// Should be decodable
			decoded, err := Base64URLDecode(result)
			if err != nil {
				t.Errorf("result not decodable: %v", err)
			}
			if len(decoded) != 32 {
				t.Errorf("decoded length = %d, want 32", len(decoded))
			}

			// Should equal manual SHA256 + encode
			expected := Base64URLEncode(SHA256(tt.input))
			if result != expected {
				t.Errorf("HashToBase64URL(%q) = %q, want %q", tt.input, result, expected)
			}

			// Should be deterministic
			result2 := HashToBase64URL(tt.input)
			if result != result2 {
				t.Error("HashToBase64URL is not deterministic")
			}
		})
	}
}

func TestHashToBase64URLDeterminism(t *testing.T) {
	// Same input should always produce same output
	input := []byte(`{"kty":"EC","crv":"P-256","x":"abc","y":"def"}`)

	results := make(map[string]bool)
	for i := 0; i < 100; i++ {
		result := HashToBase64URL(input)
		results[result] = true
	}

	if len(results) != 1 {
		t.Errorf("HashToBase64URL produced %d different outputs for same input", len(results))
	}
}
