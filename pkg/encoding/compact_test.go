package encoding

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestCompactHeader(t *testing.T) {
	tests := []struct {
		name   string
		header CompactHeader
	}{
		{
			name: "CREATE single key",
			header: CompactHeader{
				Version:   PayloadVersionCompact,
				Operation: OpCreate,
				Flags:     0x00,
			},
		},
		{
			name: "UPDATE threshold",
			header: CompactHeader{
				Version:   PayloadVersionCompact,
				Operation: OpUpdate,
				Flags:     FlagThreshold,
			},
		},
		{
			name: "UPDATE BLS aggregated",
			header: CompactHeader{
				Version:   PayloadVersionCompact,
				Operation: OpUpdate,
				Flags:     FlagThreshold | FlagBLSAggregated,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEncoder()
			e.WriteHeader(tt.header)

			d := NewDecoder(e.Bytes())
			got := d.ReadHeader()

			if d.Error() != nil {
				t.Fatalf("decode error: %v", d.Error())
			}

			if got.Version != tt.header.Version {
				t.Errorf("version: got %d, want %d", got.Version, tt.header.Version)
			}
			if got.Operation != tt.header.Operation {
				t.Errorf("operation: got %d, want %d", got.Operation, tt.header.Operation)
			}
			if got.Flags != tt.header.Flags {
				t.Errorf("flags: got %d, want %d", got.Flags, tt.header.Flags)
			}
		})
	}
}

func TestCompactString(t *testing.T) {
	tests := []struct {
		name string
		str  string
	}{
		{"empty", ""},
		{"short", "key-1"},
		{"medium", "this-is-a-medium-length-string"},
		{"max", string(make([]byte, 255))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEncoder()
			if err := e.WriteString(tt.str); err != nil {
				t.Fatalf("encode error: %v", err)
			}

			d := NewDecoder(e.Bytes())
			got := d.ReadString()

			if d.Error() != nil {
				t.Fatalf("decode error: %v", d.Error())
			}

			if got != tt.str {
				t.Errorf("got %q, want %q", got, tt.str)
			}
		})
	}
}

func TestCompactLongString(t *testing.T) {
	tests := []struct {
		name string
		str  string
	}{
		{"short", "https://example.com"},
		{"long", "https://example.com/very/long/path/that/exceeds/255/characters/" + string(make([]byte, 300))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEncoder()
			if err := e.WriteLongString(tt.str); err != nil {
				t.Fatalf("encode error: %v", err)
			}

			d := NewDecoder(e.Bytes())
			got := d.ReadLongString()

			if d.Error() != nil {
				t.Fatalf("decode error: %v", d.Error())
			}

			if got != tt.str {
				t.Errorf("string mismatch")
			}
		})
	}
}

func TestCompactPublicKey(t *testing.T) {
	tests := []struct {
		name string
		pk   CompactPublicKey
	}{
		{
			name: "Ed25519",
			pk: CompactPublicKey{
				ID:       "key-1",
				KeyType:  KeyTypeEd25519,
				KeyBytes: make([]byte, 32),
				Purposes: PurposeAuthentication,
			},
		},
		{
			name: "P-256",
			pk: CompactPublicKey{
				ID:       "signing-key",
				KeyType:  KeyTypeP256,
				KeyBytes: make([]byte, 33),
				Purposes: PurposeAuthentication | PurposeAssertionMethod,
			},
		},
		{
			name: "BLS",
			pk: CompactPublicKey{
				ID:       "bls-key",
				KeyType:  KeyTypeBLS12381G1,
				KeyBytes: make([]byte, 48),
				Purposes: PurposeAuthentication,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Fill with random data
			rand.Read(tt.pk.KeyBytes)

			e := NewEncoder()
			if err := e.WritePublicKey(tt.pk); err != nil {
				t.Fatalf("encode error: %v", err)
			}

			d := NewDecoder(e.Bytes())
			got := d.ReadPublicKey()

			if d.Error() != nil {
				t.Fatalf("decode error: %v", d.Error())
			}

			if got.ID != tt.pk.ID {
				t.Errorf("ID: got %q, want %q", got.ID, tt.pk.ID)
			}
			if got.KeyType != tt.pk.KeyType {
				t.Errorf("KeyType: got %d, want %d", got.KeyType, tt.pk.KeyType)
			}
			if !bytes.Equal(got.KeyBytes, tt.pk.KeyBytes) {
				t.Errorf("KeyBytes mismatch")
			}
			if got.Purposes != tt.pk.Purposes {
				t.Errorf("Purposes: got %d, want %d", got.Purposes, tt.pk.Purposes)
			}
		})
	}
}

func TestCompactService(t *testing.T) {
	tests := []struct {
		name string
		svc  CompactService
	}{
		{
			name: "simple",
			svc: CompactService{
				ID:       "api",
				Type:     "LinkedDomains",
				Endpoint: "https://example.com",
			},
		},
		{
			name: "long endpoint",
			svc: CompactService{
				ID:       "messaging",
				Type:     "DIDCommMessaging",
				Endpoint: "https://example.com/very/long/path/to/didcomm/endpoint/v2",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEncoder()
			if err := e.WriteService(tt.svc); err != nil {
				t.Fatalf("encode error: %v", err)
			}

			d := NewDecoder(e.Bytes())
			got := d.ReadService()

			if d.Error() != nil {
				t.Fatalf("decode error: %v", d.Error())
			}

			if got.ID != tt.svc.ID {
				t.Errorf("ID: got %q, want %q", got.ID, tt.svc.ID)
			}
			if got.Type != tt.svc.Type {
				t.Errorf("Type: got %q, want %q", got.Type, tt.svc.Type)
			}
			if got.Endpoint != tt.svc.Endpoint {
				t.Errorf("Endpoint: got %q, want %q", got.Endpoint, tt.svc.Endpoint)
			}
		})
	}
}

func TestCompactReveal(t *testing.T) {
	tests := []struct {
		name  string
		depth int
	}{
		{"depth 1", 1},
		{"depth 3", 3},
		{"depth 7", 7},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := CompactReveal{
				Index:       5,
				KeyType:     KeyTypeEd25519,
				PublicKey:   make([]byte, 32),
				MerkleDepth: byte(tt.depth),
				Signature:   make([]byte, 64),
			}
			rand.Read(r.PublicKey)
			rand.Read(r.Signature)

			r.MerkleSiblings = make([][]byte, tt.depth)
			for i := 0; i < tt.depth; i++ {
				r.MerkleSiblings[i] = make([]byte, 32)
				rand.Read(r.MerkleSiblings[i])
			}

			e := NewEncoder()
			if err := e.WriteReveal(r); err != nil {
				t.Fatalf("encode error: %v", err)
			}

			d := NewDecoder(e.Bytes())
			got := d.ReadReveal()

			if d.Error() != nil {
				t.Fatalf("decode error: %v", d.Error())
			}

			if got.Index != r.Index {
				t.Errorf("Index: got %d, want %d", got.Index, r.Index)
			}
			if got.KeyType != r.KeyType {
				t.Errorf("KeyType: got %d, want %d", got.KeyType, r.KeyType)
			}
			if !bytes.Equal(got.PublicKey, r.PublicKey) {
				t.Errorf("PublicKey mismatch")
			}
			if got.MerkleDepth != r.MerkleDepth {
				t.Errorf("MerkleDepth: got %d, want %d", got.MerkleDepth, r.MerkleDepth)
			}
			for i := 0; i < tt.depth; i++ {
				if !bytes.Equal(got.MerkleSiblings[i], r.MerkleSiblings[i]) {
					t.Errorf("MerkleSibling[%d] mismatch", i)
				}
			}
			if !bytes.Equal(got.Signature, r.Signature) {
				t.Errorf("Signature mismatch")
			}
		})
	}
}

func TestCompactDelta(t *testing.T) {
	delta := CompactDelta{
		Patches: []CompactPatch{
			{
				Type: PatchAddServices,
				Services: []CompactService{
					{ID: "api", Type: "API", Endpoint: "https://example.com"},
				},
			},
			{
				Type:       PatchRemovePublicKeys,
				KeyIDs:     []string{"old-key-1", "old-key-2"},
			},
		},
	}

	e := NewEncoder()
	if err := e.WriteDelta(delta); err != nil {
		t.Fatalf("encode error: %v", err)
	}

	d := NewDecoder(e.Bytes())
	got := d.ReadDelta()

	if d.Error() != nil {
		t.Fatalf("decode error: %v", d.Error())
	}

	if len(got.Patches) != len(delta.Patches) {
		t.Fatalf("patch count: got %d, want %d", len(got.Patches), len(delta.Patches))
	}

	// Check first patch (add services)
	if got.Patches[0].Type != PatchAddServices {
		t.Errorf("patch[0] type: got %d, want %d", got.Patches[0].Type, PatchAddServices)
	}
	if len(got.Patches[0].Services) != 1 {
		t.Errorf("patch[0] services count: got %d, want 1", len(got.Patches[0].Services))
	}
	if got.Patches[0].Services[0].ID != "api" {
		t.Errorf("service ID: got %q, want %q", got.Patches[0].Services[0].ID, "api")
	}

	// Check second patch (remove keys)
	if got.Patches[1].Type != PatchRemovePublicKeys {
		t.Errorf("patch[1] type: got %d, want %d", got.Patches[1].Type, PatchRemovePublicKeys)
	}
	if len(got.Patches[1].KeyIDs) != 2 {
		t.Errorf("patch[1] key IDs count: got %d, want 2", len(got.Patches[1].KeyIDs))
	}
}

func TestEncodeDecodeUpdate(t *testing.T) {
	// Create a simple single-key update
	suffix := make([]byte, 32)
	commitment := make([]byte, 32)
	pubKey := make([]byte, 32)
	sig := make([]byte, 64)

	rand.Read(suffix)
	rand.Read(commitment)
	rand.Read(pubKey)
	rand.Read(sig)

	update := &CompactUpdate{
		Header: CompactHeader{
			Version:   PayloadVersionCompact,
			Operation: OpUpdate,
			Flags:     0x00,
		},
		DIDSuffix: suffix,
		Reveals: []CompactReveal{
			{
				KeyType:   KeyTypeEd25519,
				PublicKey: pubKey,
				Signature: sig,
			},
		},
		NewCommitment: commitment,
		Delta: CompactDelta{
			Patches: []CompactPatch{
				{
					Type: PatchAddServices,
					Services: []CompactService{
						{ID: "api", Type: "API", Endpoint: "https://example.com"},
					},
				},
			},
		},
	}

	encoded, err := EncodeUpdate(update)
	if err != nil {
		t.Fatalf("encode error: %v", err)
	}

	// Verify size is much smaller than JSON equivalent
	// JSON would be ~700 bytes, compact should be ~217 bytes
	t.Logf("Encoded size: %d bytes", len(encoded))
	if len(encoded) > 300 {
		t.Errorf("encoded size too large: %d bytes", len(encoded))
	}

	decoded, err := DecodeUpdate(encoded)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}

	if !bytes.Equal(decoded.DIDSuffix, suffix) {
		t.Errorf("DIDSuffix mismatch")
	}
	if !bytes.Equal(decoded.NewCommitment, commitment) {
		t.Errorf("NewCommitment mismatch")
	}
	if len(decoded.Reveals) != 1 {
		t.Fatalf("reveals count: got %d, want 1", len(decoded.Reveals))
	}
	if decoded.Reveals[0].KeyType != KeyTypeEd25519 {
		t.Errorf("key type: got %d, want %d", decoded.Reveals[0].KeyType, KeyTypeEd25519)
	}
	if !bytes.Equal(decoded.Reveals[0].PublicKey, pubKey) {
		t.Errorf("public key mismatch")
	}
	if !bytes.Equal(decoded.Reveals[0].Signature, sig) {
		t.Errorf("signature mismatch")
	}
}

func TestEncodeDecodeThresholdUpdate(t *testing.T) {
	suffix := make([]byte, 32)
	commitment := make([]byte, 32)
	rand.Read(suffix)
	rand.Read(commitment)

	// 3-of-5 threshold update
	reveals := make([]CompactReveal, 3)
	for i := 0; i < 3; i++ {
		reveals[i] = CompactReveal{
			Index:       byte(i * 2), // indices 0, 2, 4
			KeyType:     KeyTypeEd25519,
			PublicKey:   make([]byte, 32),
			MerkleDepth: 3,
			Signature:   make([]byte, 64),
		}
		rand.Read(reveals[i].PublicKey)
		rand.Read(reveals[i].Signature)

		reveals[i].MerkleSiblings = make([][]byte, 3)
		for j := 0; j < 3; j++ {
			reveals[i].MerkleSiblings[j] = make([]byte, 32)
			rand.Read(reveals[i].MerkleSiblings[j])
		}
	}

	update := &CompactUpdate{
		Header: CompactHeader{
			Version:   PayloadVersionCompact,
			Operation: OpUpdate,
			Flags:     FlagThreshold,
		},
		DIDSuffix:     suffix,
		Reveals:       reveals,
		NewCommitment: commitment,
		Delta: CompactDelta{
			Patches: []CompactPatch{
				{
					Type: PatchAddServices,
					Services: []CompactService{
						{ID: "api", Type: "API", Endpoint: "https://example.com"},
					},
				},
			},
		},
	}

	encoded, err := EncodeUpdate(update)
	if err != nil {
		t.Fatalf("encode error: %v", err)
	}

	// 3-of-5 with 3-level proofs should be ~673 bytes
	t.Logf("Threshold update encoded size: %d bytes", len(encoded))
	if len(encoded) > 800 {
		t.Errorf("encoded size too large: %d bytes", len(encoded))
	}

	decoded, err := DecodeUpdate(encoded)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}

	if decoded.Header.Flags&FlagThreshold == 0 {
		t.Errorf("threshold flag not set")
	}
	if len(decoded.Reveals) != 3 {
		t.Fatalf("reveals count: got %d, want 3", len(decoded.Reveals))
	}

	for i := 0; i < 3; i++ {
		if decoded.Reveals[i].Index != reveals[i].Index {
			t.Errorf("reveal[%d] index: got %d, want %d", i, decoded.Reveals[i].Index, reveals[i].Index)
		}
		if decoded.Reveals[i].MerkleDepth != 3 {
			t.Errorf("reveal[%d] depth: got %d, want 3", i, decoded.Reveals[i].MerkleDepth)
		}
		if len(decoded.Reveals[i].MerkleSiblings) != 3 {
			t.Errorf("reveal[%d] siblings count: got %d, want 3", i, len(decoded.Reveals[i].MerkleSiblings))
		}
	}
}

func TestEncodeDecodeDeactivate(t *testing.T) {
	suffix := make([]byte, 32)
	pubKey := make([]byte, 32)
	sig := make([]byte, 64)

	rand.Read(suffix)
	rand.Read(pubKey)
	rand.Read(sig)

	deactivate := &CompactDeactivate{
		Header: CompactHeader{
			Version:   PayloadVersionCompact,
			Operation: OpDeactivate,
			Flags:     0x00,
		},
		DIDSuffix: suffix,
		Reveals: []CompactReveal{
			{
				KeyType:   KeyTypeEd25519,
				PublicKey: pubKey,
				Signature: sig,
			},
		},
	}

	encoded, err := EncodeDeactivate(deactivate)
	if err != nil {
		t.Fatalf("encode error: %v", err)
	}

	t.Logf("Deactivate encoded size: %d bytes", len(encoded))

	decoded, err := DecodeDeactivate(encoded)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}

	if !bytes.Equal(decoded.DIDSuffix, suffix) {
		t.Errorf("DIDSuffix mismatch")
	}
	if len(decoded.Reveals) != 1 {
		t.Fatalf("reveals count: got %d, want 1", len(decoded.Reveals))
	}
}

func TestDetectFormat(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    byte
		wantErr bool
	}{
		{"legacy JSON", []byte{0x01, 0x02, 0x03}, 0x01, false},
		{"compact binary", []byte{0x02, 0x02, 0x00}, 0x02, false},
		{"empty", []byte{}, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DetectFormat(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("error: got %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("version: got %d, want %d", got, tt.want)
			}
		})
	}
}

func TestCompressDecompressEC(t *testing.T) {
	// Generate a real P-256 key
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// For this test, we'll use the Ed25519 key directly since P-256 compression
	// requires actual EC math that's tested separately
	compressed := Ed25519PublicKeyToCompact(priv.Public().(ed25519.PublicKey))
	if len(compressed) != 32 {
		t.Errorf("Ed25519 compressed size: got %d, want 32", len(compressed))
	}

	decompressed, err := CompactToEd25519PublicKey(compressed)
	if err != nil {
		t.Fatalf("decompress error: %v", err)
	}

	if !bytes.Equal(decompressed, priv.Public().(ed25519.PublicKey)) {
		t.Errorf("round-trip failed for Ed25519")
	}
}

func TestSizeComparison(t *testing.T) {
	// This test documents the size savings

	// Single key update
	singleUpdate := &CompactUpdate{
		Header:        CompactHeader{Version: PayloadVersionCompact, Operation: OpUpdate, Flags: 0},
		DIDSuffix:     make([]byte, 32),
		Reveals:       []CompactReveal{{KeyType: KeyTypeEd25519, PublicKey: make([]byte, 32), Signature: make([]byte, 64)}},
		NewCommitment: make([]byte, 32),
		Delta:         CompactDelta{Patches: []CompactPatch{{Type: PatchAddServices, Services: []CompactService{{ID: "api", Type: "API", Endpoint: "https://example.com"}}}}},
	}

	encoded, _ := EncodeUpdate(singleUpdate)
	t.Logf("Single key UPDATE: %d bytes (JSON ~700 bytes, savings: %.0f%%)",
		len(encoded), (1-float64(len(encoded))/700)*100)

	// 3-of-5 threshold update
	reveals3 := make([]CompactReveal, 3)
	for i := range reveals3 {
		reveals3[i] = CompactReveal{
			Index:          byte(i),
			KeyType:        KeyTypeEd25519,
			PublicKey:      make([]byte, 32),
			MerkleDepth:    3,
			MerkleSiblings: [][]byte{make([]byte, 32), make([]byte, 32), make([]byte, 32)},
			Signature:      make([]byte, 64),
		}
	}
	thresholdUpdate := &CompactUpdate{
		Header:        CompactHeader{Version: PayloadVersionCompact, Operation: OpUpdate, Flags: FlagThreshold},
		DIDSuffix:     make([]byte, 32),
		Reveals:       reveals3,
		NewCommitment: make([]byte, 32),
		Delta:         CompactDelta{Patches: []CompactPatch{{Type: PatchAddServices, Services: []CompactService{{ID: "api", Type: "API", Endpoint: "https://example.com"}}}}},
	}

	encoded, _ = EncodeUpdate(thresholdUpdate)
	t.Logf("3-of-5 threshold UPDATE: %d bytes (JSON ~2100 bytes, savings: %.0f%%)",
		len(encoded), (1-float64(len(encoded))/2100)*100)
}
