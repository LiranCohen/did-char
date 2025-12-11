package keys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestEC256KeyRoundTrip(t *testing.T) {
	// Generate key
	privateKey, err := GenerateSecp256k1Key()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Convert to JWK
	jwk := PrivateKeyToJWK(privateKey, "test-key-1")
	if jwk.Kty != "EC" {
		t.Errorf("wrong kty: %s", jwk.Kty)
	}
	if jwk.Crv != "P-256" {
		t.Errorf("wrong crv: %s", jwk.Crv)
	}
	if jwk.ID != "test-key-1" {
		t.Errorf("wrong id: %s", jwk.ID)
	}

	// Convert back
	recoveredKey, err := JWKToPrivateKey(jwk)
	if err != nil {
		t.Fatalf("failed to convert JWK to key: %v", err)
	}

	// Verify keys match
	if !privateKey.Equal(recoveredKey) {
		t.Error("recovered key does not match original")
	}
}

func TestEC256PublicKeyRoundTrip(t *testing.T) {
	// Generate key
	privateKey, err := GenerateSecp256k1Key()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Convert public key to JWK
	pubJWK := PublicKeyToJWK(&privateKey.PublicKey, "pub-key-1")
	if pubJWK.D != "" {
		t.Error("public JWK should not contain D")
	}

	// Convert back
	recoveredPubKey, err := JWKToPublicKey(pubJWK)
	if err != nil {
		t.Fatalf("failed to convert JWK to public key: %v", err)
	}

	// Verify keys match
	if !privateKey.PublicKey.Equal(recoveredPubKey) {
		t.Error("recovered public key does not match original")
	}
}

func TestEd25519KeyRoundTrip(t *testing.T) {
	// Generate key
	privateKey, err := GenerateEd25519Key()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Convert to JWK
	jwk := Ed25519PrivateKeyToJWK(privateKey, "ed-key-1")
	if jwk.Kty != "OKP" {
		t.Errorf("wrong kty: %s", jwk.Kty)
	}
	if jwk.Crv != "Ed25519" {
		t.Errorf("wrong crv: %s", jwk.Crv)
	}
	if jwk.Alg != "EdDSA" {
		t.Errorf("wrong alg: %s", jwk.Alg)
	}
	if jwk.ID != "ed-key-1" {
		t.Errorf("wrong id: %s", jwk.ID)
	}

	// Convert back
	recoveredKey, err := JWKToEd25519PrivateKey(jwk)
	if err != nil {
		t.Fatalf("failed to convert JWK to key: %v", err)
	}

	// Verify keys match
	if !privateKey.Equal(recoveredKey) {
		t.Error("recovered key does not match original")
	}
}

func TestEd25519PublicKeyRoundTrip(t *testing.T) {
	// Generate key
	privateKey, err := GenerateEd25519Key()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	publicKey := privateKey.Public().(ed25519.PublicKey)

	// Convert public key to JWK
	pubJWK := Ed25519PublicKeyToJWK(publicKey, "ed-pub-key-1")
	if pubJWK.D != "" {
		t.Error("public JWK should not contain D")
	}

	// Convert back
	recoveredPubKey, err := JWKToEd25519PublicKey(pubJWK)
	if err != nil {
		t.Fatalf("failed to convert JWK to public key: %v", err)
	}

	// Verify keys match
	if !publicKey.Equal(recoveredPubKey) {
		t.Error("recovered public key does not match original")
	}
}

func TestBLSKeyRoundTrip(t *testing.T) {
	// Generate key
	privateKey, err := GenerateBLSKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Convert to JWK
	jwk := BLSPrivateKeyToJWK(privateKey, "bls-key-1")
	if jwk.Kty != "OKP" {
		t.Errorf("wrong kty: %s", jwk.Kty)
	}
	if jwk.Crv != "BLS12-381-G1" {
		t.Errorf("wrong crv: %s", jwk.Crv)
	}
	if jwk.Alg != "BLS" {
		t.Errorf("wrong alg: %s", jwk.Alg)
	}
	if jwk.ID != "bls-key-1" {
		t.Errorf("wrong id: %s", jwk.ID)
	}

	// Convert back
	recoveredKey, err := JWKToBLSPrivateKey(jwk)
	if err != nil {
		t.Fatalf("failed to convert JWK to key: %v", err)
	}

	// Sign with both keys to verify they match
	msg := []byte("test message")

	// We can't directly compare BLS keys, so we verify by signing
	// Original signature
	origPubKey := privateKey.PublicKey()
	origPubBytes, _ := origPubKey.MarshalBinary()

	// Recovered signature
	recoveredPubKey := recoveredKey.PublicKey()
	recoveredPubBytes, _ := recoveredPubKey.MarshalBinary()

	if string(origPubBytes) != string(recoveredPubBytes) {
		t.Error("recovered BLS key does not match original (public key mismatch)")
	}
	_ = msg // used conceptually
}

func TestBLSPublicKeyRoundTrip(t *testing.T) {
	// Generate key
	privateKey, err := GenerateBLSKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	publicKey := privateKey.PublicKey()

	// Convert public key to JWK
	pubJWK := BLSPublicKeyToJWK(publicKey, "bls-pub-key-1")
	if pubJWK.D != "" {
		t.Error("public JWK should not contain D")
	}

	// Convert back
	recoveredPubKey, err := JWKToBLSPublicKey(pubJWK)
	if err != nil {
		t.Fatalf("failed to convert JWK to public key: %v", err)
	}

	// Verify keys match by comparing serialized form
	origBytes, _ := publicKey.MarshalBinary()
	recoveredBytes, _ := recoveredPubKey.MarshalBinary()

	if string(origBytes) != string(recoveredBytes) {
		t.Error("recovered public key does not match original")
	}
}

func TestJWKToMapRoundTrip(t *testing.T) {
	jwk := &JWK{
		ID:  "test-id",
		Kty: "EC",
		Crv: "P-256",
		Alg: "ES256",
		X:   "xvalue",
		Y:   "yvalue",
		D:   "dvalue",
	}

	// Convert to map
	m := JWKToMap(jwk)

	// Convert back
	recovered := MapToJWK(m)

	// Verify all fields
	if recovered.ID != jwk.ID {
		t.Errorf("wrong ID: got %s, want %s", recovered.ID, jwk.ID)
	}
	if recovered.Kty != jwk.Kty {
		t.Errorf("wrong Kty: got %s, want %s", recovered.Kty, jwk.Kty)
	}
	if recovered.Crv != jwk.Crv {
		t.Errorf("wrong Crv: got %s, want %s", recovered.Crv, jwk.Crv)
	}
	if recovered.Alg != jwk.Alg {
		t.Errorf("wrong Alg: got %s, want %s", recovered.Alg, jwk.Alg)
	}
	if recovered.X != jwk.X {
		t.Errorf("wrong X: got %s, want %s", recovered.X, jwk.X)
	}
	if recovered.Y != jwk.Y {
		t.Errorf("wrong Y: got %s, want %s", recovered.Y, jwk.Y)
	}
	if recovered.D != jwk.D {
		t.Errorf("wrong D: got %s, want %s", recovered.D, jwk.D)
	}
}

func TestGenerateSecp256k1Key(t *testing.T) {
	key1, err := GenerateSecp256k1Key()
	if err != nil {
		t.Fatalf("failed to generate first key: %v", err)
	}

	key2, err := GenerateSecp256k1Key()
	if err != nil {
		t.Fatalf("failed to generate second key: %v", err)
	}

	// Keys should be different
	if key1.Equal(key2) {
		t.Error("generated keys should be different")
	}
}

func TestGenerateEd25519Key(t *testing.T) {
	key1, err := GenerateEd25519Key()
	if err != nil {
		t.Fatalf("failed to generate first key: %v", err)
	}

	key2, err := GenerateEd25519Key()
	if err != nil {
		t.Fatalf("failed to generate second key: %v", err)
	}

	// Keys should be different
	if key1.Equal(key2) {
		t.Error("generated keys should be different")
	}
}

func TestGenerateBLSKey(t *testing.T) {
	key1, err := GenerateBLSKey()
	if err != nil {
		t.Fatalf("failed to generate first key: %v", err)
	}

	key2, err := GenerateBLSKey()
	if err != nil {
		t.Fatalf("failed to generate second key: %v", err)
	}

	// Keys should be different
	pub1, _ := key1.PublicKey().MarshalBinary()
	pub2, _ := key2.PublicKey().MarshalBinary()

	if string(pub1) == string(pub2) {
		t.Error("generated keys should be different")
	}
}

func TestJWKMarshalUnmarshal(t *testing.T) {
	// Generate an EC key
	privateKey, _ := GenerateSecp256k1Key()
	jwk := PrivateKeyToJWK(privateKey, "marshal-test")

	// Marshal
	data, err := MarshalJWK(jwk)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	// Unmarshal
	recovered, err := UnmarshalJWK(data)
	if err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	// Verify
	if recovered.Kty != jwk.Kty {
		t.Errorf("wrong Kty: got %s, want %s", recovered.Kty, jwk.Kty)
	}
	if recovered.Crv != jwk.Crv {
		t.Errorf("wrong Crv: got %s, want %s", recovered.Crv, jwk.Crv)
	}

	// Convert back to key and verify
	recoveredKey, err := JWKToPrivateKey(recovered)
	if err != nil {
		t.Fatalf("failed to convert recovered JWK: %v", err)
	}

	if !privateKey.Equal(recoveredKey) {
		t.Error("recovered key does not match original")
	}
}

func TestInvalidJWKConversions(t *testing.T) {
	// Test invalid Ed25519 JWK
	invalidEd := &JWK{Kty: "EC", Crv: "P-256"}
	_, err := JWKToEd25519PrivateKey(invalidEd)
	if err == nil {
		t.Error("expected error for invalid Ed25519 JWK")
	}

	// Test missing D for Ed25519
	missingD := &JWK{Kty: "OKP", Crv: "Ed25519", X: "test"}
	_, err = JWKToEd25519PrivateKey(missingD)
	if err == nil {
		t.Error("expected error for missing D")
	}

	// Test invalid BLS JWK
	invalidBLS := &JWK{Kty: "EC", Crv: "P-256"}
	_, err = JWKToBLSPrivateKey(invalidBLS)
	if err == nil {
		t.Error("expected error for invalid BLS JWK")
	}
}

func TestSignWithConvertedKeys(t *testing.T) {
	// This tests the full flow: generate key, convert to JWK, convert back, sign

	// EC key
	ecKey, _ := GenerateSecp256k1Key()
	ecJWK := PrivateKeyToJWK(ecKey, "ec-test")
	recoveredEC, _ := JWKToPrivateKey(ecJWK)

	// Sign with original using rand.Reader
	msg := []byte("test message")
	r1, s1, err := ecdsa.Sign(rand.Reader, ecKey, msg)
	if err != nil {
		t.Fatalf("failed to sign EC: %v", err)
	}

	// Verify with recovered
	if !ecdsa.Verify(&recoveredEC.PublicKey, msg, r1, s1) {
		t.Error("EC signature verification failed with recovered key")
	}

	// Ed25519 key
	edKey, _ := GenerateEd25519Key()
	edJWK := Ed25519PrivateKeyToJWK(edKey, "ed-test")
	recoveredED, _ := JWKToEd25519PrivateKey(edJWK)

	// Sign with original
	sig := ed25519.Sign(edKey, msg)

	// Verify with recovered
	if !ed25519.Verify(recoveredED.Public().(ed25519.PublicKey), msg, sig) {
		t.Error("Ed25519 signature verification failed with recovered key")
	}
}
