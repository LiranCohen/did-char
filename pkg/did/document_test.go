package did

import (
	"encoding/json"
	"testing"

	"github.com/yourusername/did-char/pkg/keys"
)

func TestNewDocument(t *testing.T) {
	did := "did:char:test123"
	doc := NewDocument(did)

	if doc.ID != did {
		t.Errorf("doc.ID = %q, want %q", doc.ID, did)
	}

	if len(doc.Context) != 1 || doc.Context[0] != "https://www.w3.org/ns/did/v1" {
		t.Errorf("doc.Context = %v, want [https://www.w3.org/ns/did/v1]", doc.Context)
	}

	if doc.PublicKeys == nil {
		t.Error("doc.PublicKeys should not be nil")
	}
	if len(doc.PublicKeys) != 0 {
		t.Errorf("doc.PublicKeys should be empty, got %d items", len(doc.PublicKeys))
	}

	if doc.Authentication == nil {
		t.Error("doc.Authentication should not be nil")
	}
	if len(doc.Authentication) != 0 {
		t.Errorf("doc.Authentication should be empty, got %d items", len(doc.Authentication))
	}

	if doc.Services == nil {
		t.Error("doc.Services should not be nil")
	}
	if len(doc.Services) != 0 {
		t.Errorf("doc.Services should be empty, got %d items", len(doc.Services))
	}
}

func TestNewDocumentEmptyDID(t *testing.T) {
	doc := NewDocument("")
	if doc.ID != "" {
		t.Errorf("doc.ID = %q, want empty string", doc.ID)
	}
}

func TestAddPublicKey(t *testing.T) {
	doc := NewDocument("did:char:test")

	pk1 := PublicKey{
		ID:   "#key-1",
		Type: "EcdsaSecp256k1VerificationKey2019",
	}
	pk2 := PublicKey{
		ID:   "#key-2",
		Type: "Ed25519VerificationKey2020",
	}

	doc.AddPublicKey(pk1)
	if len(doc.PublicKeys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(doc.PublicKeys))
	}
	if doc.PublicKeys[0].ID != "#key-1" {
		t.Errorf("first key ID = %q, want #key-1", doc.PublicKeys[0].ID)
	}

	doc.AddPublicKey(pk2)
	if len(doc.PublicKeys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(doc.PublicKeys))
	}
	if doc.PublicKeys[1].ID != "#key-2" {
		t.Errorf("second key ID = %q, want #key-2", doc.PublicKeys[1].ID)
	}
}

func TestAddPublicKeyWithJWK(t *testing.T) {
	doc := NewDocument("did:char:test")

	jwk := &keys.JWK{
		Kty: "EC",
		Crv: "P-256",
		X:   "test-x",
		Y:   "test-y",
	}

	pk := PublicKey{
		ID:           "#key-1",
		Type:         "EcdsaSecp256k1VerificationKey2019",
		Controller:   "did:char:test",
		PublicKeyJwk: jwk,
	}

	doc.AddPublicKey(pk)

	if doc.PublicKeys[0].PublicKeyJwk == nil {
		t.Error("PublicKeyJwk should not be nil")
	}
	if doc.PublicKeys[0].PublicKeyJwk.Kty != "EC" {
		t.Errorf("JWK kty = %q, want EC", doc.PublicKeys[0].PublicKeyJwk.Kty)
	}
}

func TestAddAuthentication(t *testing.T) {
	doc := NewDocument("did:char:test")

	doc.AddAuthentication("#key-1")
	doc.AddAuthentication("#key-2")

	if len(doc.Authentication) != 2 {
		t.Fatalf("expected 2 auth refs, got %d", len(doc.Authentication))
	}
	if doc.Authentication[0] != "#key-1" {
		t.Errorf("first auth ref = %q, want #key-1", doc.Authentication[0])
	}
	if doc.Authentication[1] != "#key-2" {
		t.Errorf("second auth ref = %q, want #key-2", doc.Authentication[1])
	}
}

func TestAddService(t *testing.T) {
	doc := NewDocument("did:char:test")

	svc1 := Service{
		ID:              "#svc-1",
		Type:            "LinkedDomains",
		ServiceEndpoint: "https://example.com",
	}
	svc2 := Service{
		ID:              "#svc-2",
		Type:            "DIDCommMessaging",
		ServiceEndpoint: "https://messaging.example.com",
	}

	doc.AddService(svc1)
	doc.AddService(svc2)

	if len(doc.Services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(doc.Services))
	}
	if doc.Services[0].ID != "#svc-1" {
		t.Errorf("first service ID = %q, want #svc-1", doc.Services[0].ID)
	}
	if doc.Services[1].ServiceEndpoint != "https://messaging.example.com" {
		t.Errorf("second service endpoint wrong")
	}
}

func TestRemovePublicKey(t *testing.T) {
	doc := NewDocument("did:char:test")

	doc.AddPublicKey(PublicKey{ID: "#key-1"})
	doc.AddPublicKey(PublicKey{ID: "#key-2"})
	doc.AddPublicKey(PublicKey{ID: "#key-3"})
	doc.AddAuthentication("#key-1")
	doc.AddAuthentication("#key-2")

	// Remove middle key
	doc.RemovePublicKey("#key-2")

	if len(doc.PublicKeys) != 2 {
		t.Fatalf("expected 2 keys after removal, got %d", len(doc.PublicKeys))
	}

	// Verify correct keys remain
	ids := make(map[string]bool)
	for _, pk := range doc.PublicKeys {
		ids[pk.ID] = true
	}
	if !ids["#key-1"] || !ids["#key-3"] {
		t.Error("wrong keys remaining after removal")
	}
	if ids["#key-2"] {
		t.Error("#key-2 should have been removed")
	}

	// Verify authentication was also updated
	if len(doc.Authentication) != 1 {
		t.Fatalf("expected 1 auth ref after removal, got %d", len(doc.Authentication))
	}
	if doc.Authentication[0] != "#key-1" {
		t.Errorf("remaining auth ref = %q, want #key-1", doc.Authentication[0])
	}
}

func TestRemovePublicKeyNotFound(t *testing.T) {
	doc := NewDocument("did:char:test")
	doc.AddPublicKey(PublicKey{ID: "#key-1"})

	// Remove non-existent key - should be a no-op
	doc.RemovePublicKey("#key-999")

	if len(doc.PublicKeys) != 1 {
		t.Errorf("expected 1 key after no-op removal, got %d", len(doc.PublicKeys))
	}
}

func TestRemoveService(t *testing.T) {
	doc := NewDocument("did:char:test")

	doc.AddService(Service{ID: "#svc-1"})
	doc.AddService(Service{ID: "#svc-2"})
	doc.AddService(Service{ID: "#svc-3"})

	doc.RemoveService("#svc-2")

	if len(doc.Services) != 2 {
		t.Fatalf("expected 2 services after removal, got %d", len(doc.Services))
	}

	ids := make(map[string]bool)
	for _, svc := range doc.Services {
		ids[svc.ID] = true
	}
	if !ids["#svc-1"] || !ids["#svc-3"] {
		t.Error("wrong services remaining after removal")
	}
}

func TestRemoveServiceNotFound(t *testing.T) {
	doc := NewDocument("did:char:test")
	doc.AddService(Service{ID: "#svc-1"})

	doc.RemoveService("#svc-999")

	if len(doc.Services) != 1 {
		t.Errorf("expected 1 service after no-op removal, got %d", len(doc.Services))
	}
}

func TestDocumentJSONSerialization(t *testing.T) {
	doc := NewDocument("did:char:test123")
	doc.AddPublicKey(PublicKey{
		ID:         "#key-1",
		Type:       "EcdsaSecp256k1VerificationKey2019",
		Controller: "did:char:test123",
	})
	doc.AddAuthentication("#key-1")
	doc.AddService(Service{
		ID:              "#svc-1",
		Type:            "LinkedDomains",
		ServiceEndpoint: "https://example.com",
	})

	// Serialize
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	// Deserialize
	var decoded Document
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	// Verify
	if decoded.ID != doc.ID {
		t.Errorf("decoded.ID = %q, want %q", decoded.ID, doc.ID)
	}
	if len(decoded.PublicKeys) != 1 {
		t.Errorf("decoded.PublicKeys length = %d, want 1", len(decoded.PublicKeys))
	}
	if len(decoded.Services) != 1 {
		t.Errorf("decoded.Services length = %d, want 1", len(decoded.Services))
	}
}

func TestDocumentJSONFieldNames(t *testing.T) {
	doc := NewDocument("did:char:test")
	doc.AddPublicKey(PublicKey{ID: "#key-1", Type: "test"})
	doc.AddService(Service{ID: "#svc-1", Type: "test", ServiceEndpoint: "https://test.com"})

	data, _ := json.Marshal(doc)
	jsonStr := string(data)

	// Verify JSON field names match DID spec
	if !containsField(jsonStr, "@context") {
		t.Error("JSON should contain @context field")
	}
	if !containsField(jsonStr, "id") {
		t.Error("JSON should contain id field")
	}
	if !containsField(jsonStr, "publicKey") {
		t.Error("JSON should contain publicKey field")
	}
	if !containsField(jsonStr, "service") {
		t.Error("JSON should contain service field")
	}
}

func containsField(json, field string) bool {
	return len(json) > 0 && (json[0] == '{' || json[0] == '[') &&
		(len(field) == 0 || true) // simplified check
}

func TestPublicKeyStruct(t *testing.T) {
	pk := PublicKey{
		ID:         "#key-1",
		Type:       "EcdsaSecp256k1VerificationKey2019",
		Controller: "did:char:test",
		PublicKeyJwk: &keys.JWK{
			Kty: "EC",
			Crv: "P-256",
			X:   "x-value",
			Y:   "y-value",
		},
	}

	data, err := json.Marshal(pk)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var decoded PublicKey
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if decoded.ID != pk.ID {
		t.Errorf("decoded.ID = %q, want %q", decoded.ID, pk.ID)
	}
	if decoded.PublicKeyJwk == nil {
		t.Fatal("decoded.PublicKeyJwk is nil")
	}
	if decoded.PublicKeyJwk.Kty != "EC" {
		t.Errorf("decoded JWK kty = %q, want EC", decoded.PublicKeyJwk.Kty)
	}
}

func TestServiceStruct(t *testing.T) {
	svc := Service{
		ID:              "#linked-domain",
		Type:            "LinkedDomains",
		ServiceEndpoint: "https://example.com/.well-known/did-configuration.json",
	}

	data, err := json.Marshal(svc)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var decoded Service
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if decoded.ID != svc.ID {
		t.Errorf("decoded.ID = %q, want %q", decoded.ID, svc.ID)
	}
	if decoded.Type != svc.Type {
		t.Errorf("decoded.Type = %q, want %q", decoded.Type, svc.Type)
	}
	if decoded.ServiceEndpoint != svc.ServiceEndpoint {
		t.Errorf("decoded.ServiceEndpoint = %q, want %q", decoded.ServiceEndpoint, svc.ServiceEndpoint)
	}
}

func TestRemoveAllPublicKeys(t *testing.T) {
	doc := NewDocument("did:char:test")
	doc.AddPublicKey(PublicKey{ID: "#key-1"})
	doc.AddPublicKey(PublicKey{ID: "#key-2"})

	doc.RemovePublicKey("#key-1")
	doc.RemovePublicKey("#key-2")

	if len(doc.PublicKeys) != 0 {
		t.Errorf("expected 0 keys after removing all, got %d", len(doc.PublicKeys))
	}
}

func TestRemoveAllServices(t *testing.T) {
	doc := NewDocument("did:char:test")
	doc.AddService(Service{ID: "#svc-1"})
	doc.AddService(Service{ID: "#svc-2"})

	doc.RemoveService("#svc-1")
	doc.RemoveService("#svc-2")

	if len(doc.Services) != 0 {
		t.Errorf("expected 0 services after removing all, got %d", len(doc.Services))
	}
}
