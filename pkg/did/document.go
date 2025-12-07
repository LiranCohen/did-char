package did

import "github.com/yourusername/did-char/pkg/keys"

// Document represents a DID document
type Document struct {
	Context        []string          `json:"@context"`
	ID             string            `json:"id"`
	PublicKeys     []PublicKey       `json:"publicKey,omitempty"`
	Authentication []string          `json:"authentication,omitempty"`
	Services       []Service         `json:"service,omitempty"`
}

// PublicKey represents a public key in a DID document
type PublicKey struct {
	ID           string    `json:"id"`
	Type         string    `json:"type"`
	Controller   string    `json:"controller,omitempty"`
	PublicKeyJwk *keys.JWK `json:"publicKeyJwk,omitempty"`
}

// Service represents a service endpoint in a DID document
type Service struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
}

// NewDocument creates a new DID document
func NewDocument(did string) *Document {
	return &Document{
		Context:        []string{"https://www.w3.org/ns/did/v1"},
		ID:             did,
		PublicKeys:     []PublicKey{},
		Authentication: []string{},
		Services:       []Service{},
	}
}

// AddPublicKey adds a public key to the document
func (d *Document) AddPublicKey(pk PublicKey) {
	d.PublicKeys = append(d.PublicKeys, pk)
}

// AddAuthentication adds an authentication reference
func (d *Document) AddAuthentication(keyID string) {
	d.Authentication = append(d.Authentication, keyID)
}

// AddService adds a service endpoint
func (d *Document) AddService(svc Service) {
	d.Services = append(d.Services, svc)
}

// RemovePublicKey removes a public key by ID
func (d *Document) RemovePublicKey(keyID string) {
	filtered := []PublicKey{}
	for _, pk := range d.PublicKeys {
		if pk.ID != keyID {
			filtered = append(filtered, pk)
		}
	}
	d.PublicKeys = filtered

	// Also remove from authentication
	authFiltered := []string{}
	for _, authID := range d.Authentication {
		if authID != keyID {
			authFiltered = append(authFiltered, authID)
		}
	}
	d.Authentication = authFiltered
}

// RemoveService removes a service by ID
func (d *Document) RemoveService(serviceID string) {
	filtered := []Service{}
	for _, svc := range d.Services {
		if svc.ID != serviceID {
			filtered = append(filtered, svc)
		}
	}
	d.Services = filtered
}
