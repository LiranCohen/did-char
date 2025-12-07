# DID-CHAR Implementation Plan

## Project Structure

```
did-char/
├── cmd/
│   └── did-char/
│       └── main.go                 # CLI entry point
│
├── pkg/
│   ├── did/
│   │   ├── suffix.go               # DID suffix generation
│   │   ├── document.go             # DID document structure
│   │   ├── commitment.go           # Commitment/reveal schemes
│   │   ├── operations.go           # Operation structures
│   │   ├── create.go               # CREATE operation
│   │   ├── update.go               # UPDATE operation
│   │   ├── recover.go              # RECOVER operation (future)
│   │   ├── deactivate.go           # DEACTIVATE operation
│   │   └── validator.go            # Operation validation
│   │
│   ├── char/
│   │   ├── client.go               # Bitcoin RPC client wrapper
│   │   ├── referendum.go           # Referendum vote encoding
│   │   ├── polling.go              # Decision roll polling logic
│   │   └── types.go                # CHAR response types
│   │
│   ├── storage/
│   │   ├── sqlite.go               # SQLite database operations
│   │   ├── models.go               # Database models
│   │   ├── migrations.go           # Schema migrations
│   │   └── queries.go              # Query builders
│   │
│   ├── keys/
│   │   ├── manager.go              # Key file read/write
│   │   ├── generator.go            # Key generation
│   │   ├── jwk.go                  # JWK utilities
│   │   └── types.go                # Key structures
│   │
│   ├── encoding/
│   │   ├── payload.go              # Binary payload encoding
│   │   ├── base64url.go            # Base64URL encoding
│   │   └── varint.go               # Varint encoding
│   │
│   ├── crypto/
│   │   ├── hash.go                 # SHA-256 hashing
│   │   ├── sign.go                 # ECDSA signing
│   │   └── verify.go               # Signature verification
│   │
│   ├── demo/
│   │   ├── keygen.go               # Random key generation
│   │   ├── servicegen.go           # Random service generation
│   │   └── faker.go                # Fake data utilities
│   │
│   └── config/
│       ├── config.go               # Configuration loading
│       └── types.go                # Config structures
│
├── go.mod
├── go.sum
├── config.yaml.example
├── README.md
├── DESIGN.md
├── CLI.md
└── IMPLEMENTATION.md                # This file
```

## Dependencies

### Required Go Modules

```go
// go.mod
module github.com/yourusername/did-char

go 1.21

require (
    // Crypto
    github.com/btcsuite/btcd/btcec/v2 v2.3.2  // secp256k1
    github.com/btcsuite/btcd v0.24.0          // Bitcoin utilities

    // Database
    github.com/mattn/go-sqlite3 v1.14.18

    // CLI
    github.com/spf13/cobra v1.8.0
    github.com/spf13/viper v1.18.2

    // Encoding/Decoding
    github.com/multiformats/go-multibase v0.2.0  // Base64URL

    // Demo/Testing
    github.com/brianvoe/gofakeit/v6 v6.27.0  // Fake data generation

    // Utilities
    github.com/google/uuid v1.5.0
)
```

### Optional: Use sidetree-go

If we want to leverage existing Sidetree code:

```go
require (
    github.com/trustbloc/sidetree-go v0.x.x  // For canonicalizer, hashing, etc.
)
```

## Implementation Phases

### Phase 1: Basic Infrastructure (Priority 1)

**Goal**: Set up project skeleton, config, database

**Tasks**:
- [x] Create project structure
- [ ] Initialize Go module
- [ ] Set up Cobra CLI framework
- [ ] Implement config loading (Viper)
- [ ] Create SQLite schema
- [ ] Write database migration logic
- [ ] Implement key file management

**Files**:
- `cmd/did-char/main.go`
- `pkg/config/config.go`
- `pkg/storage/sqlite.go`
- `pkg/storage/migrations.go`
- `pkg/keys/manager.go`

**Tests**:
- Config loading from YAML and env vars
- Database creation and migrations
- Key file read/write

---

### Phase 2: Crypto & Encoding (Priority 1)

**Goal**: Implement cryptographic primitives and encoding

**Tasks**:
- [ ] SHA-256 hashing utilities
- [ ] secp256k1 key generation
- [ ] ECDSA signing and verification
- [ ] JWK encoding/decoding
- [ ] Base64URL encoding
- [ ] Varint encoding/decoding
- [ ] Commitment/reveal logic

**Files**:
- `pkg/crypto/hash.go`
- `pkg/crypto/sign.go`
- `pkg/crypto/verify.go`
- `pkg/keys/jwk.go`
- `pkg/keys/generator.go`
- `pkg/encoding/base64url.go`
- `pkg/encoding/varint.go`
- `pkg/did/commitment.go`

**Tests**:
- Key generation produces valid secp256k1 keys
- Signatures verify correctly
- Commitments match expected hashes
- Base64URL round-trip
- Varint encoding/decoding

---

### Phase 3: CHAR RPC Client (Priority 1)

**Goal**: Communicate with CHAR node

**Tasks**:
- [ ] Bitcoin RPC client wrapper
- [ ] `addbambookv` implementation
- [ ] `getreferendumdecisionroll` implementation
- [ ] Polling logic with retry/timeout
- [ ] Error handling for RPC failures

**Files**:
- `pkg/char/client.go`
- `pkg/char/types.go`
- `pkg/char/polling.go`

**Tests**:
- Mock RPC responses
- Test polling until `found: true`
- Test timeout behavior
- Test network errors

---

### Phase 4: DID Operations (Priority 2)

**Goal**: Implement CREATE, UPDATE, DEACTIVATE operations

**Tasks**:
- [ ] DID suffix generation
- [ ] DID document structure
- [ ] CREATE operation encoding
- [ ] UPDATE operation encoding
- [ ] DEACTIVATE operation encoding
- [ ] Operation validation
- [ ] Payload binary encoding

**Files**:
- `pkg/did/suffix.go`
- `pkg/did/document.go`
- `pkg/did/create.go`
- `pkg/did/update.go`
- `pkg/did/deactivate.go`
- `pkg/did/validator.go`
- `pkg/encoding/payload.go`

**Tests**:
- DID suffix derivation matches spec
- Operation encoding/decoding round-trip
- Validation rejects invalid operations
- Commitment verification works

---

### Phase 5: CLI Commands (Priority 2)

**Goal**: Implement user-facing commands

**Tasks**:
- [ ] `create` command
- [ ] `update` command
- [ ] `resolve` command
- [ ] `deactivate` command
- [ ] `sync` command
- [ ] `status` command
- [ ] `history` command
- [ ] `generate-key` command
- [ ] `generate-service` command

**Files**:
- `cmd/did-char/create.go`
- `cmd/did-char/update.go`
- `cmd/did-char/resolve.go`
- `cmd/did-char/deactivate.go`
- `cmd/did-char/sync.go`
- `cmd/did-char/status.go`
- `cmd/did-char/history.go`
- `cmd/did-char/generate.go`

**Tests**:
- End-to-end command execution
- Flag parsing
- Output formatting

---

### Phase 6: Demo Utilities (Priority 2)

**Goal**: Make demo/testing easier

**Tasks**:
- [ ] Random JWK generation with gofakeit
- [ ] Random service endpoint generation
- [ ] Fake data patterns (adjective-noun-number)
- [ ] Pretty output formatting

**Files**:
- `pkg/demo/keygen.go`
- `pkg/demo/servicegen.go`
- `pkg/demo/faker.go`

**Tests**:
- Generated keys are valid
- Generated services have correct structure
- Randomness produces variety

---

### Phase 7: Sync & Resolution (Priority 3)

**Goal**: Query and process decision rolls

**Tasks**:
- [ ] Decision roll parsing
- [ ] Operation decoding from payloads
- [ ] State machine for applying operations
- [ ] Batch sync from ballot range
- [ ] Incremental sync logic

**Files**:
- `pkg/char/referendum.go`
- `pkg/did/processor.go`
- `pkg/storage/sync.go`

**Tests**:
- Parse real decision roll responses
- Apply operations in order
- Handle missing ballots gracefully

---

### Phase 8: Testing & Documentation (Priority 3)

**Goal**: Make it production-ready-ish

**Tasks**:
- [ ] Integration tests against real CHAR node
- [ ] Demo script
- [ ] Usage examples in README
- [ ] Error message improvements
- [ ] Logging

**Files**:
- `test/integration_test.go`
- `demo.sh`
- Updated `README.md`

---

## Key Implementation Details

### DID Suffix Generation

```go
// pkg/did/suffix.go
func GenerateSuffix(initialState []byte) (string, error) {
    // 1. Canonicalize initial state JSON
    canonical := canonicalize(initialState)

    // 2. Hash with SHA-256
    hash := sha256.Sum256(canonical)

    // 3. Base64URL encode
    suffix := base64url.Encode(hash[:])

    return suffix, nil
}
```

### Commitment/Reveal

```go
// pkg/did/commitment.go
func GenerateCommitment(key *ecdsa.PrivateKey) (commitment, reveal string, err error) {
    // Step 1: Serialize public key
    pubKeyBytes := serializePublicKey(key.PublicKey)

    // Step 2: Hash once to get reveal value
    revealHash := sha256.Sum256(pubKeyBytes)
    reveal = base64url.Encode(revealHash[:])

    // Step 3: Hash again to get commitment
    commitmentHash := sha256.Sum256(revealHash[:])
    commitment = base64url.Encode(commitmentHash[:])

    return commitment, reveal, nil
}

func VerifyReveal(reveal, expectedCommitment string) bool {
    revealBytes := base64url.Decode(reveal)
    commitmentHash := sha256.Sum256(revealBytes)
    actualCommitment := base64url.Encode(commitmentHash[:])
    return actualCommitment == expectedCommitment
}
```

### Binary Payload Encoding

```go
// pkg/encoding/payload.go
type OperationPayload struct {
    Version      byte
    OperationType byte
    DIDSuffix    string
    OperationJSON []byte
}

func (p *OperationPayload) Encode() ([]byte, error) {
    buf := new(bytes.Buffer)

    // Version
    buf.WriteByte(p.Version)

    // Operation type
    buf.WriteByte(p.OperationType)

    // DID suffix length + suffix
    suffixBytes := []byte(p.DIDSuffix)
    buf.Write(encodeVarint(len(suffixBytes)))
    buf.Write(suffixBytes)

    // Operation JSON length + JSON
    buf.Write(encodeVarint(len(p.OperationJSON)))
    buf.Write(p.OperationJSON)

    return buf.Bytes(), nil
}

func DecodePayload(data []byte) (*OperationPayload, error) {
    r := bytes.NewReader(data)

    version, _ := r.ReadByte()
    opType, _ := r.ReadByte()

    suffixLen := decodeVarint(r)
    suffixBytes := make([]byte, suffixLen)
    r.Read(suffixBytes)

    jsonLen := decodeVarint(r)
    jsonBytes := make([]byte, jsonLen)
    r.Read(jsonBytes)

    return &OperationPayload{
        Version:       version,
        OperationType: opType,
        DIDSuffix:     string(suffixBytes),
        OperationJSON: jsonBytes,
    }, nil
}
```

### CHAR Polling Logic

```go
// pkg/char/polling.go
func (c *Client) PollForConfirmation(
    domain string,
    ballotNumber int,
    maxAttempts int,
    interval time.Duration,
) (*DecisionRoll, error) {
    for attempt := 0; attempt < maxAttempts; attempt++ {
        roll, err := c.GetReferendumDecisionRoll(domain, ballotNumber, 1)
        if err != nil {
            return nil, fmt.Errorf("RPC error: %w", err)
        }

        if roll.Found {
            return roll, nil
        }

        log.Printf("Ballot %d not confirmed yet, attempt %d/%d",
            ballotNumber, attempt+1, maxAttempts)

        time.Sleep(interval)
    }

    return nil, fmt.Errorf("timeout waiting for ballot %d confirmation", ballotNumber)
}
```

### Demo Key Generation

```go
// pkg/demo/keygen.go
import "github.com/brianvoe/gofakeit/v6"

func GenerateRandomJWK() (*JWK, error) {
    // Generate secp256k1 key
    privateKey, err := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
    if err != nil {
        return nil, err
    }

    // Random ID using faker
    keyID := fmt.Sprintf("key-%s", gofakeit.LetterN(4))

    return &JWK{
        ID:  keyID,
        Kty: "EC",
        Crv: "secp256k1",
        X:   base64url.Encode(privateKey.X.Bytes()),
        Y:   base64url.Encode(privateKey.Y.Bytes()),
        D:   base64url.Encode(privateKey.D.Bytes()),
    }, nil
}
```

### Demo Service Generation

```go
// pkg/demo/servicegen.go
func GenerateRandomService() (*Service, error) {
    serviceTypes := []string{
        "LinkedDomains",
        "SocialWebProfile",
        "DIDCommMessaging",
        "CredentialRegistry",
        "IdentityHub",
    }

    serviceType := gofakeit.RandomString(serviceTypes)
    serviceID := fmt.Sprintf("service-%s", gofakeit.LetterN(4))

    var endpoint string
    switch serviceType {
    case "LinkedDomains":
        endpoint = fmt.Sprintf("https://%s-%s-%d.example.com",
            gofakeit.Adjective(),
            gofakeit.Noun(),
            gofakeit.Number(1000, 9999))
    case "SocialWebProfile":
        endpoint = fmt.Sprintf("https://twitter.com/user_%s_%s_%d",
            gofakeit.Adjective(),
            gofakeit.Noun(),
            gofakeit.Number(1000, 9999))
    case "DIDCommMessaging":
        endpoint = fmt.Sprintf("https://agent-%s-%s-%d.example.com/inbox",
            gofakeit.Adjective(),
            gofakeit.Noun(),
            gofakeit.Number(1000, 9999))
    // ... more cases
    }

    return &Service{
        ID:              serviceID,
        Type:            serviceType,
        ServiceEndpoint: endpoint,
    }, nil
}
```

## Testing Strategy

### Unit Tests

Each package should have `*_test.go` files:
- `pkg/crypto/hash_test.go`
- `pkg/did/suffix_test.go`
- `pkg/encoding/payload_test.go`
- etc.

### Integration Tests

Test against real CHAR node:

```go
// test/integration_test.go
func TestCreateAndResolve(t *testing.T) {
    // Requires CHAR_RPC_HOST env var
    if os.Getenv("CHAR_RPC_HOST") == "" {
        t.Skip("Integration test requires CHAR node")
    }

    // 1. Create DID
    did, keyFile := createDID(t)

    // 2. Update DID
    updateDID(t, did, keyFile)

    // 3. Resolve DID
    doc := resolveDID(t, did)

    // 4. Verify state
    assert.Equal(t, 2, len(doc.PublicKeys))
}
```

### Demo Script

```bash
#!/bin/bash
# demo.sh

set -e

echo "=== DID-CHAR Demo ==="

echo "1. Creating DID..."
did-char create --verbose

echo "2. Generating random key..."
did-char generate-key --output demo-key.jwk

echo "3. Adding key to DID..."
did-char update $DID --add-public-key demo-key.jwk

echo "4. Generating random service..."
did-char generate-service --output demo-service.json

echo "5. Adding service to DID..."
did-char update $DID --add-service "$(cat demo-service.json)"

echo "6. Resolving DID..."
did-char resolve $DID

echo "7. Showing history..."
did-char history $DID

echo "=== Demo Complete ==="
```

## Development Workflow

### Day 1: Infrastructure
1. Set up Go project
2. Implement config loading
3. Create SQLite schema
4. Write key file manager

### Day 2: Crypto & CHAR
1. Implement crypto utilities
2. Build CHAR RPC client
3. Test polling logic
4. Test commitment/reveal

### Day 3: DID Operations
1. Implement CREATE operation
2. Implement UPDATE operation
3. Implement payload encoding
4. Write operation validators

### Day 4: CLI & Demo
1. Build CLI commands
2. Implement demo generators
3. Wire everything together
4. End-to-end testing

### Day 5: Polish & Demo
1. Fix bugs
2. Improve error messages
3. Write demo script
4. Present!

## Known Challenges

1. **Ballot Timing**: Need to tune polling intervals
2. **Error Handling**: RPC failures need graceful handling
3. **Concurrent Operations**: Multiple operations at once?
4. **Key Security**: Key files on disk are sensitive
5. **Sync Performance**: Large ballot ranges could be slow

## Success Criteria

Minimum viable demo:
- ✅ Create a DID
- ✅ Update the DID (add key or service)
- ✅ Resolve the DID
- ✅ Operations appear in CHAR decision rolls
- ✅ Keys persisted in files
- ✅ State tracked in SQLite

Stretch goals:
- ✅ Deactivate command
- ✅ History command
- ✅ Demo generators
- ⏸️ Recover operation (defer if time-constrained)
- ⏸️ Multiple DID support (should work automatically)
