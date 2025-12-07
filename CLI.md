# DID-CHAR CLI Documentation

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/did-char
cd did-char

# Build
go build -o did-char ./cmd/did-char

# Or install globally
go install ./cmd/did-char
```

## Configuration

Create `config.yaml` in the working directory:

```yaml
char:
  rpc_host: "100.67.0.7"
  rpc_port: 18443
  rpc_user: "char"
  rpc_password: "char"
  network: "regtest"
  app_domain: "did-char-domain"
  # App preimage in hex (for RPC calls)
  app_preimage: "6469642d636861722d646f6d61696e"

database:
  path: "./did-char.db"

polling:
  max_attempts: 30        # Maximum poll attempts
  interval_ms: 100        # Milliseconds between polls
  timeout_seconds: 10     # Overall timeout
```

Or use environment variables:
```bash
export CHAR_RPC_HOST=100.67.0.7
export CHAR_RPC_PORT=18443
export CHAR_RPC_USER=char
export CHAR_RPC_PASSWORD=char
export CHAR_APP_DOMAIN=did-char-domain
```

## Commands

### create

Create a new DID with auto-generated keys.

```bash
did-char create [options]
```

**Options**:
- `--service <json>` - Add service endpoint to initial DID document
- `--key-file <path>` - Custom path for key file (default: auto-generated from DID)
- `--verbose` - Show detailed operation information

**Example**:
```bash
# Basic creation
did-char create

# Output:
# Created DID: did:char:EiDahaOGH-liLLdDtTxEAdc8i-cfCz-WUcQdRJheMVNn3A
# Ballot: 42
# Keys saved to: did_char_EiDahaOGH-liLLdDtTxEAdc8i-cfCz-WUcQdRJheMVNn3A.json

# With service endpoint
did-char create --service '{"id":"domain","type":"LinkedDomains","serviceEndpoint":"https://example.com"}'

# Verbose output
did-char create --verbose
# Shows: key generation, commitment calculation, payload encoding, polling status
```

**What Happens**:
1. Generate secp256k1 update and recovery keys
2. Calculate update and recovery commitments
3. Create initial DID document with keys
4. Compute DID suffix from initial state
5. Encode CREATE operation as hex payload
6. Submit via `addbambookv` to next ballot
7. Poll `getreferendumdecisionroll` until confirmed
8. Save DID state to SQLite
9. Write key file: `did_char_<suffix>.json`

---

### update

Update an existing DID document.

```bash
did-char update <did> [options]
```

**Arguments**:
- `<did>` - The DID to update (e.g., `did:char:EiDahaOGH...`)

**Options**:
- `--add-public-key <jwk-file>` - Add a public key from JWK file
- `--remove-public-key <key-id>` - Remove a public key by ID
- `--add-service <json>` - Add a service endpoint
- `--remove-service <service-id>` - Remove a service by ID
- `--key-file <path>` - Override key file path (default: `did_char_<suffix>.json`)
- `--verbose` - Show detailed operation information

**Examples**:
```bash
# Add a public key
did-char update did:char:EiDahaOGH... --add-public-key new-key.jwk

# Remove a key
did-char update did:char:EiDahaOGH... --remove-public-key key-2

# Add service endpoint
did-char update did:char:EiDahaOGH... \
  --add-service '{"id":"social","type":"SocialWebProfile","serviceEndpoint":"https://twitter.com/user"}'

# Multiple operations
did-char update did:char:EiDahaOGH... \
  --add-public-key key2.jwk \
  --add-service '{"id":"domain","type":"LinkedDomains","serviceEndpoint":"https://example.com"}' \
  --verbose
```

**What Happens**:
1. Load key file: `did_char_<suffix>.json`
2. Load current DID state from SQLite
3. Verify update key matches current commitment
4. Build JSON patches for requested changes
5. Create UPDATE operation with reveal value
6. Sign operation with update key
7. Generate new update commitment
8. Encode operation as hex payload
9. Submit via `addbambookv` to next ballot
10. Poll until confirmed
11. Update SQLite with new state
12. Update key file with new commitment

---

### resolve

Resolve a DID to its current state.

```bash
did-char resolve <did> [options]
```

**Arguments**:
- `<did>` - The DID to resolve

**Options**:
- `--sync` - Force sync from CHAR before resolving
- `--history` - Include operation history
- `--format <json|yaml|table>` - Output format (default: json)
- `--verbose` - Show sync progress

**Examples**:
```bash
# Basic resolution
did-char resolve did:char:EiDahaOGH...

# Output (JSON):
{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:char:EiDahaOGH-liLLdDtTxEAdc8i-cfCz-WUcQdRJheMVNn3A",
  "publicKey": [
    {
      "id": "#key-1",
      "type": "EcdsaSecp256k1VerificationKey2019",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "secp256k1",
        "x": "...",
        "y": "..."
      }
    }
  ],
  "authentication": ["#key-1"],
  "service": [
    {
      "id": "#domain",
      "type": "LinkedDomains",
      "serviceEndpoint": "https://example.com"
    }
  ]
}

# Force sync from CHAR
did-char resolve did:char:EiDahaOGH... --sync --verbose
# Shows: Syncing from ballot 42 to 50... Processing CREATE... Processing UPDATE...

# With operation history
did-char resolve did:char:EiDahaOGH... --history

# Output:
{
  "did": "did:char:EiDahaOGH...",
  "document": { ... },
  "history": [
    {
      "ballot": 42,
      "operation": "create",
      "timestamp": "2025-12-07T10:00:00Z"
    },
    {
      "ballot": 45,
      "operation": "update",
      "timestamp": "2025-12-07T10:05:00Z"
    }
  ]
}
```

**What Happens**:
1. Check SQLite for cached DID state
2. Get `last_synced_ballot` from sync_state
3. Query decision rolls from last_synced to current
4. For each new decision roll:
   - Decode operation payload
   - Validate signatures and commitments
   - Apply state changes
   - Store in SQLite
5. Return current DID document

---

### deactivate

Permanently deactivate a DID (irreversible).

```bash
did-char deactivate <did> [options]
```

**Arguments**:
- `<did>` - The DID to deactivate

**Options**:
- `--key-file <path>` - Override key file path
- `--confirm` - Skip confirmation prompt
- `--verbose` - Show detailed operation information

**Example**:
```bash
# Deactivate a DID
did-char deactivate did:char:EiDahaOGH...

# Prompt:
# WARNING: This will permanently deactivate the DID. This cannot be undone.
# Are you sure? (yes/no): yes

# Output:
# DID deactivated permanently
# Ballot: 99

# Skip confirmation
did-char deactivate did:char:EiDahaOGH... --confirm
```

**What Happens**:
1. Load key file
2. Load current DID state
3. Verify DID is active
4. Create DEACTIVATE operation with recovery key reveal
5. Sign with recovery key
6. Submit to CHAR
7. Poll until confirmed
8. Update SQLite status to 'deactivated'
9. Key file remains but marked as deactivated

---

### generate-key

Generate a random JWK key for demo purposes.

```bash
did-char generate-key [options]
```

**Options**:
- `--output <path>` - Output file path (default: print to stdout)
- `--id <string>` - Custom key ID (default: random, e.g., "key-5a3f")
- `--purpose <auth|assertion|keyagreement|delegation>` - Key purpose (default: authentication)

**Examples**:
```bash
# Generate and print to stdout
did-char generate-key

# Output (JSON):
{
  "id": "key-8f2a",
  "kty": "EC",
  "crv": "secp256k1",
  "x": "W4EgWNd8oeZAhLjzcqUTE2gUCL7-MpgH_WvZQjnJWwI",
  "y": "n0fMCY5-8w7bvPLH5SvKnfKL2F9jAnmj3bBqK0KhfJg",
  "d": "TQ_HyLwKH4PQPKKmYHVpq8_QyWnR4J-x2C8fL9Rh3zE"
}

# Save to file
did-char generate-key --output demo-key.jwk

# With custom ID
did-char generate-key --id "my-auth-key" --purpose auth
```

**Use Case**: Generate keys to add to DIDs via `update --add-public-key`

---

### generate-service

Generate a random service endpoint for demo purposes.

```bash
did-char generate-service [options]
```

**Options**:
- `--output <path>` - Output file path (default: print to stdout)
- `--type <type>` - Service type (default: random from common types)
- `--id <string>` - Custom service ID (default: random, e.g., "service-9c4e")

**Examples**:
```bash
# Generate random service
did-char generate-service

# Output (JSON):
{
  "id": "service-3f8b",
  "type": "LinkedDomains",
  "serviceEndpoint": "https://jolly-mountain-7382.example.com"
}

# Generate with specific type
did-char generate-service --type SocialWebProfile

# Output:
{
  "id": "service-2d5a",
  "type": "SocialWebProfile",
  "serviceEndpoint": "https://twitter.com/user_vibrant_cloud_4921"
}

# Save to file
did-char generate-service --output demo-service.json --type DIDCommMessaging

# Output file:
{
  "id": "service-8a1c",
  "type": "DIDCommMessaging",
  "serviceEndpoint": "https://agent-purple-star-1647.example.com/inbox"
}
```

**Common Service Types**:
- `LinkedDomains` - Website verification
- `SocialWebProfile` - Social media profiles
- `DIDCommMessaging` - DIDComm messaging endpoints
- `CredentialRegistry` - Credential issuance/verification
- `IdentityHub` - Decentralized identity hub

**Random Generation**:
- IDs: `service-<4-char-hex>` (e.g., `service-3f8b`)
- Domains: Uses fake but realistic-looking patterns
  - `https://<adjective>-<noun>-<number>.example.com`
  - `https://<service>.example.com/<random-path>`
  - `https://api-<id>.example.com/v1/<endpoint>`
- Usernames (for social): `user_<adjective>_<noun>_<number>`

**Use Case**: Generate services to add to DIDs via `update --add-service`

---

### sync

Sync all DIDs from CHAR (process new decision rolls).

```bash
did-char sync [options]
```

**Options**:
- `--from <ballot>` - Start syncing from specific ballot number
- `--to <ballot>` - Stop syncing at specific ballot number
- `--verbose` - Show progress for each ballot

**Example**:
```bash
# Sync all new operations
did-char sync

# Output:
# Syncing from ballot 42 to 100...
# Processed 3 operations
# - CREATE did:char:EiDahaOGH... (ballot 42)
# - UPDATE did:char:EiDahaOGH... (ballot 45)
# - CREATE did:char:EiBbcdef... (ballot 50)

# Verbose sync
did-char sync --verbose
# Shows detailed processing for each operation

# Sync specific range
did-char sync --from 40 --to 60
```

---

### status

Show CLI and database status.

```bash
did-char status
```

**Example**:
```bash
did-char status

# Output:
Configuration:
  CHAR Node: 100.67.0.7:18443
  App Domain: did-char-domain
  Database: ./did-char.db

Database Status:
  Total DIDs: 5
  Active DIDs: 4
  Deactivated DIDs: 1
  Last Synced Ballot: 99
  Total Operations: 12

Recent Activity:
  Ballot 95: UPDATE did:char:EiDahaOGH... (2 mins ago)
  Ballot 90: CREATE did:char:EiBbcdef... (5 mins ago)
  Ballot 85: UPDATE did:char:EiCcccc... (8 mins ago)
```

---

### history

Show operation history for a DID.

```bash
did-char history <did> [options]
```

**Arguments**:
- `<did>` - The DID to show history for

**Options**:
- `--format <json|table>` - Output format (default: table)
- `--limit <n>` - Show only last N operations

**Example**:
```bash
did-char history did:char:EiDahaOGH...

# Output (table):
Ballot | Operation   | Timestamp           | Changes
-------|-------------|---------------------|---------------------------
42     | CREATE      | 2025-12-07 10:00:00 | Initial creation
45     | UPDATE      | 2025-12-07 10:05:00 | Added key-2
50     | UPDATE      | 2025-12-07 10:10:00 | Added service endpoint
55     | UPDATE      | 2025-12-07 10:15:00 | Removed key-1

# JSON format
did-char history did:char:EiDahaOGH... --format json
```

---

## Demo Workflow

Quick demo using the generator commands:

```bash
# 1. Create a DID
did-char create --verbose
# Created: did:char:EiDahaOGH-liLLdDtTxEAdc8i-cfCz-WUcQdRJheMVNn3A

# 2. Generate a random key
did-char generate-key --output demo-key.jwk

# 3. Add the key to the DID
did-char update did:char:EiDahaOGH... --add-public-key demo-key.jwk

# 4. Generate a random service
did-char generate-service --output demo-service.json

# 5. Add the service to the DID
did-char update did:char:EiDahaOGH... --add-service "$(cat demo-service.json)"

# 6. Resolve and see the updates
did-char resolve did:char:EiDahaOGH...

# 7. Check history
did-char history did:char:EiDahaOGH...
```

---

## Global Options

Available for all commands:

- `--config <path>` - Path to config file (default: `./config.yaml`)
- `--help` - Show help for command
- `--version` - Show version information

## Exit Codes

- `0` - Success
- `1` - General error
- `2` - Configuration error
- `3` - CHAR RPC error
- `4` - Database error
- `5` - Key file error
- `6` - Validation error

## Key File Structure

Example `did_char_EiDahaOGH-liLLdDtTxEAdc8i-cfCz-WUcQdRJheMVNn3A.json`:

```json
{
  "did": "did:char:EiDahaOGH-liLLdDtTxEAdc8i-cfCz-WUcQdRJheMVNn3A",
  "updateKey": {
    "kty": "EC",
    "crv": "secp256k1",
    "x": "W4EgWNd8oeZAhLjzcqUTE2gUCL7-MpgH_WvZQjnJWwI",
    "y": "n0fMCY5-8w7bvPLH5SvKnfKL2F9jAnmj3bBqK0KhfJg",
    "d": "TQ_HyLwKH4PQPKKmYHVpq8_QyWnR4J-x2C8fL9Rh3zE"
  },
  "recoveryKey": {
    "kty": "EC",
    "crv": "secp256k1",
    "x": "FvlMjqKr_xS5VWHQsI2F3rZR9Wv2VTn3xE5dN9hQ7B0",
    "y": "y2Nx-E3r_g4F5Wg8vN3pR9QhL2xZ5jT7nK3mF8gQ6A",
    "d": "K3mH9pQ4vR5tZ7nF2gL8xJ5wN3rE9hT6yM2bQ8fV4C"
  },
  "nextUpdateCommitment": "QmZ4tDuvesekSs4qM5ZBKpXVBPd62A3pPMvPMZKC7GWB",
  "nextRecoveryCommitment": "QmXA8F2uEwRt5Qgvk7P2mN9hFzKdC3pLvH6sM8fZ9QWE",
  "createdAtBallot": 42,
  "lastOperationBallot": 55
}
```

**Security Note**: Keep key files secure. They contain private keys that control the DID.

## Tips

1. **Backup key files**: Loss means permanent loss of DID control
2. **Wait for confirmation**: Operations aren't final until ballot confirms
3. **Use --verbose**: When debugging, shows detailed operation flow
4. **Use generators for demos**: `generate-key` and `generate-service` for quick testing
5. **Sync regularly**: Run `did-char sync` to stay up-to-date
6. **Check status**: Use `did-char status` to verify configuration
