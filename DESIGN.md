# DID-CHAR Design Document

## Architecture Overview

```
┌──────────────────────────────────────────────────────────┐
│                   CLI Tool (Go)                          │
│                                                          │
│  - Create: Generate DID + keys → write to file          │
│  - Update: Read keys from file → submit → update file   │
│  - Resolve: Query CHAR → sync → return current state    │
│  - Deactivate: Read keys → submit → mark deactivated    │
└──────────────────────────────────────────────────────────┘
           ↓                              ↑
    Write Operations              Read Operations
           ↓                              ↑
┌──────────────────────┐      ┌──────────────────────────┐
│   Key Files          │      │   CHAR RPC Client        │
│                      │      │                          │
│  did_char_<did>.json │      │  - addbambookv           │
│  - updateKey         │      │  - getreferendumdecis... │
│  - recoveryKey       │      │  - Poll until confirmed  │
│  - commitments       │      │                          │
│  (updated per op)    │      │                          │
└──────────────────────┘      └──────────────────────────┘
                                       ↓
           ┌───────────────────────────┴─────────┐
           ↓                                     ↑
┌──────────────────────┐              ┌─────────────────────┐
│   SQLite Database    │              │  CHAR Node          │
│                      │              │  (100.67.0.7:18443) │
│  - DID states        │              │                     │
│  - Operation history │              │  - Single bond      │
│  - Sync metadata     │              │  - Always leader    │
└──────────────────────┘              └─────────────────────┘
```

## Core Concepts from Sidetree

### Self-Certifying DID URIs

```
did:char:EiDahaOGH-liLLdDtTxEAdc8i-cfCz-WUcQdRJheMVNn3A
         └─────────────────┬────────────────────────┘
                     DID Suffix
            Base64URL(SHA256(initial_state))
```

The DID suffix is cryptographically derived from the initial state, making it:
- **Self-certifying**: Anyone can verify the DID matches its initial state
- **Content-addressable**: The suffix IS the hash of the content
- **Tamper-proof**: Cannot change initial state without changing the DID

### Commitment/Reveal Scheme

Prevents front-running and unauthorized operations through two-level hashing:

**Update Key Protection**:
```
updateKey (private)
    ↓ Hash
revealValue = Hash(updateKey)
    ↓ Hash
commitment = Hash(revealValue)
    ↓
Stored in DID state
```

When updating:
1. Provide `revealValue` in the operation
2. Verifier checks: `Hash(revealValue) == stored_commitment`
3. Verifier checks signature with revealed `updateKey`
4. New commitment provided for next update

**Recovery Key Protection**: Same two-level scheme for recovery operations

### Four Operation Types

#### 1. CREATE
- Generates new DID with initial state
- Includes initial public keys and service endpoints
- Provides initial update and recovery commitments
- DID suffix computed from this operation

#### 2. UPDATE
- Modifies DID document (add/remove keys, change services)
- **Requires**: Reveal value matching current update commitment
- **Requires**: Signature from revealed update key
- **Provides**: New update commitment for next operation
- Uses JSON patches for delta changes

#### 3. RECOVER
- Replaces entire DID state using recovery key
- Used when update keys are compromised
- **Requires**: Reveal value matching current recovery commitment
- **Requires**: Signature from revealed recovery key
- **Provides**: New update AND recovery commitments

#### 4. DEACTIVATE
- Permanently disables the DID (irreversible)
- **Requires**: Reveal value matching current recovery commitment
- **Requires**: Signature from revealed recovery key
- Sets DID status to "deactivated" permanently
- No further operations possible

## CHAR Integration

### Referendum Voting Mechanism

CHAR uses a ballot-based consensus system:

1. **App Registration**: One-time setup of app domain
2. **Ballot Numbers**: Sequential integers (0, 1, 2, 3, ...)
3. **Referendum Votes**: Submit data payloads via `addbambookv`
4. **Leader Selection**: Deterministic selection picks winning vote
5. **Decision Rolls**: Winning votes gossiped via Bamboo KV
6. **Attestation**: Bonded participants attest to Bitcoin

### Key RPC Commands

**addbambookv** - Submit a vote
```json
addbambookv '[{"<app_preimage_hex>":"<payload_hex>"}]' true

Parameters:
- app_preimage_hex: Unhashed app domain identifier
- payload_hex: Your DID operation encoded as hex
- slotize: true = auto-format for slot system

Returns:
{
  "<app_preimage_hex>": true  // Success indicator
}
```

**getreferendumdecisionroll** - Query ballot result
```json
getreferendumdecisionroll "<domain_hex>" <ballot_number> 1

Parameters:
- domain_hex: App domain (unhashed)
- ballot_number: Sequential ballot number
- verbosity: 0=minimal, 1=detailed, 2=provable

Returns:
{
  "domain_hash": "...",
  "ballot_number": 42,
  "leader": "txid...",
  "leader_is_mine": true,
  "found": true,           // ← Key: Is this ballot confirmed?
  "decision_roll": {
    "data": "hex...",      // ← The winning payload
    "roll_hash": "...",
    ...
  }
}
```

### Single Bond Behavior

**Important**: Since there's only one bond (ours), we're always the leader:
- `leader_is_mine` will always be `true`
- We still need to wait for `found: true`
- The network needs time to confirm the decision roll
- Must poll repeatedly until ballot is confirmed

### Write Flow with Polling

```
1. Encode DID operation as hex payload

2. Determine next ballot number
   - Query last confirmed ballot
   - Increment by 1

3. Submit vote
   result = addbambookv([{app_preimage: payload}], true)

4. Poll until confirmed (CRITICAL STEP)
   loop:
     roll = getreferendumdecisionroll(app_preimage, ballot_num, 1)
     if roll.found:
       break
     sleep(100ms)
     // Retry up to N times or timeout

5. Verify payload matches what we submitted

6. Update local state (SQLite + key file)
```

## Data Formats

### Operation Payload Structure

Binary format for each referendum vote:

```
┌─────────────────────────────────────────────┐
│ Version (1 byte)           │ 0x01           │
├─────────────────────────────────────────────┤
│ Operation Type (1 byte)    │ 0x01=CREATE    │
│                            │ 0x02=UPDATE    │
│                            │ 0x03=RECOVER   │
│                            │ 0x04=DEACTIVATE│
├─────────────────────────────────────────────┤
│ DID Suffix Length (varint) │ N bytes        │
├─────────────────────────────────────────────┤
│ DID Suffix                 │ variable       │
├─────────────────────────────────────────────┤
│ Operation JSON Length      │ varint         │
├─────────────────────────────────────────────┤
│ Operation JSON (UTF-8)     │ variable       │
└─────────────────────────────────────────────┘
```

### Key File Format

File name: `did_char_<full_did_suffix>.json`

```json
{
  "did": "did:char:EiDahaOGH-liLLdDtTxEAdc8i-cfCz-WUcQdRJheMVNn3A",
  "updateKey": {
    "kty": "EC",
    "crv": "secp256k1",
    "x": "base64url...",
    "y": "base64url...",
    "d": "base64url..."
  },
  "recoveryKey": {
    "kty": "EC",
    "crv": "secp256k1",
    "x": "base64url...",
    "y": "base64url...",
    "d": "base64url..."
  },
  "nextUpdateCommitment": "Qm...",
  "nextRecoveryCommitment": "Qm...",
  "createdAtBallot": 42,
  "lastOperationBallot": 45
}
```

**Updated after each operation** to contain new commitments.

### SQLite Schema

```sql
CREATE TABLE dids (
    did TEXT PRIMARY KEY,
    status TEXT NOT NULL,              -- 'active' | 'deactivated'
    document TEXT NOT NULL,            -- JSON DID document
    update_commitment TEXT,            -- Current update commitment
    recovery_commitment TEXT,          -- Current recovery commitment
    created_at_ballot INTEGER NOT NULL,
    last_operation_ballot INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE operations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    did TEXT NOT NULL,
    ballot_number INTEGER NOT NULL,
    operation_type TEXT NOT NULL,      -- 'create'|'update'|'recover'|'deactivate'
    operation_data TEXT NOT NULL,      -- JSON operation details
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (did) REFERENCES dids(did),
    UNIQUE(ballot_number)              -- One operation per ballot
);

CREATE TABLE sync_state (
    key TEXT PRIMARY KEY,              -- e.g., 'last_synced_ballot'
    value TEXT NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_operations_ballot ON operations(ballot_number);
CREATE INDEX idx_operations_did ON operations(did);
```

## State Machine

```
          CREATE
            ↓
    ┌───────────────┐
    │    ACTIVE     │ ←─┐
    └───────────────┘   │
        ↓       ↑       │
      UPDATE  RECOVER   │
        ↓       ↓       │
        └───────────────┘
            ↓
       DEACTIVATE
            ↓
    ┌───────────────┐
    │  DEACTIVATED  │ (terminal)
    └───────────────┘
```

### Validation Rules

**CREATE**:
- DID must not already exist
- Initial state must be well-formed
- Commitments must be valid hashes

**UPDATE**:
- DID must exist and status = 'active'
- `Hash(revealValue) == current_update_commitment`
- Signature must verify with revealed updateKey
- Provides new update commitment

**RECOVER**:
- DID must exist and status = 'active'
- `Hash(revealValue) == current_recovery_commitment`
- Signature must verify with revealed recoveryKey
- Provides new update AND recovery commitments

**DEACTIVATE**:
- DID must exist and status = 'active'
- `Hash(revealValue) == current_recovery_commitment`
- Signature must verify with revealed recoveryKey
- No further operations allowed after this

## Ballot Number Allocation

Since we're the only bond and always the leader:

**Strategy**: Sequential allocation
1. Query `sync_state` table for `last_processed_ballot`
2. Next ballot = `last_processed_ballot + 1`
3. Submit operation to that ballot
4. Poll until `found: true`
5. Update `last_processed_ballot`

**Conflict Handling**: Not needed (single operator)

## Security Considerations

1. **Key File Security**: Files contain private keys, must be secured
2. **Commitment Chain**: Breaking the chain bricks the DID
3. **No Key Rotation in CREATE**: Update/recovery keys set at creation
4. **Deactivation Finality**: No recovery after deactivation
5. **Single Bond Risk**: Centralization, but acceptable for PoC

## Open Questions

1. How long should we poll before timing out?
2. Should we retry failed submissions?
3. How to handle if another bond appears?
4. Sync strategy: on-demand or continuous?

## Performance Considerations

- **Latency**: Each operation requires polling confirmation (~seconds)
- **Storage**: SQLite scales to thousands of DIDs easily
- **Network**: RPC calls to CHAR node are fast (local network)
- **Bottleneck**: Waiting for CHAR ballot confirmation
