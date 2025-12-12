# Threshold DID Design: Multi-Signature Control for did:char

## Overview

Enable DIDs to be controlled by M-of-N threshold signatures, where M signatures from N designated controllers are required to authorize operations (update, recover, deactivate).

### Use Cases

1. **Organizational DIDs**: A company DID requiring 3-of-5 executives to approve changes
2. **DAO DIDs**: Decentralized governance with 6-of-9 board members
3. **Custodial Recovery**: 2-of-3 where user + 2 backup guardians can recover
4. **High-Security DIDs**: Requiring multiple hardware keys for critical identity

---

## Current Single-Key Model

```
CREATE:
  └── commitment = hash(hash(updateKey))

UPDATE:
  ├── revealValue = hash(updateKey)
  ├── signedData = sign(deltaHash, updateKey)
  └── Verify: hash(revealValue) == commitment
              verify(signedData, updateKey)
              hash(updateKey) == revealValue
```

**Problem**: Single point of failure. One compromised key = compromised DID.

---

## Merkle Tree Commitment Scheme (Recommended)

Instead of storing N separate commitments, we store a single **Merkle root** that commits to all N controller keys. Each controller proves membership via a Merkle proof during operations.

### Tree Construction

```
Controller Keys: pk_0, pk_1, pk_2, pk_3, pk_4 (5 controllers, 3-of-5 threshold)

Leaves (double-hashed for reveal protection):
    L_0 = H(H(pk_0))
    L_1 = H(H(pk_1))
    L_2 = H(H(pk_2))
    L_3 = H(H(pk_3))
    L_4 = H(H(pk_4))

Tree Structure:
    L_0      L_1      L_2      L_3      L_4     [pad]
      \      /          \      /          \      /
      H(0,1)            H(2,3)            H(4,pad)
          \              /                   |
           \            /                    |
            H(0,1,2,3)                    H(4,pad)
                 \                          /
                  \                        /
                   ----  MERKLE_ROOT  ----

On-chain storage:
  - updateCommitment = MERKLE_ROOT (32 bytes)
  - updateThreshold = 3
  - updateControllerCount = 5
```

### Why Double Hash?

```
Leaf = H(H(pk))     ← Stored in tree
Reveal = H(pk)      ← Revealed during operation (not the actual key)
Verify: H(reveal) == leaf
```

The reveal value `H(pk)` doesn't expose the actual public key bytes, maintaining the same security properties as the single-key scheme.

### Merkle Proof Structure

Each controller's proof contains the sibling hashes needed to reconstruct the root:

```
Controller 2 proving membership:

            ROOT
           /    \
      H(0,1,2,3) H(4,pad)  ← need H(4,pad)
         /    \
    H(0,1)   H(2,3)        ← need H(0,1)
              / \
           L_2  L_3        ← need L_3 (sibling)
            ↑
     proving this leaf

Proof for index 2: [L_3, H(0,1), H(4,pad)]
Path: left, right, left (encoded in index bits)
```

### Storage Efficiency

| Controllers (N) | Separate Commitments | Merkle Tree |
|-----------------|---------------------|-------------|
| 5 | 160 bytes | 32 bytes root |
| 9 | 288 bytes | 32 bytes root |
| 21 | 672 bytes | 32 bytes root |
| 99 | 3,168 bytes | 32 bytes root |

**Trade-off**: Merkle proofs add ~32 bytes per tree level to each operation, but on-chain storage is constant regardless of N.


## Detailed Design: Merkle Tree Multi-Sig

### Data Structures

```go
// MaxControllers is the maximum number of controllers allowed
const MaxControllers = 99

// MaxMerkleDepth is log2(MaxControllers) rounded up
const MaxMerkleDepth = 7  // 2^7 = 128 > 99

// ThresholdConfig defines M-of-N control for a DID
type ThresholdConfig struct {
    Threshold  int `json:"threshold"`  // M (required signatures), must be >= 1
    Total      int `json:"total"`      // N (total controllers), must be <= 99
}

// MerkleProof contains the sibling hashes to prove leaf membership
type MerkleProof struct {
    Siblings []string `json:"siblings"` // Sibling hashes from leaf to root
    Index    int      `json:"index"`    // Leaf index (determines left/right path)
}

// CreateOperation with Merkle tree commitments
type CreateOperation struct {
    Type                    string           `json:"type"`
    InitialDocument         *Document        `json:"initialDocument"`
    UpdateThreshold         int              `json:"updateThreshold"`         // M for updates
    UpdateControllerCount   int              `json:"updateControllerCount"`   // N for updates
    UpdateCommitment        string           `json:"updateCommitment"`        // Merkle root
    RecoveryThreshold       int              `json:"recoveryThreshold"`       // M for recovery
    RecoveryControllerCount int              `json:"recoveryControllerCount"` // N for recovery
    RecoveryCommitment      string           `json:"recoveryCommitment"`      // Merkle root
}

// ControllerReveal is one controller's signature + Merkle proof
type ControllerReveal struct {
    Index       int          `json:"index"`       // Controller index (0 to N-1)
    RevealValue string       `json:"revealValue"` // H(publicKey) - the reveal
    PublicKey   *keys.JWK    `json:"publicKey"`   // The actual public key
    MerkleProof MerkleProof  `json:"merkleProof"` // Proof of inclusion in tree
    Signature   string       `json:"signature"`   // JWS over deltaHash
}

// UpdateOperation with M controller reveals
type UpdateOperation struct {
    Type      string             `json:"type"`
    DIDSuffix string             `json:"didSuffix"`
    Reveals   []ControllerReveal `json:"reveals"` // M controller reveals with proofs
    Delta     *Delta             `json:"delta"`
}
```

### DID Document Extension

Public keys are NOT stored in the document - only commitments are stored on-chain for privacy. The document only reflects the threshold configuration:

```json
{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:char:abc123",
  "controller": {
    "mode": "threshold",
    "updateThreshold": 3,
    "updateControllerCount": 5,
    "recoveryThreshold": 4,
    "recoveryControllerCount": 5
  },
  "verificationMethod": [...],
  "service": [...]
}
```

The actual commitments are stored in the `did_controllers` table (see Storage Schema below).

### Storage Schema

```sql
-- DIDs table with Merkle root commitments
-- No separate controller table needed - just store the roots!
ALTER TABLE dids ADD COLUMN update_threshold INTEGER DEFAULT 1;
ALTER TABLE dids ADD COLUMN update_controller_count INTEGER DEFAULT 1;
-- update_commitment already exists (now stores Merkle root)
ALTER TABLE dids ADD COLUMN recovery_threshold INTEGER DEFAULT 1;
ALTER TABLE dids ADD COLUMN recovery_controller_count INTEGER DEFAULT 1;
-- recovery_commitment already exists (now stores Merkle root)
```

Note: The Merkle root replaces N separate commitments. Controllers must retain their own proofs off-chain.

### Verification Flow

```go
func (p *Processor) processThresholdUpdate(did string, op UpdateOperation) error {
    // 1. Load DID and threshold config
    didRecord, _ := p.store.GetDID(did)
    threshold := didRecord.UpdateThreshold
    controllerCount := didRecord.UpdateControllerCount
    merkleRoot := didRecord.UpdateCommitment

    // 2. Verify we have enough reveals
    if len(op.Reveals) < threshold {
        return fmt.Errorf("insufficient reveals: got %d, need %d",
            len(op.Reveals), threshold)
    }

    // 3. Compute delta hash once
    deltaHash := computeDeltaHash(op.Delta)

    // 4. Verify each reveal
    validCount := 0
    usedIndices := make(map[int]bool)

    for _, reveal := range op.Reveals {
        // Prevent duplicate controller usage
        if usedIndices[reveal.Index] {
            return fmt.Errorf("duplicate controller index: %d", reveal.Index)
        }
        usedIndices[reveal.Index] = true

        // Validate index is in range
        if reveal.Index < 0 || reveal.Index >= controllerCount {
            return fmt.Errorf("controller index out of range: %d", reveal.Index)
        }

        // Step A: Verify H(publicKey) == revealValue
        computedReveal := hash(canonicalize(reveal.PublicKey))
        if computedReveal != reveal.RevealValue {
            continue // Public key doesn't match reveal
        }

        // Step B: Compute leaf = H(revealValue) = H(H(publicKey))
        leaf := hash(reveal.RevealValue)

        // Step C: Verify Merkle proof: leaf + proof => merkleRoot
        if !verifyMerkleProof(leaf, reveal.MerkleProof, merkleRoot) {
            continue // Merkle proof invalid
        }

        // Step D: Verify signature over deltaHash
        if err := verifySignature(reveal.Signature, deltaHash, reveal.PublicKey); err != nil {
            continue // Signature invalid
        }

        validCount++
    }

    // 5. Check threshold met
    if validCount < threshold {
        return fmt.Errorf("threshold not met: %d valid of %d required",
            validCount, threshold)
    }

    // 6. Apply the update
    return p.applyDelta(did, op.Delta)
}

// verifyMerkleProof verifies that a leaf is in the tree with the given root
func verifyMerkleProof(leaf string, proof MerkleProof, expectedRoot string) bool {
    current := leaf
    index := proof.Index

    for _, sibling := range proof.Siblings {
        if index % 2 == 0 {
            // Current is left child, sibling is right
            current = hash(current + sibling)
        } else {
            // Current is right child, sibling is left
            current = hash(sibling + current)
        }
        index = index / 2
    }

    return current == expectedRoot
}
```

### Merkle Tree Construction Utilities

```go
// BuildMerkleTree constructs a Merkle tree from controller public keys
// Returns the root and all proofs for each controller
func BuildMerkleTree(publicKeys []*keys.JWK) (root string, proofs []MerkleProof, err error) {
    n := len(publicKeys)
    if n == 0 {
        return "", nil, fmt.Errorf("no public keys provided")
    }
    if n > MaxControllers {
        return "", nil, fmt.Errorf("too many controllers: %d > %d", n, MaxControllers)
    }

    // Compute leaves: H(H(pk)) for each public key
    leaves := make([]string, n)
    for i, pk := range publicKeys {
        pkJSON, _ := json.Marshal(pk)
        reveal := hash(pkJSON)        // H(pk)
        leaves[i] = hash(reveal)      // H(H(pk))
    }

    // Pad to power of 2
    treeSize := nextPowerOf2(n)
    for len(leaves) < treeSize {
        leaves = append(leaves, hash(""))  // Empty leaf padding
    }

    // Build tree bottom-up, collecting proofs
    proofs = make([]MerkleProof, n)
    for i := 0; i < n; i++ {
        proofs[i] = MerkleProof{Index: i, Siblings: []string{}}
    }

    currentLevel := leaves
    for len(currentLevel) > 1 {
        nextLevel := make([]string, len(currentLevel)/2)

        for i := 0; i < len(currentLevel); i += 2 {
            left := currentLevel[i]
            right := currentLevel[i+1]
            nextLevel[i/2] = hash(left + right)

            // Add sibling to proofs for original leaves in this subtree
            for j := 0; j < n; j++ {
                levelIndex := proofs[j].Index >> (len(proofs[j].Siblings))
                if levelIndex/2 == i/2 {
                    if levelIndex%2 == 0 {
                        proofs[j].Siblings = append(proofs[j].Siblings, right)
                    } else {
                        proofs[j].Siblings = append(proofs[j].Siblings, left)
                    }
                }
            }
        }
        currentLevel = nextLevel
    }

    return currentLevel[0], proofs, nil
}

func nextPowerOf2(n int) int {
    p := 1
    for p < n {
        p *= 2
    }
    return p
}
```

### Example: Complete Update Operation

**Scenario**: 3-of-5 threshold DID, controllers 0, 2, and 4 sign an update.

```json
{
  "type": "update",
  "didSuffix": "EiD_abc123...",
  "reveals": [
    {
      "index": 0,
      "revealValue": "H(pk_0)_base64url",
      "publicKey": {
        "kty": "EC",
        "crv": "P-256",
        "x": "...",
        "y": "..."
      },
      "merkleProof": {
        "index": 0,
        "siblings": [
          "H(H(pk_1))",
          "H(H(pk_2), H(pk_3))",
          "H(H(pk_4), pad)"
        ]
      },
      "signature": "eyJhbGciOiJFUzI1NiJ9.eyJkZWx0YUhhc2giOiIuLi4ifQ.sig0"
    },
    {
      "index": 2,
      "revealValue": "H(pk_2)_base64url",
      "publicKey": {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "..."
      },
      "merkleProof": {
        "index": 2,
        "siblings": [
          "H(H(pk_3))",
          "H(H(pk_0), H(pk_1))",
          "H(H(pk_4), pad)"
        ]
      },
      "signature": "eyJhbGciOiJFZERTQSJ9.eyJkZWx0YUhhc2giOiIuLi4ifQ.sig2"
    },
    {
      "index": 4,
      "revealValue": "H(pk_4)_base64url",
      "publicKey": {
        "kty": "OKP",
        "crv": "BLS12-381-G1",
        "x": "..."
      },
      "merkleProof": {
        "index": 4,
        "siblings": [
          "H(pad)",
          "H(H(pk_0,1), H(pk_2,3))"
        ]
      },
      "signature": "eyJhbGciOiJCTFMifQ.eyJkZWx0YUhhc2giOiIuLi4ifQ.sig4"
    }
  ],
  "delta": {
    "patches": [
      {
        "action": "add-services",
        "services": [{"id": "#api", "type": "API", "serviceEndpoint": "https://api.example.com"}]
      }
    ],
    "updateCommitment": "NEW_MERKLE_ROOT_after_key_rotation"
  }
}
```

---

## Key Rotation in Threshold Model

With Merkle trees, **any change to the controller set requires a new Merkle root**. This is a feature, not a bug: it provides a clean audit trail and ensures all controllers must coordinate for changes.

### Rotating a Single Controller's Key

When controller #3 rotates their key, the organization must:
1. Generate new key for controller #3
2. Rebuild the entire Merkle tree with the new leaf
3. Distribute new proofs to all controllers
4. Submit update with M signatures and the new Merkle root

```json
{
  "type": "update",
  "didSuffix": "abc123",
  "reveals": [
    {
      "index": 0,
      "revealValue": "H(pk_0)",
      "publicKey": { "kty": "EC", ... },
      "merkleProof": { "index": 0, "siblings": ["...", "..."] },
      "signature": "..."
    },
    {
      "index": 2,
      "revealValue": "H(pk_2)",
      "publicKey": { "kty": "OKP", ... },
      "merkleProof": { "index": 2, "siblings": ["...", "..."] },
      "signature": "..."
    },
    {
      "index": 3,
      "revealValue": "H(pk_3_OLD)",
      "publicKey": { "kty": "EC", ... },
      "merkleProof": { "index": 3, "siblings": ["...", "..."] },
      "signature": "..."
    }
  ],
  "delta": {
    "patches": [],
    "updateCommitment": "NEW_MERKLE_ROOT_with_pk_3_NEW"
  }
}
```

**Note**: Controller #3 signs with their OLD key to authorize the rotation to their NEW key. After this update, proofs using the old tree are invalid.

### Adding/Removing Controllers

Changing the controller count also requires rebuilding the tree:

```json
{
  "delta": {
    "patches": [],
    "updateCommitment": "NEW_MERKLE_ROOT",
    "updateThreshold": 4,
    "updateControllerCount": 7
  }
}
```

The new Merkle root is computed from the new set of 7 controller keys. Removed controllers simply aren't included in the new tree.

---

## Recovery Considerations

### Separate Recovery Threshold

Recovery should have its own threshold (often higher for security):

```
Update: 3-of-5 (routine operations)
Recovery: 4-of-5 (emergency full reset)
```

### Recovery Operation

```json
{
  "type": "recover",
  "didSuffix": "abc123",
  "reveals": [
    // M recovery controller reveals
  ],
  "delta": {
    "patches": [...],
    "newUpdateCommitments": [...],   // Complete reset of update controllers
    "newRecoveryCommitments": [...]  // Can also rotate recovery controllers
  }
}
```

---

## Security Considerations

### 1. Replay Protection

Each signature must be over a unique message. Include:
- DID suffix
- Delta hash
- Operation counter or timestamp

```go
message := hash(didSuffix || deltaHash || operationCount)
```

### 2. Rogue Key Attack (BLS Aggregation)

If using BLS aggregate signatures, require proof-of-possession for each key during setup to prevent rogue key attacks.

### 3. Threshold Selection

Recommendations:
- **Minimum**: M > N/2 (simple majority)
- **Conservative**: M >= 2N/3 (supermajority)
- **Maximum Security**: M = N (unanimous)

### 4. Controller Key Security

Each controller should:
- Use different key storage (hardware wallets, HSMs)
- Be geographically distributed
- Have independent compromise detection

---

## Migration Path

### Phase 1: Backward Compatible

- Single-key DIDs continue to work unchanged
- `thresholdConfig` is optional (defaults to 1-of-1)
- Existing DIDs can upgrade to threshold via recovery operation

### Phase 2: New Threshold DIDs

- Create new DIDs with threshold from the start
- Full M-of-N support for update and recovery

### Phase 3: BLS Aggregation (Optional)

- Add aggregate signature mode for all-BLS controller sets
- Reduces operation size when M is large

---

## API Examples

### Creating a Threshold DID

```go
// Create 3-of-5 threshold DID
controllers := []ControllerConfig{
    {Key: key1, Algorithm: "ES256"},
    {Key: key2, Algorithm: "ES256"},
    {Key: key3, Algorithm: "EdDSA"},
    {Key: key4, Algorithm: "EdDSA"},
    {Key: key5, Algorithm: "BLS"},
}

did, err := CreateThresholdDID(CreateThresholdRequest{
    UpdateThreshold:   3,
    UpdateControllers: controllers,
    RecoveryThreshold: 4,
    RecoveryControllers: controllers,  // Can be different set
    Document: initialDoc,
})
```

### Updating a Threshold DID

```go
// Collect M signatures from controllers
reveals := []ControllerReveal{}

// Controller 0 signs
reveals = append(reveals, SignAsController(key0, 0, delta))

// Controller 2 signs
reveals = append(reveals, SignAsController(key2, 2, delta))

// Controller 4 signs
reveals = append(reveals, SignAsController(key4, 4, delta))

// Submit update with 3 reveals
err := UpdateThresholdDID(UpdateThresholdRequest{
    DID:     "did:char:abc123",
    Reveals: reveals,
    Delta:   delta,
})
```

---

## Design Decisions

1. **Only commitments stored on-chain** - Public keys are revealed only during operations, not stored in the DID document. This provides better privacy and smaller documents.

2. **Maximum 99 controllers** - Practical limit for coordination and ballot size.

3. **No weighted voting** - Simple M-of-N threshold only. Each controller has equal weight.

4. **Recovery handles compromise** - If a controller key is compromised, the recovery operation (with its separate, typically higher threshold) is the mechanism to reset the update controllers.

---

## Summary

| Aspect | Single-Key (Current) | Threshold (Proposed) |
|--------|---------------------|---------------------|
| Control | 1 key | M-of-N keys (max 99 controllers) |
| Algorithms | Any | Mixed - each controller chooses |
| On-chain Storage | 1 commitment (32 bytes) | 1 Merkle root (32 bytes) |
| Operation Size | 1 signature | M signatures + M Merkle proofs |
| Proof Size | N/A | ~log₂(N) × 32 bytes per reveal |
| Rotation | Full key rotation | Rebuild tree, new root |
| Recovery | 1 recovery key | M-of-N recovery keys (separate tree) |
| Privacy | Key revealed on update | Keys revealed only during ops |

**Implementation**: Merkle tree commitment scheme - stores single 32-byte root regardless of N controllers, supports mixed algorithms, each operation includes M reveals with Merkle proofs.

### Implementation Files

| File | Purpose |
|------|---------|
| `pkg/did/merkle.go` | **NEW** - Merkle tree construction and verification |
| `pkg/did/operations.go` | Update CreateOperation, UpdateOperation with threshold fields |
| `pkg/did/processor.go` | Add processThresholdUpdate with Merkle verification |
| `pkg/storage/store.go` | Add threshold/controller count columns |
| `pkg/did/threshold.go` | **NEW** - Threshold DID creation and signing helpers |

---

## Appendix A: Comprehensive Analysis of Threshold Signature Approaches

This section analyzes various cryptographic approaches for implementing M-of-N threshold control and evaluates whether the Merkle tree approach is optimal for did:char.

### Approach Comparison Matrix

| Approach | On-Chain Storage | Operation Size | Setup Complexity | Algorithm Support | Key Never Reconstructed | Rounds |
|----------|------------------|----------------|------------------|-------------------|------------------------|--------|
| **Merkle Tree + M Signatures** | O(1) - 32 bytes | O(M × log N) | Simple | Any mix | Yes | 1 (async) |
| **BLS Threshold (TBLS)** | O(1) - 48 bytes | O(1) - 96 bytes | Complex DKG | BLS only | Yes* | 1 |
| **FROST (Schnorr Threshold)** | O(1) - 32 bytes | O(1) - 64 bytes | Medium DKG | Schnorr only | Yes | 2 |
| **Shamir Secret Sharing** | O(1) - 32 bytes | O(1) - varies | Simple | Any | **No** | 1 |
| **On-chain Multi-sig** | O(N) - 32N bytes | O(M) - M sigs | Simple | Any | Yes | 1 (async) |
| **MPC-TSS** | O(1) | O(1) | Very Complex | ECDSA/EdDSA | Yes | Multiple |

### Detailed Analysis of Each Approach

#### 1. Shamir Secret Sharing (SSS) - NOT RECOMMENDED

**How it works**: A secret key is split into N shares using polynomial interpolation. Any M shares can reconstruct the original key.

**Critical flaw**: The key must be reconstructed at signing time, creating a single point of failure.

> "SSS has a critical vulnerability: someone must reconstruct the full private key to sign, even momentarily. This reconstruction creates a window where the key exists in one place and could be exfiltrated." - [MPC Explainer](https://www.llamarisk.com/research/mpc-explainer)

**Why not for did:char**:
- Contradicts our goal of never having a single point of compromise
- Reconstruction moment is vulnerable to memory attacks
- Whoever reconstructs could steal the key

#### 2. BLS Threshold Signatures (TBLS)

**How it works**: Uses Distributed Key Generation (DKG) to create key shares. Each participant signs with their share, and partial signatures are aggregated into a single final signature. The full key never exists.

**Advantages**:
- Non-interactive: signatures can be collected asynchronously
- Constant-size output regardless of M or N
- Key never reconstructed (unlike Shamir)
- Deterministic - no random nonces needed

**Disadvantages**:
- Requires all controllers to use BLS keys (no algorithm mixing)
- ~5x slower verification due to pairing operations
- DKG is complex and has known vulnerabilities if not implemented carefully
- Less mature than ECDSA/EdDSA - pairing-based assumptions less studied

> "BLS verification is about 5x costlier than Schnorr and ECDSA... Efficiency-wise, threshold BLS outperforms other threshold signatures in signing, but incurs higher cost during aggregation and verification due to use of pairing." - [Crypto Advance](https://medium.com/cryptoadvance/bls-signatures-better-than-schnorr-5a7fe30ea716)

**Rogue Key Attack**: BLS aggregation is vulnerable to rogue key attacks where an attacker crafts a public key relative to honest parties' keys. Mitigation requires proof-of-possession (PoP) during setup.

> "The rogue public-key attack works when an attacker registers a public key that is crafted relative to another party's key... the attacker can then claim that both it and the victim signed some message." - [Cornell Research](https://rist.tech.cornell.edu/papers/pkreg.pdf)

**Why not default for did:char**:
- Forces all controllers to use BLS (no EC/Ed25519 mixing)
- DKG complexity adds failure modes
- Suitable as an optional optimization for homogeneous BLS controller sets

#### 3. FROST (Flexible Round-Optimized Schnorr Threshold)

**How it works**: Threshold adaptation of Schnorr signatures using DKG. Requires 2 rounds (or 1 with preprocessing). Recently standardized in [RFC 9591](https://datatracker.ietf.org/doc/rfc9591/).

**Advantages**:
- Round-optimized: 2 rounds (or 1 with preprocessing)
- Signature indistinguishable from regular Schnorr
- Key never reconstructed
- Unlimited concurrent signing operations

**Disadvantages**:
- Schnorr-only (no ECDSA, EdDSA, or BLS)
- Requires interactive coordination during signing
- Aborts if any participant misbehaves (not robust)
- Semi-trusted coordinator needed

> "FROST achieves its efficiency improvements in part by allowing the protocol to abort in the presence of a misbehaving participant (who is then identified and excluded from future operations)." - [University of Waterloo](https://crysp.uwaterloo.ca/software/frost/)

**Why not for did:char**:
- Interactive requirement doesn't fit our async ballot model
- Schnorr-only limits algorithm choice
- Coordinator requirement adds complexity

#### 4. MPC-TSS (Multi-Party Computation Threshold Signing)

**How it works**: General MPC protocols applied to threshold signing. Multiple rounds of communication with secret sharing and commitment schemes.

**Advantages**:
- Works with ECDSA (important for Bitcoin/Ethereum compatibility)
- Key never exists in one place
- Established production deployments (custody solutions)

**Disadvantages**:
- Multiple communication rounds required
- Complex implementation with many potential vulnerabilities
- Higher latency
- Recent vulnerabilities discovered in DKG protocols

> "Trail of Bits recently disclosed a vulnerability in the MPC threshold signature scheme that affects the DKG protocol... a single malicious participant can surreptitiously raise the threshold required to reconstruct the shared key." - [Safeheron](https://safeheron.com/blog/dkg-threshold-raising-vulnerability/)

**Why not for did:char**:
- Interactive multi-round protocols don't fit async model
- Implementation complexity and vulnerability surface
- Overkill for our use case

#### 5. On-Chain Multi-sig (N Separate Commitments)

**How it works**: Store N separate commitments on-chain. Require M valid signatures at operation time.

**Advantages**:
- Simplest to implement
- Any algorithm mix supported
- No DKG needed
- Fully async

**Disadvantages**:
- O(N) storage grows with controller count
- 99 controllers = 3,168 bytes of commitments
- Controller rotation requires updating all N commitments

**Why not for did:char**:
- Storage inefficiency at scale
- Our Merkle approach achieves same functionality with O(1) storage

#### 6. Merkle Tree + M Individual Signatures (RECOMMENDED)

**How it works**: Commit to N controller keys via a single Merkle root. Each operation includes M signatures with Merkle proofs of key membership.

**Advantages**:
- **O(1) storage**: 32 bytes regardless of N
- **Algorithm agnostic**: Controllers can use EC, Ed25519, BLS, or mix
- **No DKG**: Each controller generates their own key independently
- **Fully async**: No interactive coordination needed
- **Key never shared**: Each controller maintains their own complete key
- **Simple implementation**: Standard Merkle tree + existing signature verification
- **Accountable**: Each signing controller is identified (unlike aggregated signatures)
- **Robust**: Individual signature failures don't abort the entire operation
- **Post-quantum ready**: Can use hash-based signatures (XMSS/SPHINCS+) for individual keys

**Disadvantages**:
- **O(M × log N) operation size**: Each reveal includes a Merkle proof
- **Key rotation coordination**: Changing any key requires new tree and redistributed proofs
- **No signature aggregation**: M signatures instead of 1 aggregated signature

**Trade-off analysis for did:char**:

For 5 controllers (3-of-5 threshold):
- Merkle proof: ~3 levels × 32 bytes = 96 bytes per reveal
- 3 reveals × (96 bytes proof + ~100 bytes signature + ~100 bytes key) ≈ 888 bytes

For 21 controllers (11-of-21 threshold):
- Merkle proof: ~5 levels × 32 bytes = 160 bytes per reveal
- 11 reveals × (160 bytes + 200 bytes) ≈ 3,960 bytes

For 99 controllers (50-of-99 threshold):
- Merkle proof: ~7 levels × 32 bytes = 224 bytes per reveal
- 50 reveals × (224 bytes + 200 bytes) ≈ 21,200 bytes

This is acceptable given:
1. CHAR ballots can accommodate this size
2. Operations are infrequent (updates are rare)
3. The storage savings (32 bytes vs 3,168 bytes for 99 controllers) matter more for long-term state

### Novel Considerations for DIDs

#### 1. Accountability vs Privacy Trade-off

Traditional multi-sigs expose which parties signed. BLS aggregation hides this. For DIDs:
- **Accountability is often desirable**: Audit trails of who authorized changes
- **Privacy might be wanted**: Hide organizational structure
- **Our choice**: Merkle tree reveals signing controllers (accountable) - matches organizational DID use cases

#### 2. Async-First Design

DIDs operate in an async environment:
- Controllers may be in different timezones
- Hardware keys may be air-gapped
- Coordination happens over days, not seconds

Interactive protocols (FROST, MPC) don't fit this model. Our Merkle approach allows:
1. Coordinator proposes delta
2. Controllers sign independently over hours/days
3. Once M signatures collected, submit operation

#### 3. Mixed Algorithm Support is Critical

Organizations have diverse security requirements:
- CFO uses hardware token with ECDSA
- CTO uses Ed25519 on YubiKey
- Legal team uses BLS for potential future aggregation

Locking to one algorithm (BLS-only for TBLS, Schnorr-only for FROST) reduces flexibility.

#### 4. Recovery as Compromise Handling

Our design separates update (routine) from recovery (emergency). If an update key is compromised:
- Attacker needs M-of-N update keys (hard if threshold is reasonable)
- Legitimate controllers use recovery (higher threshold) to reset update tree

This is simpler than MPC key resharing protocols.

### Hybrid Approach: Future Optimization

For organizations where ALL controllers use BLS keys, we could offer an optional BLS aggregation mode:

```
Standard Mode (recommended):
  - Merkle root commitment
  - M individual signatures + Merkle proofs
  - ~21KB for 50-of-99

BLS Aggregate Mode (optional, BLS-only):
  - Merkle root commitment (still for commitment scheme)
  - 1 aggregated BLS signature
  - ~96 bytes regardless of M
```

This could be a Phase 3 enhancement after the core threshold system is proven.

### Conclusion

The **Merkle Tree + M Individual Signatures** approach is optimal for did:char because:

1. **Storage efficiency**: O(1) commitment storage matches single-key DIDs
2. **Algorithm flexibility**: Critical for real-world organizational adoption
3. **Simplicity**: No DKG, no interactive protocols, no coordinator
4. **Async-native**: Fits CHAR ballot submission model perfectly
5. **Accountability**: Clear audit trail of authorizing controllers
6. **Robustness**: Individual signature failures are recoverable
7. **Security**: No key reconstruction, no shared secrets

The operation size trade-off (KB instead of bytes) is acceptable for:
- Infrequent DID operations
- The storage savings being more important than operation size
- CHAR ballot capacity being sufficient

### References

- [NIST Threshold Cryptography Project](https://csrc.nist.gov/projects/threshold-cryptography)
- [FROST RFC 9591](https://datatracker.ietf.org/doc/rfc9591/)
- [BLS Signatures: Better than Schnorr](https://medium.com/cryptoadvance/bls-signatures-better-than-schnorr-5a7fe30ea716)
- [Merkle Signature Scheme - Wikipedia](https://en.wikipedia.org/wiki/Merkle_signature_scheme)
- [Rogue Key Attack Prevention](https://rist.tech.cornell.edu/papers/pkreg.pdf)
- [MPC Threshold Signing Vulnerabilities](https://safeheron.com/blog/dkg-threshold-raising-vulnerability/)
- [University of Waterloo FROST](https://crysp.uwaterloo.ca/software/frost/)
- [Binance Academy: Threshold Signatures](https://academy.binance.com/en/articles/threshold-signatures-explained)
- [BLS Multi-Signatures with Public-Key Aggregation](https://crypto.stanford.edu/~dabo/pubs/papers/BLSmultisig.html)
- [NIST Threshold BLS Presentation](https://csrc.nist.gov/presentations/2023/mpts2023-day1-talk-threshold-BLS)

---

## Appendix B: Serialization Analysis for Compact Payloads

CHAR data is permanent and never pruned. Every byte matters. This section analyzes current payload sizes and evaluates compact serialization options.

### Current Payload Sizes (JSON)

| Operation Type | Typical Size | Notes |
|----------------|--------------|-------|
| CREATE | ~500 bytes | Document + 2 commitments |
| UPDATE (single-key) | ~700 bytes | JWS + delta + commitment |
| UPDATE (3-of-5 threshold) | ~2,100 bytes | 3 reveals with Merkle proofs |
| UPDATE (50-of-99 threshold) | ~38,700 bytes | 50 reveals with 7-level proofs |
| DEACTIVATE | ~400 bytes | JWS + reveal only |

### Component Size Breakdown

```
Public Keys (JWK format):
  EC P-256:     ~139 bytes  {"kty":"EC","crv":"P-256","x":"...","y":"..."}
  Ed25519:      ~106 bytes  {"kty":"OKP","crv":"Ed25519","x":"..."}
  BLS12-381:    ~120 bytes  {"kty":"OKP","crv":"BLS12-381-G1","x":"..."}

Cryptographic Values:
  SHA-256 hash (base64url):  43 bytes
  Commitment:                43 bytes
  Reveal value:              43 bytes
  Merkle sibling:            43 bytes

JWS Signature (ES256):
  Header:       ~36 bytes   eyJhbGciOiJFUzI1NiJ9
  Payload:      ~150 bytes  (embedded public key + delta hash)
  Signature:    ~86 bytes   (64 raw bytes -> base64url)
  TOTAL:        ~272 bytes

Merkle Proof (per level):
  Sibling hash: 43 bytes
  3-of-5:       ~129 bytes  (3 levels)
  50-of-99:     ~301 bytes  (7 levels)
```

### JSON Field Name Overhead

JSON repeats field names in every object. These add up:

```
Common field names and their overhead:
  "type":               7 bytes (with quotes + colon)
  "didSuffix":         12 bytes
  "revealValue":       14 bytes
  "signedData":        13 bytes
  "updateCommitment":  19 bytes
  "publicKeyJwk":      15 bytes
  "merkleProof":       14 bytes
  "siblings":          11 bytes
  ...
  Total common fields: ~209 bytes PER OPERATION
```

In a threshold operation with 50 reveals, field names like "revealValue", "publicKey", "merkleProof", "signature" repeat 50 times = **~3,000 bytes just in field names**.

### Serialization Format Comparison

| Format | Size vs JSON | Schema Required | Self-Describing | Go Library |
|--------|--------------|-----------------|-----------------|------------|
| **JSON** | 100% (baseline) | No | Yes | stdlib |
| **CBOR** | ~65-70% | No | Yes | `fxamacker/cbor` |
| **MessagePack** | ~65-70% | No | Yes | `vmihailenco/msgpack` |
| **Protobuf** | ~45-50% | Yes | No | `protocolbuffers/protobuf` |
| **Custom Binary** | ~35-45% | Implicit | No | Manual |

### Option 1: CBOR (Recommended)

CBOR (Concise Binary Object Representation) is an IETF standard (RFC 8949) designed for constrained environments.

**Advantages**:
- **Self-describing**: No external schema needed to decode
- **~30-35% smaller** than JSON
- **Deterministic encoding** (with dCBOR) - important for hashing
- **Well-supported** in Go, JavaScript, Rust, Python
- **IETF standard** - widely adopted, future-proof
- **Extensible** - can add fields without breaking old decoders

**Size reduction techniques in CBOR**:
1. Integer keys instead of string keys (map field names to integers)
2. Compact integer encoding (small ints = 1 byte)
3. Raw bytes instead of base64url strings
4. No whitespace or quotes

**Example: UPDATE operation**

```go
// JSON field mapping to integer keys
const (
    FieldType           = 0
    FieldDIDSuffix      = 1
    FieldRevealValue    = 2
    FieldSignedData     = 3
    FieldDelta          = 4
    FieldPatches        = 5
    FieldUpdateCommitment = 6
    FieldReveals        = 7
    FieldIndex          = 8
    FieldPublicKey      = 9
    FieldMerkleProof    = 10
    FieldSignature      = 11
    FieldSiblings       = 12
)

// JSON (688 bytes):
{"type":"update","didSuffix":"EiD_abc...","revealValue":"xyz...","signedData":"eyJ...","delta":{"patches":[...],"updateCommitment":"..."}}

// CBOR with integer keys (~450 bytes):
{0: 2, 1: h'...', 2: h'...', 3: h'...', 4: {5: [...], 6: h'...'}}
```

**Estimated sizes with CBOR**:

| Operation | JSON | CBOR | Reduction |
|-----------|------|------|-----------|
| CREATE | 500 | 330 | 34% |
| UPDATE (single) | 700 | 460 | 34% |
| UPDATE (3-of-5) | 2,100 | 1,350 | 36% |
| UPDATE (50-of-99) | 38,700 | 24,000 | 38% |

### Option 2: Custom Binary Format (Maximum Compression)

For absolute minimum size, a custom binary format with fixed field order:

```
UPDATE Operation Binary Format:
┌─────────────────────────────────────────────────────────────┐
│ Version (1 byte) │ OpType (1 byte) │ Flags (1 byte)        │
├─────────────────────────────────────────────────────────────┤
│ DID Suffix (32 bytes raw, not base64)                       │
├─────────────────────────────────────────────────────────────┤
│ Reveal Count (1 byte) │ Reveal 0... │ Reveal 1... │ ...    │
├─────────────────────────────────────────────────────────────┤
│ Patches (CBOR-encoded for flexibility)                      │
├─────────────────────────────────────────────────────────────┤
│ New Commitment (32 bytes raw)                               │
└─────────────────────────────────────────────────────────────┘

Reveal Structure (fixed size based on key type):
┌─────────────────────────────────────────────────────────────┐
│ Index (1 byte) │ KeyType (1 byte) │ ProofDepth (1 byte)    │
├─────────────────────────────────────────────────────────────┤
│ PublicKey (32-48 bytes depending on type)                   │
├─────────────────────────────────────────────────────────────┤
│ Merkle Siblings (32 bytes × ProofDepth)                     │
├─────────────────────────────────────────────────────────────┤
│ Signature (64-96 bytes depending on algorithm)              │
└─────────────────────────────────────────────────────────────┘
```

**Key savings in custom binary**:
1. **Raw bytes instead of base64url**: 32 bytes vs 43 bytes (25% savings per hash)
2. **No field names**: 0 bytes vs 209+ bytes
3. **Fixed-size fields**: No length prefixes for known sizes
4. **Implicit structure**: Field order implies meaning

**Estimated sizes with custom binary**:

| Operation | JSON | Custom Binary | Reduction |
|-----------|------|---------------|-----------|
| CREATE | 500 | 200 | 60% |
| UPDATE (single) | 700 | 280 | 60% |
| UPDATE (3-of-5) | 2,100 | 750 | 64% |
| UPDATE (50-of-99) | 38,700 | 13,500 | 65% |

**Drawbacks**:
- Not self-describing - decoder must know exact version
- Harder to debug (not human-readable)
- More complex versioning/migration

### Option 3: Hybrid Approach (Recommended)

Use a layered approach:

```
┌────────────────────────────────────────┐
│ Envelope (Custom Binary - 3 bytes)     │
│ - Version (1 byte)                     │
│ - OpType (1 byte)                      │
│ - Flags (1 byte)                       │
├────────────────────────────────────────┤
│ Payload (CBOR with integer keys)       │
│ - Self-describing                      │
│ - Extensible                           │
│ - Uses raw bytes for hashes            │
└────────────────────────────────────────┘
```

This gives us:
- **Simple envelope** for routing/filtering without full decode
- **CBOR flexibility** for the payload
- **Integer keys** eliminate field name overhead
- **Raw bytes** for cryptographic values
- **Forward compatibility** - new fields can be added

### Recommended Implementation

**Phase 1: CBOR with Integer Keys**

```go
// encoding/cbor.go

import "github.com/fxamacker/cbor/v2"

// Field key constants
const (
    FType       = 0
    FSuffix     = 1
    FReveal     = 2
    FSigned     = 3
    FDelta      = 4
    FPatches    = 5
    FCommitment = 6
    FReveals    = 7
    FIndex      = 8
    FPubKey     = 9
    FProof      = 10
    FSig        = 11
    FSiblings   = 12
)

// EncodeUpdateCBOR encodes an update operation to compact CBOR
func EncodeUpdateCBOR(op *UpdateOperation) ([]byte, error) {
    // Convert to map with integer keys
    m := map[int]interface{}{
        FType:    2, // update = 2
        FSuffix:  decodeBase64ToRaw(op.DIDSuffix),
        FReveal:  decodeBase64ToRaw(op.RevealValue),
        FSigned:  []byte(op.SignedData), // Keep JWS as string for now
        FDelta: map[int]interface{}{
            FPatches:    op.Delta.Patches, // CBOR-encode patches
            FCommitment: decodeBase64ToRaw(op.Delta.UpdateCommitment),
        },
    }

    return cbor.Marshal(m)
}
```

**Migration Path**:
1. Add payload version byte (current = 0x01, CBOR = 0x02)
2. Support both formats during transition
3. All new operations use CBOR
4. Processor decodes based on version byte

### Size Summary

| Format | 3-of-5 Update | 50-of-99 Update | Complexity |
|--------|---------------|-----------------|------------|
| JSON (current) | 2,100 bytes | 38,700 bytes | Low |
| CBOR + int keys | 1,350 bytes | 24,000 bytes | Low |
| Custom binary | 750 bytes | 13,500 bytes | High |
| Hybrid | 900 bytes | 16,000 bytes | Medium |

**Recommendation**: Start with **CBOR + integer keys**. It provides 35-40% size reduction with minimal complexity, maintains self-describing properties, and can be optimized further if needed.

### Additional Optimizations

1. **Signature compression**: For threshold operations with all-BLS keys, aggregate M signatures into 1 (96 bytes total vs M×96 bytes)

2. **Merkle proof optimization**: Instead of full 32-byte siblings, use truncated hashes (20 bytes) for internal nodes - still collision-resistant for practical purposes

3. **Public key omission**: Since public key can be derived from the signature in some schemes (BLS), consider omitting it

4. **Delta compression**: For simple patches (add one service), use operation codes instead of full action strings

**With all optimizations, a 3-of-5 threshold update could be ~400 bytes instead of 2,100 bytes (81% reduction).**

---

## Appendix C: DID-DHT Style Encoding - Custom Binary Format Analysis

After analyzing the [DID-DHT implementation](https://github.com/decentralized-identity/did-dht), we can adopt their highly efficient encoding patterns. DID-DHT must fit within BEP44's **1000 byte limit**, forcing extreme compactness.

### Key Insights from DID-DHT

#### 1. Key Type Registry (Single Byte Instead of JWK)

DID-DHT uses a **key type index** instead of verbose JWK metadata:

```
Key Type Index:
  0 = Ed25519 (default alg: EdDSA)
  1 = secp256k1 (default alg: ES256K)
  2 = P-256 (default alg: ES256)
  3 = X25519 (default alg: ECDH-ES+A256KW)
```

**Savings**: Instead of `{"kty":"EC","crv":"P-256","alg":"ES256"}` (~40 bytes), just use `t=2` (3 bytes) or binary `0x02` (1 byte).

#### 2. Compressed Point Encoding for Public Keys

DID-DHT uses **compressed point encoding**:
- EC keys: 33 bytes (compressed) instead of 65 bytes (uncompressed x,y)
- Ed25519: 32 bytes (already compact)
- BLS12-381: 48 bytes (compressed G1 point)

**Savings**: 32 bytes per EC key

#### 3. Raw Bytes Instead of Base64URL

Store cryptographic values as raw bytes, not base64url strings:
- SHA-256 hash: 32 bytes (raw) vs 43 bytes (base64url) = **26% savings**
- Signature: 64 bytes (raw) vs 86 bytes (base64url) = **26% savings**

#### 4. Short Field Identifiers

DID-DHT uses 1-3 character field names:
```
t=   (type)
k=   (key)
id=  (identifier)
se=  (service endpoint)
```

vs our current:
```
"type":
"publicKeyJwk":
"serviceEndpoint":
```

#### 5. Implicit Structure (No Repeated Keys)

DID-DHT uses DNS record names to imply structure:
```
_k0._did.  →  first key
_k1._did.  →  second key
_s0._did.  →  first service
```

### Proposed did:char Compact Binary Format

#### Format Overview

```
┌────────────────────────────────────────────────────────────────┐
│ Header (3 bytes)                                               │
│ ┌──────────┬──────────┬──────────┐                            │
│ │ Version  │ OpType   │ Flags    │                            │
│ │ (1 byte) │ (1 byte) │ (1 byte) │                            │
│ └──────────┴──────────┴──────────┘                            │
├────────────────────────────────────────────────────────────────┤
│ DID Suffix (32 bytes raw)                                      │
├────────────────────────────────────────────────────────────────┤
│ Operation-specific payload (variable)                          │
└────────────────────────────────────────────────────────────────┘
```

#### Key Type Registry for did:char

```go
const (
    KeyTypeEd25519    = 0  // 32-byte public key, 64-byte signature
    KeyTypeSecp256k1  = 1  // 33-byte compressed pubkey, 64-byte signature
    KeyTypeP256       = 2  // 33-byte compressed pubkey, 64-byte signature
    KeyTypeBLS12381G1 = 3  // 48-byte compressed pubkey, 96-byte signature
)

// Key sizes in bytes
var KeySizes = map[byte]struct{ PubKey, Sig int }{
    0: {32, 64},   // Ed25519
    1: {33, 64},   // secp256k1
    2: {33, 64},   // P-256
    3: {48, 96},   // BLS12-381-G1
}
```

#### UPDATE Operation (Single Key) - Binary Format

```
UPDATE (single key):
┌─────────────────────────────────────────────────────────────┐
│ Header: 0x02 0x02 0x00  (version=2, op=update, flags=0)     │ 3 bytes
├─────────────────────────────────────────────────────────────┤
│ DID Suffix (raw bytes, not base64)                          │ 32 bytes
├─────────────────────────────────────────────────────────────┤
│ Reveal Value (raw SHA-256)                                  │ 32 bytes
├─────────────────────────────────────────────────────────────┤
│ Key Type                                                    │ 1 byte
├─────────────────────────────────────────────────────────────┤
│ Public Key (compressed)                                     │ 32-48 bytes
├─────────────────────────────────────────────────────────────┤
│ Signature (raw, over delta hash)                            │ 64-96 bytes
├─────────────────────────────────────────────────────────────┤
│ New Commitment (raw SHA-256)                                │ 32 bytes
├─────────────────────────────────────────────────────────────┤
│ Patch Count                                                 │ 1 byte
├─────────────────────────────────────────────────────────────┤
│ Patches (compact encoding, see below)                       │ variable
└─────────────────────────────────────────────────────────────┘

TOTAL (Ed25519, 1 patch): 3 + 32 + 32 + 1 + 32 + 64 + 32 + 1 + ~20 = ~217 bytes
vs JSON: ~700 bytes (69% reduction!)
```

#### Patch Encoding

```
Patch Types:
  0x01 = add-public-keys
  0x02 = remove-public-keys
  0x03 = add-services
  0x04 = remove-services

Add Service Patch:
┌──────────┬──────────┬─────────────────┬──────────┬─────────────────┐
│ Type=0x03│ Count    │ Service 0       │ ...      │ Service N       │
│ (1 byte) │ (1 byte) │ (variable)      │          │                 │
└──────────┴──────────┴─────────────────┴──────────┴─────────────────┘

Service Encoding:
┌──────────┬──────────────┬──────────┬──────────────┬──────────┬─────────────────┐
│ ID Len   │ ID (UTF-8)   │ Type Len │ Type (UTF-8) │ URL Len  │ URL (UTF-8)     │
│ (1 byte) │ (variable)   │ (1 byte) │ (variable)   │ (2 bytes)│ (variable)      │
└──────────┴──────────────┴──────────┴──────────────┴──────────┴─────────────────┘

Example: {id: "api", type: "API", endpoint: "https://example.com"}
= 1 + 3 + 1 + 3 + 2 + 19 = 29 bytes
vs JSON: ~70 bytes
```

#### UPDATE Operation (Threshold) - Binary Format

```
UPDATE (3-of-5 threshold):
┌─────────────────────────────────────────────────────────────┐
│ Header: 0x02 0x02 0x01  (version=2, op=update, flags=threshold)│ 3 bytes
├─────────────────────────────────────────────────────────────┤
│ DID Suffix                                                  │ 32 bytes
├─────────────────────────────────────────────────────────────┤
│ Reveal Count (M)                                            │ 1 byte
├─────────────────────────────────────────────────────────────┤
│ Reveal 0                                                    │ ~135 bytes
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ Controller Index                                  1 byte│ │
│ │ Key Type                                          1 byte│ │
│ │ Public Key (compressed)                       32-48 bytes│ │
│ │ Merkle Proof Depth                               1 byte│ │
│ │ Merkle Siblings (32 bytes × depth)           96-224 bytes│ │
│ │ Signature (raw)                               64-96 bytes│ │
│ └─────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│ Reveal 1                                                    │ ~135 bytes
├─────────────────────────────────────────────────────────────┤
│ Reveal 2                                                    │ ~135 bytes
├─────────────────────────────────────────────────────────────┤
│ New Commitment (Merkle root)                                │ 32 bytes
├─────────────────────────────────────────────────────────────┤
│ Patches                                                     │ variable
└─────────────────────────────────────────────────────────────┘

Per-reveal breakdown (Ed25519, 3-level proof):
  1 (index) + 1 (type) + 32 (key) + 1 (depth) + 96 (siblings) + 64 (sig) = 195 bytes

TOTAL (3-of-5, Ed25519, 1 patch):
  3 + 32 + 1 + (3 × 195) + 32 + 20 = 673 bytes
  vs JSON: ~2,100 bytes (68% reduction!)
```

### Size Comparison: All Formats

| Operation | JSON | CBOR | Custom Binary | Reduction |
|-----------|------|------|---------------|-----------|
| CREATE | 500 | 330 | **180** | **64%** |
| UPDATE (single) | 700 | 460 | **217** | **69%** |
| UPDATE (3-of-5) | 2,100 | 1,350 | **673** | **68%** |
| UPDATE (11-of-21) | 4,000 | 2,600 | **1,450** | **64%** |
| UPDATE (50-of-99) | 38,700 | 24,000 | **12,500** | **68%** |
| DEACTIVATE | 400 | 260 | **140** | **65%** |

### Implementation: Compact Encoder

```go
package encoding

import (
    "bytes"
    "encoding/binary"
)

const (
    PayloadVersionCompact byte = 0x02

    OpCreate     byte = 0x01
    OpUpdate     byte = 0x02
    OpRecover    byte = 0x03
    OpDeactivate byte = 0x04

    FlagThreshold byte = 0x01
    FlagBLSAggregated byte = 0x02
)

const (
    KeyTypeEd25519    byte = 0
    KeyTypeSecp256k1  byte = 1
    KeyTypeP256       byte = 2
    KeyTypeBLS12381G1 byte = 3
)

// CompactUpdate encodes an update operation in compact binary format
func CompactUpdate(
    didSuffix []byte,        // 32 bytes raw
    revealValue []byte,      // 32 bytes raw
    keyType byte,
    publicKey []byte,        // compressed
    signature []byte,        // raw
    newCommitment []byte,    // 32 bytes raw
    patches []Patch,
) ([]byte, error) {
    buf := new(bytes.Buffer)

    // Header
    buf.WriteByte(PayloadVersionCompact)
    buf.WriteByte(OpUpdate)
    buf.WriteByte(0x00) // flags: single key

    // DID Suffix (32 bytes)
    buf.Write(didSuffix)

    // Reveal value (32 bytes)
    buf.Write(revealValue)

    // Key type (1 byte)
    buf.WriteByte(keyType)

    // Public key (32-48 bytes depending on type)
    buf.Write(publicKey)

    // Signature (64-96 bytes)
    buf.Write(signature)

    // New commitment (32 bytes)
    buf.Write(newCommitment)

    // Patches
    if err := encodePatches(buf, patches); err != nil {
        return nil, err
    }

    return buf.Bytes(), nil
}

// CompactThresholdUpdate encodes a threshold update in compact binary format
func CompactThresholdUpdate(
    didSuffix []byte,
    reveals []CompactReveal,
    newCommitment []byte,
    patches []Patch,
) ([]byte, error) {
    buf := new(bytes.Buffer)

    // Header
    buf.WriteByte(PayloadVersionCompact)
    buf.WriteByte(OpUpdate)
    buf.WriteByte(FlagThreshold)

    // DID Suffix
    buf.Write(didSuffix)

    // Reveal count
    buf.WriteByte(byte(len(reveals)))

    // Each reveal
    for _, r := range reveals {
        buf.WriteByte(r.Index)
        buf.WriteByte(r.KeyType)
        buf.Write(r.PublicKey)
        buf.WriteByte(byte(len(r.MerkleSiblings)))
        for _, sibling := range r.MerkleSiblings {
            buf.Write(sibling)
        }
        buf.Write(r.Signature)
    }

    // New commitment
    buf.Write(newCommitment)

    // Patches
    if err := encodePatches(buf, patches); err != nil {
        return nil, err
    }

    return buf.Bytes(), nil
}

type CompactReveal struct {
    Index          byte
    KeyType        byte
    PublicKey      []byte   // compressed
    MerkleSiblings [][]byte // 32 bytes each
    Signature      []byte   // raw
}
```

### Migration Strategy

```
Version Byte Routing:
  0x01 → JSON payload (current)
  0x02 → Compact binary payload (new)

Processor detects format from first byte and routes accordingly.
Both formats supported indefinitely for backward compatibility.
```

### Summary: Why Custom Binary Over CBOR

| Aspect | CBOR | Custom Binary |
|--------|------|---------------|
| Size reduction | 35% | **68%** |
| Self-describing | Yes | No (version-dependent) |
| Field names | Integer keys | Implicit (position-based) |
| Crypto values | Raw bytes | Raw bytes |
| Public keys | Full JWK | Type byte + compressed |
| Complexity | Low | Medium |
| Debugging | Easier | Harder (need decoder) |

**Recommendation**: Use **custom binary format** for maximum compactness. The 68% reduction is worth the added complexity, especially since:
1. CHAR data is permanent (every byte matters forever)
2. The format is well-defined and versioned
3. We can provide CLI tools for debugging/inspection
4. Threshold operations with many reveals benefit enormously
