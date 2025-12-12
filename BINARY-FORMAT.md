# did:char Compact Binary Format Specification

**Version**: 2
**Status**: Draft
**Last Updated**: 2024-12

## Overview

This document specifies the compact binary encoding format for did:char operations stored on the CHAR network. The format is designed for maximum space efficiency since CHAR data is permanent and never pruned.

### Design Goals

1. **Minimize payload size** - Every byte matters forever
2. **Self-versioning** - Format can evolve with backward compatibility
3. **Deterministic encoding** - Same input always produces same output
4. **Fast parsing** - Fixed-size fields where possible, minimal branching

### Size Comparison

| Operation | JSON | Compact Binary | Reduction |
|-----------|------|----------------|-----------|
| CREATE | 500 bytes | 180 bytes | 64% |
| UPDATE (single key) | 700 bytes | 217 bytes | 69% |
| UPDATE (3-of-5 threshold) | 2,100 bytes | 673 bytes | 68% |
| UPDATE (50-of-99 threshold) | 38,700 bytes | 12,500 bytes | 68% |
| DEACTIVATE | 400 bytes | 140 bytes | 65% |

---

## Encoding Conventions

### Byte Order

All multi-byte integers are encoded in **big-endian** (network byte order).

### Variable-Length Integers (Varint)

For counts and lengths that may exceed 255, we use a simple varint encoding:

```
0x00-0x7F: Single byte (0-127)
0x80-0xFF: Two bytes, first byte has high bit set
           Value = ((byte0 & 0x7F) << 8) | byte1
           Range: 128-32767
```

### Strings

Strings are encoded as:
```
┌────────────┬─────────────────┐
│ Length     │ UTF-8 bytes     │
│ (1 byte)   │ (variable)      │
└────────────┴─────────────────┘
```

For strings potentially longer than 255 bytes (e.g., service endpoints):
```
┌────────────┬─────────────────┐
│ Length     │ UTF-8 bytes     │
│ (2 bytes)  │ (variable)      │
└────────────┴─────────────────┘
```

### Cryptographic Values

All hashes, signatures, and keys are stored as **raw bytes**, not base64url encoded.

| Value | Size |
|-------|------|
| SHA-256 hash | 32 bytes |
| DID Suffix | 32 bytes |
| Commitment | 32 bytes |
| Reveal value | 32 bytes |
| Merkle sibling | 32 bytes |

---

## Key Type Registry

Instead of verbose JWK metadata, keys are identified by a single-byte type index:

| Index | Algorithm | Curve | Public Key Size | Signature Size |
|-------|-----------|-------|-----------------|----------------|
| 0x00 | EdDSA | Ed25519 | 32 bytes | 64 bytes |
| 0x01 | ES256K | secp256k1 | 33 bytes (compressed) | 64 bytes |
| 0x02 | ES256 | P-256 | 33 bytes (compressed) | 64 bytes |
| 0x03 | BLS | BLS12-381-G1 | 48 bytes (compressed) | 96 bytes |

### Compressed Point Encoding

For elliptic curve keys (secp256k1, P-256), public keys use **compressed point encoding**:
- 1 byte prefix: `0x02` (even y) or `0x03` (odd y)
- 32 bytes x-coordinate

This reduces EC public keys from 65 bytes (uncompressed) to 33 bytes.

### Key Type to JWK Mapping

```
0x00 (Ed25519):
  kty: "OKP"
  crv: "Ed25519"
  alg: "EdDSA"

0x01 (secp256k1):
  kty: "EC"
  crv: "secp256k1"
  alg: "ES256K"

0x02 (P-256):
  kty: "EC"
  crv: "P-256"
  alg: "ES256"

0x03 (BLS12-381-G1):
  kty: "OKP"
  crv: "BLS12-381-G1"
  alg: "BLS"
```

---

## Packet Header

Every packet begins with a 3-byte header:

```
┌──────────────┬──────────────┬──────────────┐
│ Version      │ Operation    │ Flags        │
│ (1 byte)     │ (1 byte)     │ (1 byte)     │
└──────────────┴──────────────┴──────────────┘
```

### Version

| Value | Description |
|-------|-------------|
| 0x01 | Legacy JSON format (for backward compatibility detection) |
| 0x02 | Compact binary format v2 (this specification) |

### Operation Types

| Value | Operation |
|-------|-----------|
| 0x01 | CREATE |
| 0x02 | UPDATE |
| 0x03 | RECOVER |
| 0x04 | DEACTIVATE |

### Flags

| Bit | Name | Description |
|-----|------|-------------|
| 0 | THRESHOLD | Operation uses M-of-N threshold signatures |
| 1 | BLS_AGGREGATED | Signatures are BLS-aggregated (requires all BLS keys) |
| 2-7 | Reserved | Must be 0 |

```
Examples:
  0x00 = Single key operation
  0x01 = Threshold operation (M individual signatures)
  0x03 = Threshold + BLS aggregated (single aggregate signature)
```

---

## CREATE Operation

Creates a new DID with an initial document.

```
CREATE Packet:
┌─────────────────────────────────────────────────────────────────┐
│ Header                                                    3 bytes│
│   Version: 0x02                                                 │
│   Operation: 0x01 (CREATE)                                      │
│   Flags: 0x00 or 0x01 (threshold)                              │
├─────────────────────────────────────────────────────────────────┤
│ Suffix Data Hash (input to DID suffix generation)       32 bytes│
├─────────────────────────────────────────────────────────────────┤
│ Update Commitment                                       32 bytes│
├─────────────────────────────────────────────────────────────────┤
│ Recovery Commitment                                     32 bytes│
├─────────────────────────────────────────────────────────────────┤
│ [If THRESHOLD flag set]                                         │
│   Update Threshold (M)                                   1 byte │
│   Update Controller Count (N)                            1 byte │
│   Recovery Threshold (M)                                 1 byte │
│   Recovery Controller Count (N)                          1 byte │
├─────────────────────────────────────────────────────────────────┤
│ Initial Document                                        variable│
└─────────────────────────────────────────────────────────────────┘
```

### Initial Document Encoding

```
Document:
┌─────────────────────────────────────────────────────────────────┐
│ Public Key Count                                         1 byte │
├─────────────────────────────────────────────────────────────────┤
│ Public Key 0                                            variable│
│ Public Key 1                                            variable│
│ ...                                                             │
├─────────────────────────────────────────────────────────────────┤
│ Service Count                                            1 byte │
├─────────────────────────────────────────────────────────────────┤
│ Service 0                                               variable│
│ Service 1                                               variable│
│ ...                                                             │
├─────────────────────────────────────────────────────────────────┤
│ Authentication Key Indices (bitmask)                    variable│
└─────────────────────────────────────────────────────────────────┘
```

### Public Key Encoding

```
Public Key:
┌─────────────────────────────────────────────────────────────────┐
│ ID Length                                                1 byte │
├─────────────────────────────────────────────────────────────────┤
│ ID (UTF-8, without # prefix)                            variable│
├─────────────────────────────────────────────────────────────────┤
│ Key Type                                                 1 byte │
├─────────────────────────────────────────────────────────────────┤
│ Public Key Bytes (compressed)                        32-48 bytes│
├─────────────────────────────────────────────────────────────────┤
│ Purpose Flags                                            1 byte │
│   Bit 0: authentication                                         │
│   Bit 1: assertionMethod                                        │
│   Bit 2: keyAgreement                                           │
│   Bit 3: capabilityInvocation                                   │
│   Bit 4: capabilityDelegation                                   │
└─────────────────────────────────────────────────────────────────┘

Example (Ed25519 key with ID "key-1", authentication purpose):
  06                      # ID length = 6
  6b 65 79 2d 31          # "key-1"
  00                      # Key type = Ed25519
  [32 bytes public key]   # Raw Ed25519 public key
  01                      # Purpose flags = authentication only

Total: 1 + 5 + 1 + 32 + 1 = 40 bytes
vs JSON: ~180 bytes
```

### Service Encoding

```
Service:
┌─────────────────────────────────────────────────────────────────┐
│ ID Length                                                1 byte │
├─────────────────────────────────────────────────────────────────┤
│ ID (UTF-8, without # prefix)                            variable│
├─────────────────────────────────────────────────────────────────┤
│ Type Length                                              1 byte │
├─────────────────────────────────────────────────────────────────┤
│ Type (UTF-8)                                            variable│
├─────────────────────────────────────────────────────────────────┤
│ Endpoint Length                                         2 bytes │
├─────────────────────────────────────────────────────────────────┤
│ Endpoint (UTF-8)                                        variable│
└─────────────────────────────────────────────────────────────────┘

Example (service "api" of type "API" at "https://example.com"):
  03                      # ID length = 3
  61 70 69                # "api"
  03                      # Type length = 3
  41 50 49                # "API"
  00 13                   # Endpoint length = 19
  [19 bytes URL]          # "https://example.com"

Total: 1 + 3 + 1 + 3 + 2 + 19 = 29 bytes
vs JSON: ~80 bytes
```

---

## UPDATE Operation (Single Key)

Updates an existing DID using a single update key.

```
UPDATE (Single Key) Packet:
┌─────────────────────────────────────────────────────────────────┐
│ Header                                                    3 bytes│
│   Version: 0x02                                                 │
│   Operation: 0x02 (UPDATE)                                      │
│   Flags: 0x00                                                   │
├─────────────────────────────────────────────────────────────────┤
│ DID Suffix                                              32 bytes│
├─────────────────────────────────────────────────────────────────┤
│ Reveal Value                                            32 bytes│
├─────────────────────────────────────────────────────────────────┤
│ Key Type                                                 1 byte │
├─────────────────────────────────────────────────────────────────┤
│ Public Key (compressed)                              32-48 bytes│
├─────────────────────────────────────────────────────────────────┤
│ Signature (over Delta Hash)                          64-96 bytes│
├─────────────────────────────────────────────────────────────────┤
│ New Update Commitment                                   32 bytes│
├─────────────────────────────────────────────────────────────────┤
│ Delta (patches)                                         variable│
└─────────────────────────────────────────────────────────────────┘
```

### Signature Message

The signature is computed over the **Delta Hash**, which is:

```
DeltaHash = SHA256(Delta)
```

Where Delta is the compact-encoded patches + new commitment (not JSON).

### Size Calculation (Ed25519)

```
Header:           3 bytes
DID Suffix:      32 bytes
Reveal:          32 bytes
Key Type:         1 byte
Public Key:      32 bytes
Signature:       64 bytes
New Commitment:  32 bytes
Delta (1 patch): ~20 bytes
─────────────────────────
TOTAL:          ~216 bytes
```

---

## UPDATE Operation (Threshold)

Updates a DID requiring M-of-N controller signatures.

```
UPDATE (Threshold) Packet:
┌─────────────────────────────────────────────────────────────────┐
│ Header                                                    3 bytes│
│   Version: 0x02                                                 │
│   Operation: 0x02 (UPDATE)                                      │
│   Flags: 0x01 (THRESHOLD)                                       │
├─────────────────────────────────────────────────────────────────┤
│ DID Suffix                                              32 bytes│
├─────────────────────────────────────────────────────────────────┤
│ Reveal Count (M)                                         1 byte │
├─────────────────────────────────────────────────────────────────┤
│ Reveal 0                                                variable│
├─────────────────────────────────────────────────────────────────┤
│ Reveal 1                                                variable│
├─────────────────────────────────────────────────────────────────┤
│ ...                                                             │
├─────────────────────────────────────────────────────────────────┤
│ Reveal M-1                                              variable│
├─────────────────────────────────────────────────────────────────┤
│ New Update Commitment (Merkle root)                     32 bytes│
├─────────────────────────────────────────────────────────────────┤
│ Delta (patches)                                         variable│
└─────────────────────────────────────────────────────────────────┘
```

### Reveal Structure

Each reveal contains a controller's signature and Merkle proof:

```
Reveal:
┌─────────────────────────────────────────────────────────────────┐
│ Controller Index                                         1 byte │
├─────────────────────────────────────────────────────────────────┤
│ Key Type                                                 1 byte │
├─────────────────────────────────────────────────────────────────┤
│ Public Key (compressed)                              32-48 bytes│
├─────────────────────────────────────────────────────────────────┤
│ Merkle Proof Depth                                       1 byte │
├─────────────────────────────────────────────────────────────────┤
│ Merkle Siblings                               32 × Depth bytes │
├─────────────────────────────────────────────────────────────────┤
│ Signature (over Delta Hash)                          64-96 bytes│
└─────────────────────────────────────────────────────────────────┘
```

### Size Calculation (3-of-5, Ed25519)

```
Per Reveal (3-level Merkle proof):
  Index:            1 byte
  Key Type:         1 byte
  Public Key:      32 bytes
  Proof Depth:      1 byte
  Siblings:        96 bytes (3 × 32)
  Signature:       64 bytes
  ─────────────────────────
  Per Reveal:     195 bytes

Total Packet:
  Header:           3 bytes
  DID Suffix:      32 bytes
  Reveal Count:     1 byte
  Reveals:        585 bytes (3 × 195)
  New Commitment:  32 bytes
  Delta:          ~20 bytes
  ─────────────────────────
  TOTAL:         ~673 bytes
```

---

## UPDATE Operation (BLS Aggregated)

For threshold DIDs where ALL controllers use BLS keys, signatures can be aggregated into a single 96-byte signature.

```
UPDATE (BLS Aggregated) Packet:
┌─────────────────────────────────────────────────────────────────┐
│ Header                                                    3 bytes│
│   Version: 0x02                                                 │
│   Operation: 0x02 (UPDATE)                                      │
│   Flags: 0x03 (THRESHOLD | BLS_AGGREGATED)                      │
├─────────────────────────────────────────────────────────────────┤
│ DID Suffix                                              32 bytes│
├─────────────────────────────────────────────────────────────────┤
│ Signer Count (M)                                         1 byte │
├─────────────────────────────────────────────────────────────────┤
│ Signer Indices (M bytes)                                M bytes │
├─────────────────────────────────────────────────────────────────┤
│ Aggregated Public Keys (M × 48 bytes)              M × 48 bytes │
├─────────────────────────────────────────────────────────────────┤
│ Merkle Proofs (M proofs)                                variable│
├─────────────────────────────────────────────────────────────────┤
│ Aggregated Signature                                    96 bytes│
├─────────────────────────────────────────────────────────────────┤
│ New Update Commitment                                   32 bytes│
├─────────────────────────────────────────────────────────────────┤
│ Delta                                                   variable│
└─────────────────────────────────────────────────────────────────┘
```

### Size Calculation (3-of-5, BLS Aggregated)

```
Header:                   3 bytes
DID Suffix:              32 bytes
Signer Count:             1 byte
Signer Indices:           3 bytes
Public Keys:            144 bytes (3 × 48)
Merkle Proofs:          102 bytes (3 × (1 + 96))
Aggregated Signature:    96 bytes
New Commitment:          32 bytes
Delta:                  ~20 bytes
─────────────────────────────────
TOTAL:                 ~433 bytes

vs Non-aggregated:     ~673 bytes (36% additional savings)
vs JSON:             ~2,100 bytes (79% reduction!)
```

---

## RECOVER Operation

Recovers a DID using recovery key(s), allowing full reset of update keys.

```
RECOVER Packet:
┌─────────────────────────────────────────────────────────────────┐
│ Header                                                    3 bytes│
│   Version: 0x02                                                 │
│   Operation: 0x03 (RECOVER)                                     │
│   Flags: 0x00 or 0x01 (threshold)                              │
├─────────────────────────────────────────────────────────────────┤
│ DID Suffix                                              32 bytes│
├─────────────────────────────────────────────────────────────────┤
│ [Single key: same as UPDATE single key reveal]                  │
│ [Threshold: same as UPDATE threshold reveals]                   │
├─────────────────────────────────────────────────────────────────┤
│ New Update Commitment                                   32 bytes│
├─────────────────────────────────────────────────────────────────┤
│ New Recovery Commitment                                 32 bytes│
├─────────────────────────────────────────────────────────────────┤
│ [If THRESHOLD flag set]                                         │
│   New Update Threshold                                   1 byte │
│   New Update Controller Count                            1 byte │
│   New Recovery Threshold                                 1 byte │
│   New Recovery Controller Count                          1 byte │
├─────────────────────────────────────────────────────────────────┤
│ Delta (patches to apply)                                variable│
└─────────────────────────────────────────────────────────────────┘
```

---

## DEACTIVATE Operation

Permanently deactivates a DID.

```
DEACTIVATE Packet:
┌─────────────────────────────────────────────────────────────────┐
│ Header                                                    3 bytes│
│   Version: 0x02                                                 │
│   Operation: 0x04 (DEACTIVATE)                                  │
│   Flags: 0x00 or 0x01 (threshold)                              │
├─────────────────────────────────────────────────────────────────┤
│ DID Suffix                                              32 bytes│
├─────────────────────────────────────────────────────────────────┤
│ [Single key reveal OR threshold reveals]                variable│
└─────────────────────────────────────────────────────────────────┘
```

### Size Calculation (Single Key, Ed25519)

```
Header:           3 bytes
DID Suffix:      32 bytes
Reveal:          32 bytes
Key Type:         1 byte
Public Key:      32 bytes
Signature:       64 bytes
─────────────────────────
TOTAL:          164 bytes

vs JSON:        ~400 bytes (59% reduction)
```

---

## Delta (Patches) Encoding

The delta contains patches to apply and the new commitment.

```
Delta:
┌─────────────────────────────────────────────────────────────────┐
│ Patch Count                                              1 byte │
├─────────────────────────────────────────────────────────────────┤
│ Patch 0                                                 variable│
├─────────────────────────────────────────────────────────────────┤
│ Patch 1                                                 variable│
├─────────────────────────────────────────────────────────────────┤
│ ...                                                             │
└─────────────────────────────────────────────────────────────────┘
```

### Patch Types

| Value | Action | Description |
|-------|--------|-------------|
| 0x01 | add-public-keys | Add one or more public keys |
| 0x02 | remove-public-keys | Remove keys by ID |
| 0x03 | add-services | Add one or more services |
| 0x04 | remove-services | Remove services by ID |

### Add Public Keys Patch

```
┌─────────────────────────────────────────────────────────────────┐
│ Patch Type: 0x01                                         1 byte │
├─────────────────────────────────────────────────────────────────┤
│ Key Count                                                1 byte │
├─────────────────────────────────────────────────────────────────┤
│ Public Key 0 (see Public Key Encoding)                  variable│
├─────────────────────────────────────────────────────────────────┤
│ Public Key 1                                            variable│
├─────────────────────────────────────────────────────────────────┤
│ ...                                                             │
└─────────────────────────────────────────────────────────────────┘
```

### Remove Public Keys Patch

```
┌─────────────────────────────────────────────────────────────────┐
│ Patch Type: 0x02                                         1 byte │
├─────────────────────────────────────────────────────────────────┤
│ ID Count                                                 1 byte │
├─────────────────────────────────────────────────────────────────┤
│ ID 0 Length                                              1 byte │
│ ID 0 (UTF-8)                                            variable│
├─────────────────────────────────────────────────────────────────┤
│ ID 1 Length                                              1 byte │
│ ID 1 (UTF-8)                                            variable│
├─────────────────────────────────────────────────────────────────┤
│ ...                                                             │
└─────────────────────────────────────────────────────────────────┘
```

### Add Services Patch

```
┌─────────────────────────────────────────────────────────────────┐
│ Patch Type: 0x03                                         1 byte │
├─────────────────────────────────────────────────────────────────┤
│ Service Count                                            1 byte │
├─────────────────────────────────────────────────────────────────┤
│ Service 0 (see Service Encoding)                        variable│
├─────────────────────────────────────────────────────────────────┤
│ Service 1                                               variable│
├─────────────────────────────────────────────────────────────────┤
│ ...                                                             │
└─────────────────────────────────────────────────────────────────┘
```

### Remove Services Patch

```
┌─────────────────────────────────────────────────────────────────┐
│ Patch Type: 0x04                                         1 byte │
├─────────────────────────────────────────────────────────────────┤
│ ID Count                                                 1 byte │
├─────────────────────────────────────────────────────────────────┤
│ ID 0 Length                                              1 byte │
│ ID 0 (UTF-8)                                            variable│
├─────────────────────────────────────────────────────────────────┤
│ ...                                                             │
└─────────────────────────────────────────────────────────────────┘
```

---

## Verification

### Delta Hash Computation

The delta hash signed by update/recovery keys is computed as:

```
DeltaHash = SHA256(CompactEncodedDelta)
```

Where `CompactEncodedDelta` is the binary-encoded patches (not JSON).

### Merkle Proof Verification

For threshold operations, each reveal includes a Merkle proof. Verification:

```go
func VerifyMerkleProof(
    publicKey []byte,
    index int,
    siblings [][]byte,
    expectedRoot []byte,
) bool {
    // Leaf = H(H(publicKey))
    reveal := SHA256(publicKey)
    leaf := SHA256(reveal)

    current := leaf
    idx := index

    for _, sibling := range siblings {
        if idx % 2 == 0 {
            // Current is left child
            current = SHA256(current || sibling)
        } else {
            // Current is right child
            current = SHA256(sibling || current)
        }
        idx = idx / 2
    }

    return bytes.Equal(current, expectedRoot)
}
```

### Signature Verification

For single-key operations:
```
Verify(publicKey, DeltaHash, signature)
```

For threshold operations, verify each signature individually:
```
for each reveal:
    Verify(reveal.publicKey, DeltaHash, reveal.signature)
```

For BLS-aggregated threshold operations:
```
VerifyAggregate(publicKeys[], DeltaHash, aggregatedSignature)
```

---

## Wire Format Examples

### Example 1: Simple UPDATE (Ed25519)

Adding a service endpoint:

```
Hex dump:
02 02 00                              # Header: v2, UPDATE, no flags
[32 bytes DID suffix]                 # DID suffix
[32 bytes reveal]                     # Reveal value
00                                    # Key type: Ed25519
[32 bytes public key]                 # Ed25519 public key
[64 bytes signature]                  # Ed25519 signature
[32 bytes new commitment]             # New update commitment
01                                    # Patch count: 1
03                                    # Patch type: add-services
01                                    # Service count: 1
03 61 70 69                           # ID: "api"
03 41 50 49                           # Type: "API"
00 13 68 74 74 70 73 3a 2f 2f        # Endpoint: "https://example.com"
65 78 61 6d 70 6c 65 2e 63 6f 6d

Total: ~220 bytes
```

### Example 2: Threshold UPDATE (3-of-5, Ed25519)

```
Hex dump:
02 02 01                              # Header: v2, UPDATE, THRESHOLD flag
[32 bytes DID suffix]                 # DID suffix
03                                    # Reveal count: 3
                                      # --- Reveal 0 ---
00                                    # Controller index: 0
00                                    # Key type: Ed25519
[32 bytes public key]                 # Public key
03                                    # Merkle proof depth: 3
[32 bytes sibling 0]                  # Merkle siblings
[32 bytes sibling 1]
[32 bytes sibling 2]
[64 bytes signature]                  # Signature
                                      # --- Reveal 1 ---
02                                    # Controller index: 2
00                                    # Key type: Ed25519
[32 bytes public key]
03
[96 bytes siblings]
[64 bytes signature]
                                      # --- Reveal 2 ---
04                                    # Controller index: 4
00                                    # Key type: Ed25519
[32 bytes public key]
03
[96 bytes siblings]
[64 bytes signature]
                                      # --- Delta ---
[32 bytes new commitment]             # New Merkle root
01                                    # Patch count: 1
03 01 03 61 70 69 ...                # Add service patch

Total: ~673 bytes
```

---

## Implementation Notes

### Backward Compatibility

The processor MUST support both formats:

```go
func DecodePayload(data []byte) (Operation, error) {
    if len(data) == 0 {
        return nil, ErrEmptyPayload
    }

    switch data[0] {
    case 0x01:
        // Legacy JSON format
        return decodeJSONPayload(data)
    case 0x02:
        // Compact binary format
        return decodeCompactPayload(data)
    default:
        return nil, ErrUnknownVersion
    }
}
```

### Deterministic Encoding

For hash computation, encoding MUST be deterministic:
- Keys in documents are ordered by ID (lexicographic)
- Services are ordered by ID
- Patches are ordered by type, then by ID within each type

### Error Handling

Decoders MUST validate:
- Version byte is known
- Operation type is valid
- Key type indices are in registry
- Lengths don't exceed packet size
- Required fields are present

---

## Appendix A: Quick Reference

### Header Bytes

```
Version:   0x02
Operations: CREATE=0x01, UPDATE=0x02, RECOVER=0x03, DEACTIVATE=0x04
Flags:     THRESHOLD=0x01, BLS_AGGREGATED=0x02
```

### Key Types

```
0x00 = Ed25519    (32-byte key, 64-byte sig)
0x01 = secp256k1  (33-byte key, 64-byte sig)
0x02 = P-256      (33-byte key, 64-byte sig)
0x03 = BLS12-381  (48-byte key, 96-byte sig)
```

### Patch Types

```
0x01 = add-public-keys
0x02 = remove-public-keys
0x03 = add-services
0x04 = remove-services
```

### Fixed Sizes

```
SHA-256 hash:     32 bytes
DID Suffix:       32 bytes
Commitment:       32 bytes
Merkle sibling:   32 bytes
Ed25519 key:      32 bytes
Ed25519 sig:      64 bytes
EC compressed:    33 bytes
EC signature:     64 bytes
BLS key:          48 bytes
BLS signature:    96 bytes
```
