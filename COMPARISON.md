# did:char vs did:ion Analysis

## Overview

| Aspect | did:ion | did:char |
|--------|---------|----------|
| **Anchoring Layer** | Bitcoin (L1 direct) | Bitcoin via CHAR (L2) |
| **Data Availability** | IPFS (external) | CHAR decision rolls |
| **Batching** | Yes (core file + chunk files) | No (one op per ballot) |
| **Protocol** | Full Sidetree spec | Sidetree-inspired, simplified |

---

## How did:ion Works

1. **Batching**: ION nodes collect operations into batches
2. **IPFS Storage**: Batch data stored on IPFS as CAS (Content Addressable Storage)
3. **Bitcoin Anchoring**: Single anchor transaction per batch contains IPFS CID
4. **Resolution**: Download from IPFS → replay all operations → compute current state

**Architecture**:
```
Operations → Batch → IPFS (core file + chunks) → Bitcoin anchor tx
```

---

## Comparison

### Pros of did:char over did:ion

1. **Simpler Architecture**
   - No IPFS dependency (notoriously unreliable for long-term storage)
   - No complex batching logic
   - Single CHAR node vs ION node + IPFS node + Bitcoin node

2. **Faster Resolution** (potentially)
   - did:char caches state in SQLite after sync
   - No need to fetch from IPFS on every resolve
   - did:ion must download potentially large batch files from IPFS

3. **Better Data Availability Guarantees**
   - CHAR's decision rolls are replicated across bonded participants
   - IPFS has pin rot problem - if nobody pins your data, it disappears
   - did:ion effectively requires trusted "ION nodes" to maintain IPFS data

4. **Deterministic Ordering via Referendum**
   - CHAR provides total ordering across all operations
   - No ambiguity about which operation wins in a race condition
   - did:ion relies on batch ordering + block confirmation

5. **Native Bitcoin Integration**
   - CHAR attestations are cryptographically tied to Bitcoin
   - More "Bitcoin-native" than IPFS + anchor hash approach

### Cons of did:char vs did:ion

1. **Scalability**
   - did:char: One ballot per operation (O(n) ballots for n operations)
   - did:ion: One anchor per batch (O(1) anchors for thousands of ops)
   - This is a **significant limitation** - did:ion was designed for scale

2. **Single Bond Centralization** (current PoC)
   - Only one bond means one operator controls all DID operations
   - did:ion has multiple ION nodes that can batch independently
   - *Note: This is fixable with multiple bonds*

3. **Maturity & Ecosystem**
   - did:ion: Production-ready, used by Microsoft, has tooling
   - did:char: Proof of concept, no ecosystem

4. **Specification Compliance**
   - did:ion: Follows full Sidetree spec
   - did:char: Sidetree-inspired but simplified (missing signatures on operations)

---

## Key Design Questions for did:char

### 1. How to achieve batching?

The one-op-per-ballot model won't scale. Options:
- Batch multiple operations into one ballot payload (like Sidetree core files)
- Use a Merkle tree of operations anchored in each ballot
- Allow nodes to aggregate pending operations before submitting

### 2. Multi-bond coordination?

With multiple bonds:
- How do different bonds coordinate on which DIDs they're operating?
- Do you need consensus on operation ordering across bonds?
- Can different bonds handle different "shards" of the DID space?

### 3. Long-term data availability?

CHAR decision rolls are great, but:
- How long are they retained?
- What happens to very old ballots?
- Is there a pruning mechanism? If so, how do new nodes sync?

### 4. Security: Missing operation signatures?

Operations don't include cryptographic signatures over the entire operation payload. In Sidetree:
- Each operation is signed by the appropriate key
- This prevents ballot substitution attacks

Currently did:char relies on the commitment/reveal scheme, but an attacker who sees your reveal value could potentially submit a different operation using that reveal before you do.

---

## Suggestions for did:char Improvement

1. **Add operation batching**
   ```
   Ballot payload = [op1, op2, op3, ...]
   ```
   Process all operations in one ballot, dramatically improving throughput.

2. **Add operation signatures**
   Sign the entire operation JSON with the update/recovery key, not just rely on commitment verification.

3. **Consider a Merkle tree anchor**
   Similar to how did:ion anchors a Merkle root:
   - Collect operations into a tree
   - Anchor root in ballot
   - Provide Merkle proofs for individual operations

4. **Define multi-bond behavior**
   - How multiple bonds coordinate
   - Leader rotation/selection
   - Conflict resolution when bonds disagree

5. **Historical data availability**
   Define how old ballots are archived and how new nodes can bootstrap without replaying from ballot 0.

---

## Is did:ion Superior?

**For production use today**: Yes, clearly. It's battle-tested, scales, has tooling.

**Architecturally**: Debatable.

did:ion's reliance on IPFS is arguably its biggest weakness:
- IPFS availability is not guaranteed
- Requires running/paying for IPFS infrastructure
- Pin rot is a real problem

did:char's CHAR-based approach could be **architecturally superior** if:
1. Batching is added
2. Multi-bond decentralization is achieved
3. Long-term data availability is guaranteed

The core innovation of did:char - using referendum voting for deterministic ordering without external storage dependencies - is sound. The question is whether CHAR can scale to handle the throughput needed for a global DID system.

---

## Open Questions

1. **How does CHAR handle ballot throughput?** What's the max ballots/second? This determines if batching is strictly necessary.

2. **What's the long-term plan for CHAR data retention?** Can old decision rolls be pruned, or are they kept forever?

3. **Are there plans for multiple bonds?** How would leader selection work with competing bonds?

4. **What's the Bitcoin anchoring cadence?** How frequently do CHAR attestations get written to Bitcoin L1?

---

## Discussion Notes

(Add notes from our discussion below)

