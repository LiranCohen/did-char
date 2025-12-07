# DID-CHAR: Decentralized Identifiers on CHAR

A proof-of-concept CLI tool that implements decentralized identifiers (DIDs) using CHAR (Covenant-based Hash-chained Attestation Records) for Bitcoin-native sequencing and storage.

## What is This?

DID-CHAR combines:
- **Sidetree protocol concepts**: Self-certifying DIDs, commitment/reveal security, operation types
- **CHAR mechanism**: Bitcoin-anchored sequencing through referendum voting
- **Simple architecture**: No IPFS, no complex batching, just SQLite + CHAR RPC

## Quick Start

```bash
# Build
go build -o did-char ./cmd/did-char

# Run the demo
./demo.sh

# Or try commands manually:

# Create a DID (generates keys automatically)
./did-char create --verbose
# Output: Created did:char:y6iHpgYsUfueGwqSI88JWwhXCE2saXjEcS1jsegPzjo
# Keys saved to: did_char_y6iHpgYsUfueGwqSI88JWwhXCE2saXjEcS1jsegPzjo.json

# Generate and add a service
./did-char generate-service --type LinkedDomains --output service.json
./did-char update <did> --add-service "$(cat service.json)" --verbose

# Generate and add a public key
./did-char generate-key --output key.jwk
./did-char update <did> --add-public-key key.jwk --verbose

# Resolve with history
./did-char resolve <did> --history

# Check status
./did-char status
```

## Core Commands

- `did-char create` - Create a new DID with auto-generated keys
- `did-char update <did>` - Update a DID document (reads keys from `did_char_<did>.json`)
- `did-char resolve <did>` - Resolve a DID to its current state
- `did-char deactivate <did>` - Permanently deactivate a DID (reads keys from file)

## Key Management

Each DID gets its own key file named after the DID:

```
did_char_EiDahaOGH-liLLdDtTxEAdc8i-cfCz-WUcQdRJheMVNn3A.json
```

The file contains:
- Current update key (for updates)
- Current recovery key (for recovery/deactivate)
- Next update commitment (for next update)
- Next recovery commitment (for next recovery)

**The key file is updated after each operation** to contain new commitments.

## Key Features

1. **Self-Certifying DIDs**: DID suffixes cryptographically derived from initial state
2. **Commitment/Reveal Security**: Prevents unauthorized modifications
3. **Bitcoin-Anchored**: All operations sequenced through CHAR and anchored to Bitcoin
4. **Automatic Key Management**: Keys generated and updated per DID
5. **SQLite Storage**: Local database caches DID states

## How It Works

1. Register a CHAR app domain once (manual setup)
2. Each DID operation (create, update, etc.) becomes a referendum vote
3. Submit vote via `addbambookv` RPC to next ballot number
4. Poll `getreferendumdecisionroll` repeatedly until ballot is confirmed
   - Since we're the only bond, we're always the leader
   - Need to wait for network to confirm the decision roll
5. All nodes process the same decision rolls in ballot order
6. Deterministic state convergence across all nodes

## Architecture

See [DESIGN.md](DESIGN.md) for detailed architecture.

## CLI Usage

See [CLI.md](CLI.md) for complete CLI documentation.

## Implementation

See [IMPLEMENTATION.md](IMPLEMENTATION.md) for development roadmap.

## Configuration

```yaml
# config.yaml
char:
  rpc_host: "100.67.0.7"
  rpc_port: 18443
  rpc_user: "char"
  rpc_password: "char"
  network: "regtest"
  app_domain: "did-char-domain"

database:
  path: "./did-char.db"
```

## Requirements

- Go 1.21+
- Access to a CHAR-enabled Bitcoin node
- CHAR bond registered for your app domain

## Project Status

This is a hackathon proof-of-concept demonstrating the feasibility of using CHAR for decentralized identity. Not production-ready.

## License

MIT
