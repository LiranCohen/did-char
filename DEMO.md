# Hackathon Demo Guide

## Quick Demo - Multi-Node Replication

This demo shows DID-CHAR's key feature: **deterministic state replication via CHAR ballots**.

### Run the Demo

```bash
./demo-replication.sh
```

### What It Shows

1. **Node 1** has existing DID state (ballots 0-2 already on CHAR)
2. **Node 2** starts with empty database
3. Node 2 syncs from CHAR: `did-char sync --from 0`
4. Node 2 reconstructs identical state
5. Both nodes resolve the same DID successfully

**Key Insight**: Nodes never communicate directly - CHAR is the source of truth!

## Manual Demo Steps

### 1. Check Initial State

```bash
./did-char status
```

### 2. Sync from CHAR Ballots

```bash
# Create fresh database for Node 2
rm -f node2.db

# Sync ballots from CHAR
DB_PATH=node2.db ./did-char sync --from 0 --to 10 --verbose
```

### 3. Verify Replication

```bash
# Get DID from Node 1
DID=$(sqlite3 did-char.db "SELECT did FROM dids LIMIT 1")

# Node 2 can resolve it!
DB_PATH=node2.db ./did-char resolve "$DID"

# Compare databases
sqlite3 did-char.db "SELECT did, status, last_operation_ballot FROM dids"
sqlite3 node2.db "SELECT did, status, last_operation_ballot FROM dids"
```

## Key Commands

```bash
# Check current state
./did-char status

# Sync from CHAR
./did-char sync --from 0 --verbose

# Resolve DID
./did-char resolve <did>

# Use different database
DB_PATH=node2.db ./did-char <command>
```

## What Makes This Special

- **No central server** - CHAR ballots are the truth
- **Deterministic** - All nodes reach same state
- **Self-certifying DIDs** - `did:char:<hash(initial_state)>`
- **Commitment/reveal security** - Prevents front-running

See [ARCHITECTURE.md](ARCHITECTURE.md) and [DESIGN.md](DESIGN.md) for details.
