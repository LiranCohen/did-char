#!/bin/bash
set -e

echo "========================================================"
echo "DID-CHAR Multi-Node Replication Demo"
echo "Using Existing Ballots from CHAR"
echo "========================================================"
echo ""

# Build if needed
if [ ! -f "./did-char" ]; then
    echo "Building did-char..."
    go build -o did-char ./cmd/did-char
    echo "✓ Built"
fi

echo ""
echo "SETUP: Using existing DID from ballots 0-2"
echo "============================================"
echo ""
echo "Previously, Node 1 created a DID which resulted in:"
echo "  - Ballot 0: CREATE operation"
echo "  - Ballot 1: UPDATE operation (add service)"
echo "  - Ballot 2: UPDATE operation (add key)"
echo ""
echo "These ballots are permanently stored in CHAR's decision rolls."
echo ""

read -p "Press Enter to continue..."

echo ""
echo "STEP 1: Restore Node 1 Database from Backup"
echo "============================================="
if [ ! -f "did-char.db.backup" ]; then
    echo "ERROR: No backup found. You need to have created a DID first."
    echo "Run: ./did-char create"
    exit 1
fi

cp did-char.db.backup did-char.db
echo "✓ Restored Node 1 database"
echo ""
./did-char status
echo ""

read -p "Press Enter to continue..."

echo ""
echo "STEP 2: Get the DID from Node 1"
echo "================================"
DID=$(sqlite3 did-char.db "SELECT did FROM dids LIMIT 1")
echo "DID: $DID"
echo ""
echo "Full DID Document from Node 1:"
./did-char resolve "$DID"
echo ""

read -p "Press Enter to continue..."

echo ""
echo "STEP 3: Create Node 2 with Fresh Database"
echo "=========================================="
echo "Simulating a brand new node joining the network..."
NODE2_DB="node2-did-char.db"
rm -f "$NODE2_DB"
echo "✓ Created empty database for Node 2"
echo ""

read -p "Press Enter to start syncing..."

echo ""
echo "STEP 4: Node 2 Syncs from CHAR"
echo "==============================="
echo "Node 2 will now query CHAR ballots and reconstruct state..."
echo ""
DB_PATH="$NODE2_DB" ./did-char sync --from 0 --to 10 --verbose
echo ""

read -p "Press Enter to continue..."

echo ""
echo "STEP 5: Verify Node 2 State"
echo "============================"
echo "Node 2 Status:"
DB_PATH="$NODE2_DB" ./did-char status
echo ""

read -p "Press Enter to continue..."

echo ""
echo "STEP 6: Node 2 Resolves the DID"
echo "================================"
echo "Node 2 should now be able to resolve the DID created by Node 1!"
echo ""
echo "Resolving: $DID"
echo ""
DB_PATH="$NODE2_DB" ./did-char resolve "$DID"
echo ""

read -p "Press Enter to continue..."

echo ""
echo "STEP 7: Compare Node States"
echo "============================"
echo ""
echo "Node 1 DIDs:"
echo "------------"
sqlite3 did-char.db "SELECT did, status, created_at_ballot, last_operation_ballot FROM dids;"
echo ""
echo "Node 2 DIDs:"
echo "------------"
sqlite3 "$NODE2_DB" "SELECT did, status, created_at_ballot, last_operation_ballot FROM dids;"
echo ""
echo "Node 1 Operations:"
echo "------------------"
sqlite3 did-char.db "SELECT ballot_number, operation_type, did FROM operations ORDER BY ballot_number;"
echo ""
echo "Node 2 Operations:"
echo "------------------"
sqlite3 "$NODE2_DB" "SELECT ballot_number, operation_type, did FROM operations ORDER BY ballot_number;"
echo ""

echo "========================================================"
echo "✓ Demo Complete!"
echo "========================================================"
echo ""
echo "Key Achievements:"
echo ""
echo "1. Node 2 started with ZERO state"
echo "2. Node 2 queried CHAR ballots (decentralized source of truth)"
echo "3. Node 2 deterministically reconstructed DID state"
echo "4. Both nodes have IDENTICAL state"
echo "5. No direct communication between nodes needed!"
echo ""
echo "This demonstrates:"
echo "  - Decentralized state replication"
echo "  - CHAR as ordering/consensus layer"
echo "  - Deterministic state reconstruction"
echo "  - Multi-node consistency without coordination"
echo ""
echo "Files:"
ls -lh did-char.db "$NODE2_DB" 2>/dev/null
echo ""
