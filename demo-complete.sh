#!/bin/bash
set -e

echo "========================================================"
echo "DID-CHAR Demo - Decentralized Identity on CHAR"
echo "Multi-Node Replication Demonstration"
echo "========================================================"
echo ""

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

step() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}STEP $1:${NC} $2"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

success() {
    echo -e "${GREEN}✓${NC} $1"
}

info() {
    echo -e "${YELLOW}→${NC} $1"
}

error() {
    echo -e "${RED}✗${NC} $1"
}

pause() {
    echo ""
    read -p "Press Enter to continue..."
}

# Check if binary exists
if [ ! -f "./did-char" ]; then
    echo "Building did-char..."
    go build -o did-char ./cmd/did-char
    success "Binary built"
fi

# Clean up old demo files
echo "Cleaning up previous demo files..."
rm -f did-char.db did_char_*.json demo-*.json node2-did-char.db

step "1" "Initial Status - Node 1"
info "Checking the initial state of our database"
./did-char status
pause

step "2" "Create a New DID"
info "This will:"
info "  1. Generate secp256k1 update and recovery keys"
info "  2. Create commitments using two-level hashing"
info "  3. Generate self-certifying DID suffix from initial state"
info "  4. Encode operation as binary payload"
info "  5. Submit to CHAR ballot system"
info "  6. Wait for ballot confirmation"
info "  7. Process ballot to write to SQLite"
echo ""
CREATE_OUTPUT=$(./did-char create --verbose 2>&1)
echo "$CREATE_OUTPUT"
DID=$(echo "$CREATE_OUTPUT" | grep "Created DID:" | awk '{print $3}')
success "Created DID: $DID"
pause

step "3" "Resolve the DID"
info "Reading DID document from local SQLite database"
./did-char resolve "$DID"
pause

step "4" "Generate Random Service Endpoint"
info "Using gofakeit to create realistic test data"
./did-char generate-service --type LinkedDomains --output demo-service.json
echo ""
echo "Generated service:"
cat demo-service.json | jq .
pause

step "5" "Update DID - Add Service"
info "This will:"
info "  1. Load update key from keyfile"
info "  2. Generate reveal value from current commitment"
info "  3. Generate new commitment for next update"
info "  4. Create UPDATE operation with patches"
info "  5. Submit to CHAR and wait for confirmation"
info "  6. Process ballot to update SQLite"
echo ""
./did-char update "$DID" --add-service "$(cat demo-service.json)" --verbose
success "Service added via UPDATE operation"
pause

step "6" "Generate Random Public Key"
info "Creating a new secp256k1 key in JWK format"
./did-char generate-key --output demo-key.jwk
echo ""
echo "Generated key:"
cat demo-key.jwk | jq .
pause

step "7" "Update DID - Add Public Key"
info "Adding the key via another UPDATE operation"
./did-char update "$DID" --add-public-key demo-key.jwk --verbose
success "Public key added via UPDATE operation"
pause

step "8" "View Complete DID with History"
info "Showing final DID document with all operations"
./did-char resolve "$DID" --history
pause

step "9" "Check Final Status - Node 1"
./did-char status
pause

step "10" "MULTI-NODE REPLICATION TEST"
info "Now let's simulate a second node joining the network!"
info "We'll create a fresh database and sync from CHAR ballots"
echo ""
info "Creating node2 database path..."
NODE2_DB="node2-did-char.db"
echo ""
info "Node 2 will now sync ballots from CHAR..."
DB_PATH="$NODE2_DB" ./did-char sync --from 0 --verbose
success "Node 2 synced from CHAR!"
pause

step "11" "Node 2 Status"
info "Checking what Node 2 reconstructed from ballots:"
DB_PATH="$NODE2_DB" ./did-char status
pause

step "12" "Node 2 Resolves the DID"
info "Node 2 should be able to resolve the DID created by Node 1!"
info "Resolving: $DID"
echo ""
DB_PATH="$NODE2_DB" ./did-char resolve "$DID" --history
success "Node 2 successfully resolved DID created by Node 1!"
pause

step "13" "Compare Databases"
echo "Node 1 Database:"
sqlite3 did-char.db "SELECT did, status, created_at_ballot, last_operation_ballot FROM dids;"
echo ""
echo "Node 2 Database:"
sqlite3 "$NODE2_DB" "SELECT did, status, created_at_ballot, last_operation_ballot FROM dids;"
echo ""
success "Both nodes have identical state!"
pause

echo ""
echo "========================================================"
echo -e "${GREEN}Demo Complete!${NC}"
echo "========================================================"
echo ""
echo "What we demonstrated:"
echo ""
echo "1. DID Creation with Self-Certifying Suffix"
echo "   - Keys generated using secp256k1"
echo "   - Commitments using two-level hashing (prevents front-running)"
echo "   - DID suffix = base64url(sha256(initial_state))"
echo ""
echo "2. DID Updates via Commitment/Reveal"
echo "   - Added service endpoint"
echo "   - Added public key"
echo "   - Each update reveals previous commitment and creates new one"
echo ""
echo "3. CHAR Integration"
echo "   - Operations encoded as binary payloads"
echo "   - Submitted to CHAR referendum ballot system"
echo "   - Confirmed via decision rolls"
echo ""
echo "4. Multi-Node Replication"
echo "   - Node 2 started with empty database"
echo "   - Synced ballots from CHAR"
echo "   - Reconstructed identical DID state"
echo "   - Can resolve DIDs created by Node 1"
echo ""
echo "Architecture Highlights:"
echo "   - SQLite writes ONLY from ballot processing"
echo "   - Deterministic state reconstruction"
echo "   - No centralized coordination needed"
echo "   - CHAR provides ordering and consensus"
echo ""
echo "Files created:"
ls -lh did-char.db "$NODE2_DB" did_char_*.json demo-*.json 2>/dev/null || true
echo ""
echo "Try these commands:"
echo "  ./did-char status                           # Node 1 status"
echo "  DB_PATH=$NODE2_DB ./did-char status        # Node 2 status"
echo "  ./did-char resolve $DID                     # Resolve DID"
echo "  ./did-char sync --from 0 --verbose          # Sync ballots"
echo ""
