#!/bin/bash
set -e

echo "================================================"
echo "DID-CHAR Demo - Decentralized Identity on CHAR"
echo "================================================"
echo ""

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

step() {
    echo -e "${BLUE}[$1]${NC} $2"
}

success() {
    echo -e "${GREEN}✓${NC} $1"
}

info() {
    echo -e "${YELLOW}→${NC} $1"
}

# Check if binary exists
if [ ! -f "./did-char" ]; then
    echo "Building did-char..."
    go build -o did-char ./cmd/did-char
fi

echo ""
step "1" "Checking status"
./did-char status
echo ""

step "2" "Creating a new DID"
info "This generates keys, creates a DID with self-certifying suffix, and submits to CHAR"
CREATE_OUTPUT=$(./did-char create --verbose 2>&1)
echo "$CREATE_OUTPUT"
DID=$(echo "$CREATE_OUTPUT" | grep "Created DID:" | awk '{print $3}')
success "Created DID: $DID"
echo ""
sleep 2

step "3" "Resolving the DID"
info "Fetching the current DID document from storage"
./did-char resolve "$DID"
echo ""
sleep 2

step "4" "Generating a random service endpoint"
info "Using gofakeit to create realistic test data"
./did-char generate-service --type LinkedDomains --output demo-service.json
cat demo-service.json
echo ""
sleep 2

step "5" "Adding the service to the DID"
info "This creates an UPDATE operation, submits to CHAR, and waits for confirmation"
./did-char update "$DID" --add-service "$(cat demo-service.json)" --verbose
echo ""
sleep 2

step "6" "Generating a random public key"
info "Creating a secp256k1 key in JWK format"
./did-char generate-key --output demo-key.jwk
echo "Generated key:"
cat demo-key.jwk | head -8
echo ""
sleep 2

step "7" "Adding the key to the DID"
info "Another UPDATE operation to add a public key"
./did-char update "$DID" --add-public-key demo-key.jwk --verbose
echo ""
sleep 2

step "8" "Final DID resolution with history"
info "Showing the complete DID document and operation history"
./did-char resolve "$DID" --history
echo ""

step "9" "Final status"
./did-char status
echo ""

echo "================================================"
echo -e "${GREEN}Demo Complete!${NC}"
echo "================================================"
echo ""
echo "Summary:"
echo "  - Created DID with self-certifying suffix"
echo "  - Added service endpoint via UPDATE operation"
echo "  - Added public key via UPDATE operation"
echo "  - All operations confirmed on CHAR (ballots 0, 1, 2)"
echo "  - DID state tracked in SQLite"
echo "  - Keys stored in did_char_<suffix>.json"
echo ""
echo "Key files created:"
ls -lh did_char_*.json demo-*.json 2>/dev/null || true
echo ""
echo "Try these commands:"
echo "  ./did-char status                  # Show database stats"
echo "  ./did-char resolve $DID          # Resolve DID"
echo "  ./did-char generate-service        # Generate random service"
echo "  ./did-char generate-key            # Generate random key"
echo ""
