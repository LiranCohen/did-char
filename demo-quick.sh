#!/bin/bash
set -e

echo "========================================================"
echo "DID-CHAR Quick Demo"
echo "========================================================"
echo ""

# Build if needed
if [ ! -f "./did-char" ]; then
    echo "Building..."
    go build -o did-char ./cmd/did-char
fi

# Clean up
echo "Cleaning up old files..."
rm -f did-char.db did_char_*.json demo-*.json node2-did-char.db

echo ""
echo "STEP 1: Create DID"
echo "-------------------"
CREATE_OUTPUT=$(./did-char create --verbose 2>&1)
echo "$CREATE_OUTPUT"
DID=$(echo "$CREATE_OUTPUT" | grep "Created DID:" | awk '{print $3}')
echo ""
echo "✓ Created: $DID"

echo ""
echo "STEP 2: Resolve DID"
echo "-------------------"
./did-char resolve "$DID" | head -20

echo ""
echo "STEP 3: Generate and Add Service"
echo "---------------------------------"
./did-char generate-service --type LinkedDomains --output demo-service.json
cat demo-service.json | jq .
./did-char update "$DID" --add-service "$(cat demo-service.json)" --verbose

echo ""
echo "STEP 4: Generate and Add Key"
echo "-----------------------------"
./did-char generate-key --output demo-key.jwk
./did-char update "$DID" --add-public-key demo-key.jwk --verbose

echo ""
echo "STEP 5: View Final DID"
echo "----------------------"
./did-char resolve "$DID" --history

echo ""
echo "STEP 6: Multi-Node Replication"
echo "-------------------------------"
echo "Creating Node 2 with fresh database..."
NODE2_DB="node2-did-char.db"
DB_PATH="$NODE2_DB" ./did-char sync --from 0 --verbose

echo ""
echo "Node 2 Status:"
DB_PATH="$NODE2_DB" ./did-char status

echo ""
echo "Node 2 Resolves DID:"
DB_PATH="$NODE2_DB" ./did-char resolve "$DID" | head -20

echo ""
echo "✓ Node 2 successfully replicated state from CHAR!"
echo ""
echo "========================================================"
echo "Demo Complete!"
echo "========================================================"
