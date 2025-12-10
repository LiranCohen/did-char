#!/bin/bash

set -e  # Exit on error

echo "========================================="
echo "DID CHAR Lifecycle Test"
echo "========================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Cleanup function
cleanup() {
    echo ""
    echo -e "${YELLOW}Cleaning up test files...${NC}"
    rm -f test_service_*.json
    rm -f test_key_*.json
}

# Set trap to cleanup on exit
trap cleanup EXIT

echo -e "${BLUE}Step 1: Create a new DID${NC}"
echo "Running: ./did-char create --verbose"
CREATE_OUTPUT=$(./did-char create --verbose 2>&1)
echo "$CREATE_OUTPUT"

# Extract DID from output
DID=$(echo "$CREATE_OUTPUT" | grep -o 'did:char:[a-zA-Z0-9_-]*' | head -1)
if [ -z "$DID" ]; then
    echo -e "${RED}ERROR: Failed to extract DID from create output${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Created DID: $DID${NC}"
echo ""

# Wait a bit for the operation to be ready
sleep 2

echo -e "${BLUE}Step 2: Sync to get the created DID${NC}"
echo "Running: ./did-char sync --verbose"
./did-char sync --verbose
echo -e "${GREEN}✓ Sync complete${NC}"
echo ""

echo -e "${BLUE}Step 3: Resolve the DID (initial state)${NC}"
echo "Running: ./did-char resolve $DID"
INITIAL_STATE=$(./did-char resolve $DID 2>&1)
echo "$INITIAL_STATE"

# Check if resolution was successful
if echo "$INITIAL_STATE" | grep -q "error\|failed\|not found"; then
    echo -e "${RED}ERROR: Failed to resolve DID${NC}"
    exit 1
fi

# Count initial services
INITIAL_SERVICE_COUNT=$(echo "$INITIAL_STATE" | grep -c '"type"' || echo "0")
echo -e "${GREEN}✓ Initial service count: $INITIAL_SERVICE_COUNT${NC}"
echo ""

echo -e "${BLUE}Step 4: Create a service endpoint JSON${NC}"
cat > test_service_1.json <<'EOF'
{
  "id": "#github",
  "type": "SocialWebProfile",
  "serviceEndpoint": "https://github.com/test-user"
}
EOF
echo "Created test_service_1.json:"
cat test_service_1.json
echo ""

echo -e "${BLUE}Step 5: Update DID - Add service endpoint${NC}"
echo "Running: ./did-char update $DID --add-service test_service_1.json --verbose"
UPDATE_OUTPUT=$(./did-char update "$DID" --add-service test_service_1.json --verbose 2>&1)
echo "$UPDATE_OUTPUT"

# Check if update was successful
if echo "$UPDATE_OUTPUT" | grep -q "error\|failed"; then
    echo -e "${RED}ERROR: Update failed${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Update submitted${NC}"
echo ""

# Wait for the update to be processed
sleep 2

echo -e "${BLUE}Step 6: Sync to get the update${NC}"
echo "Running: ./did-char sync --verbose"
./did-char sync --verbose
echo -e "${GREEN}✓ Sync complete${NC}"
echo ""

echo -e "${BLUE}Step 7: Resolve DID again (should have new service)${NC}"
echo "Running: ./did-char resolve $DID"
UPDATED_STATE=$(./did-char resolve $DID 2>&1)
echo "$UPDATED_STATE"

# Check if the new service is present
if echo "$UPDATED_STATE" | grep -q "github"; then
    echo -e "${GREEN}✓ Service 'github' found in updated DID!${NC}"
else
    echo -e "${RED}ERROR: Service 'github' NOT found in updated DID${NC}"
    exit 1
fi

# Count services after first update
UPDATED_SERVICE_COUNT=$(echo "$UPDATED_STATE" | grep -c '"type"' || echo "0")
echo -e "${GREEN}✓ Updated service count: $UPDATED_SERVICE_COUNT${NC}"
echo ""

echo -e "${BLUE}Step 8: Create second service endpoint JSON${NC}"
cat > test_service_2.json <<'EOF'
{
  "id": "#website",
  "type": "LinkedDomains",
  "serviceEndpoint": "https://example.com"
}
EOF
echo "Created test_service_2.json:"
cat test_service_2.json
echo ""

echo -e "${BLUE}Step 9: Update DID again - Add second service${NC}"
echo "Running: ./did-char update $DID --add-service test_service_2.json --verbose"
UPDATE_OUTPUT_2=$(./did-char update "$DID" --add-service test_service_2.json --verbose 2>&1)
echo "$UPDATE_OUTPUT_2"

if echo "$UPDATE_OUTPUT_2" | grep -q "error\|failed"; then
    echo -e "${RED}ERROR: Second update failed${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Second update submitted${NC}"
echo ""

# Wait for the update to be processed
sleep 2

echo -e "${BLUE}Step 10: Sync to get the second update${NC}"
echo "Running: ./did-char sync --verbose"
./did-char sync --verbose
echo -e "${GREEN}✓ Sync complete${NC}"
echo ""

echo -e "${BLUE}Step 11: Resolve DID final time (should have both services)${NC}"
echo "Running: ./did-char resolve $DID"
FINAL_STATE=$(./did-char resolve $DID 2>&1)
echo "$FINAL_STATE"

# Check if both services are present
GITHUB_FOUND=false
WEBSITE_FOUND=false

if echo "$FINAL_STATE" | grep -q "github"; then
    echo -e "${GREEN}✓ Service 'github' found!${NC}"
    GITHUB_FOUND=true
else
    echo -e "${RED}✗ Service 'github' NOT found${NC}"
fi

if echo "$FINAL_STATE" | grep -q "example.com"; then
    echo -e "${GREEN}✓ Service 'website' found!${NC}"
    WEBSITE_FOUND=true
else
    echo -e "${RED}✗ Service 'website' NOT found${NC}"
fi

# Count services after second update
FINAL_SERVICE_COUNT=$(echo "$FINAL_STATE" | grep -c '"type"' || echo "0")
echo -e "${GREEN}✓ Final service count: $FINAL_SERVICE_COUNT${NC}"
echo ""

echo "========================================="
echo "Test Summary:"
echo "========================================="
echo "DID: $DID"
echo "Initial services: $INITIAL_SERVICE_COUNT"
echo "After first update: $UPDATED_SERVICE_COUNT"
echo "After second update: $FINAL_SERVICE_COUNT"
echo ""

if [ "$GITHUB_FOUND" = true ] && [ "$WEBSITE_FOUND" = true ]; then
    echo -e "${GREEN}✓✓✓ ALL TESTS PASSED! ✓✓✓${NC}"
    exit 0
else
    echo -e "${RED}✗✗✗ TESTS FAILED ✗✗✗${NC}"
    exit 1
fi
