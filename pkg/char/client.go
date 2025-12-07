package char

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/yourusername/did-char/pkg/config"
)

// Client wraps bitcoin-cli for CHAR RPC calls
type Client struct {
	cfg *config.CHARConfig
}

// NewClient creates a new CHAR RPC client
func NewClient(cfg *config.CHARConfig) *Client {
	return &Client{cfg: cfg}
}

// RPCRequest represents a JSON-RPC request
type RPCRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      string        `json:"id"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
}

// RPCResponse represents a JSON-RPC response
type RPCResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *RPCError       `json:"error"`
	ID     string          `json:"id"`
}

// RPCError represents a JSON-RPC error
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// rpcCall executes a JSON-RPC HTTP request
func (c *Client) rpcCall(method string, params ...interface{}) ([]byte, error) {
	// Build JSON-RPC request
	req := RPCRequest{
		JSONRPC: "1.0",
		ID:      "did-char",
		Method:  method,
		Params:  params,
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	url := fmt.Sprintf("http://%s:%d/", c.cfg.RPCHost, c.cfg.RPCPort)
	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "text/plain")
	httpReq.SetBasicAuth(c.cfg.RPCUser, c.cfg.RPCPassword)

	// Execute request
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse JSON-RPC response
	var rpcResp RPCResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Check for RPC error
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("RPC error code %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	return rpcResp.Result, nil
}

// AddBambooKV submits a key-value pair via addbambookv
func (c *Client) AddBambooKV(appPreimage, dataHex string, slotize bool) (AddBambooKVResponse, error) {
	// Convert appPreimage to hex
	appPreimageHex := stringToHex(appPreimage)

	// Build the bamboo KV array
	bambooKV := []map[string]string{
		{appPreimageHex: dataHex},
	}

	result, err := c.rpcCall("addbambookv", bambooKV, slotize)
	if err != nil {
		return nil, fmt.Errorf("addbambookv failed: %w", err)
	}

	var response AddBambooKVResponse
	if err := json.Unmarshal(result, &response); err != nil {
		return nil, fmt.Errorf("failed to parse addbambookv response: %w", err)
	}

	return response, nil
}

// GetReferendumDecisionRoll queries a ballot's decision roll
func (c *Client) GetReferendumDecisionRoll(domain string, ballotNumber, verbosity int) (*DecisionRollResponse, error) {
	// Convert domain to hex
	domainHex := stringToHex(domain)

	result, err := c.rpcCall("getreferendumdecisionroll", domainHex, ballotNumber, verbosity)
	if err != nil {
		return nil, fmt.Errorf("getreferendumdecisionroll failed: %w", err)
	}

	var response DecisionRollResponse
	if err := json.Unmarshal(result, &response); err != nil {
		return nil, fmt.Errorf("failed to parse getreferendumdecisionroll response: %w", err)
	}

	return &response, nil
}

// stringToHex converts a string to hex encoding
func stringToHex(s string) string {
	return fmt.Sprintf("%x", s)
}

// GetNextAvailableBallot finds the next empty ballot by searching forward
func (c *Client) GetNextAvailableBallot(domain string, startFrom int) (int, error) {
	// Search forward from startFrom, looking for an empty ballot
	// Check up to 50 ballots ahead
	for i := 0; i < 50; i++ {
		ballotNum := startFrom + i
		roll, err := c.GetReferendumDecisionRoll(domain, ballotNum, 0)
		if err != nil {
			return 0, fmt.Errorf("failed to query ballot %d: %w", ballotNum, err)
		}

		if !roll.Found {
			// Ballot doesn't exist yet - use this number (it will exist soon)
			// Ballots are created every 20 seconds
			return ballotNum, nil
		}

		// Check if ballot is empty (no data or data is empty)
		if roll.DecisionRoll == nil || roll.DecisionRoll.Data == "" || len(roll.DecisionRoll.Data) == 0 {
			return ballotNum, nil
		}
	}

	return 0, fmt.Errorf("no empty ballot found in range %d to %d", startFrom, startFrom+50)
}

// wrapInSlotFormat wraps data in CHAR slot format
// Format: [0x00][0x00][CompactSize length][data]
func wrapInSlotFormat(dataHex string) string {
	data, err := hex.DecodeString(dataHex)
	if err != nil {
		return ""
	}

	buf := new(bytes.Buffer)

	// Slot format prefix: 0000
	buf.WriteByte(0x00)
	buf.WriteByte(0x00)

	// Data length as CompactSize
	writeCompactSize(buf, uint64(len(data)))

	// Data
	buf.Write(data)

	return hex.EncodeToString(buf.Bytes())
}

// encodeReferendumVote encodes a referendum vote
// Format: [0x00][varint ballot_number][compact_size payload_len][payload]
func encodeReferendumVote(ballotNumber int, payloadHex string) string {
	payload, err := hex.DecodeString(payloadHex)
	if err != nil {
		// If decode fails, return empty - will cause submission to fail
		return ""
	}

	buf := new(bytes.Buffer)

	// Leaf type = 0x00 for REFERENDUM_VOTE
	buf.WriteByte(0x00)

	// Ballot number as varint
	writeVarint(buf, uint64(ballotNumber))

	// Payload length as CompactSize
	writeCompactSize(buf, uint64(len(payload)))

	// Payload
	buf.Write(payload)

	return hex.EncodeToString(buf.Bytes())
}

// writeVarint writes a Bitcoin-style varint
func writeVarint(buf *bytes.Buffer, n uint64) {
	tmp := make([]byte, binary.MaxVarintLen64)
	size := binary.PutUvarint(tmp, n)
	buf.Write(tmp[:size])
}

// writeCompactSize writes a Bitcoin-style CompactSize
func writeCompactSize(buf *bytes.Buffer, n uint64) {
	if n < 0xfd {
		buf.WriteByte(byte(n))
	} else if n <= 0xffff {
		buf.WriteByte(0xfd)
		binary.Write(buf, binary.LittleEndian, uint16(n))
	} else if n <= 0xffffffff {
		buf.WriteByte(0xfe)
		binary.Write(buf, binary.LittleEndian, uint32(n))
	} else {
		buf.WriteByte(0xff)
		binary.Write(buf, binary.LittleEndian, n)
	}
}

// PollForConfirmation polls until a ballot is confirmed (found: true) and has data
func (c *Client) PollForConfirmation(domain string, ballotNumber int, maxAttempts int, interval time.Duration) (*DecisionRollResponse, error) {
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		roll, err := c.GetReferendumDecisionRoll(domain, ballotNumber, 1)
		if err != nil {
			return nil, fmt.Errorf("poll attempt %d failed: %w", attempt, err)
		}

		if roll.Found {
			// Check if decision roll has data
			if roll.DecisionRoll != nil && roll.DecisionRoll.Data != "" {
				return roll, nil
			}
			// Ballot found but no data yet - keep polling
		}

		if attempt < maxAttempts {
			time.Sleep(interval)
		}
	}

	return nil, fmt.Errorf("timeout: ballot %d not confirmed with data after %d attempts", ballotNumber, maxAttempts)
}

// SubmitAndWaitForConfirmation submits a referendum vote and polls until confirmed
func (c *Client) SubmitAndWaitForConfirmation(appPreimage, dataHex string, ballotNumber int, pollingCfg config.PollingConfig) (*DecisionRollResponse, error) {
	// Encode as referendum vote
	voteHex := encodeReferendumVote(ballotNumber, dataHex)

	// Submit with slotize=true (let CHAR wrap in slot format)
	response, err := c.AddBambooKV(appPreimage, voteHex, true)
	if err != nil {
		return nil, fmt.Errorf("failed to submit vote: %w", err)
	}

	// Check if submission was successful
	// Response key is hex-encoded domain
	appPreimageHex := stringToHex(appPreimage)
	if !response[appPreimageHex] {
		return nil, fmt.Errorf("vote submission failed for app preimage %s (hex: %s)", appPreimage, appPreimageHex)
	}

	// Poll for confirmation
	interval := time.Duration(pollingCfg.IntervalMS) * time.Millisecond
	roll, err := c.PollForConfirmation(appPreimage, ballotNumber, pollingCfg.MaxAttempts, interval)
	if err != nil {
		return nil, fmt.Errorf("failed to confirm ballot: %w", err)
	}

	return roll, nil
}
