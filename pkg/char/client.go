package char

import (
	"bytes"
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
	// Build the bamboo KV array
	bambooKV := []map[string]string{
		{appPreimage: dataHex},
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
	result, err := c.rpcCall("getreferendumdecisionroll", domain, ballotNumber, verbosity)
	if err != nil {
		return nil, fmt.Errorf("getreferendumdecisionroll failed: %w", err)
	}

	var response DecisionRollResponse
	if err := json.Unmarshal(result, &response); err != nil {
		return nil, fmt.Errorf("failed to parse getreferendumdecisionroll response: %w", err)
	}

	return &response, nil
}

// PollForConfirmation polls until a ballot is confirmed (found: true)
func (c *Client) PollForConfirmation(domain string, ballotNumber int, maxAttempts int, interval time.Duration) (*DecisionRollResponse, error) {
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		roll, err := c.GetReferendumDecisionRoll(domain, ballotNumber, 1)
		if err != nil {
			return nil, fmt.Errorf("poll attempt %d failed: %w", attempt, err)
		}

		if roll.Found {
			return roll, nil
		}

		if attempt < maxAttempts {
			time.Sleep(interval)
		}
	}

	return nil, fmt.Errorf("timeout: ballot %d not confirmed after %d attempts", ballotNumber, maxAttempts)
}

// SubmitAndWaitForConfirmation submits a referendum vote and polls until confirmed
func (c *Client) SubmitAndWaitForConfirmation(appPreimage, dataHex string, ballotNumber int, pollingCfg config.PollingConfig) (*DecisionRollResponse, error) {
	// Submit the vote
	response, err := c.AddBambooKV(appPreimage, dataHex, true)
	if err != nil {
		return nil, fmt.Errorf("failed to submit vote: %w", err)
	}

	// Check if submission was successful
	if !response[appPreimage] {
		return nil, fmt.Errorf("vote submission failed for app preimage %s", appPreimage)
	}

	// Poll for confirmation
	interval := time.Duration(pollingCfg.IntervalMS) * time.Millisecond
	roll, err := c.PollForConfirmation(appPreimage, ballotNumber, pollingCfg.MaxAttempts, interval)
	if err != nil {
		return nil, fmt.Errorf("failed to confirm ballot: %w", err)
	}

	return roll, nil
}
