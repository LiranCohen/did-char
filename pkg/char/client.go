package char

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
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

// rpcCall executes a bitcoin-cli RPC command
func (c *Client) rpcCall(method string, params ...interface{}) ([]byte, error) {
	// Build bitcoin-cli command
	args := c.cfg.BitcoinCLIArgs()
	args = append(args, method)

	// Add parameters
	for _, param := range params {
		switch v := param.(type) {
		case string:
			args = append(args, v)
		case int:
			args = append(args, fmt.Sprintf("%d", v))
		case bool:
			args = append(args, fmt.Sprintf("%t", v))
		default:
			// For complex types, marshal to JSON
			jsonBytes, err := json.Marshal(v)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal parameter: %w", err)
			}
			args = append(args, string(jsonBytes))
		}
	}

	// Execute command
	cmd := exec.Command("bitcoin-cli", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("bitcoin-cli error: %s: %w", stderr.String(), err)
	}

	return stdout.Bytes(), nil
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
