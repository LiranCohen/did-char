package main

import (
	"encoding/hex"
	"fmt"

	"github.com/yourusername/did-char/pkg/char"
	"github.com/yourusername/did-char/pkg/config"
)

func main() {
	cfg := &config.CHARConfig{
		RPCHost:     "100.67.0.7",
		RPCPort:     18443,
		RPCUser:     "char",
		RPCPassword: "char",
		AppPreimage: "did-char-domain",
	}

	client := char.NewClient(cfg)

	// Simple test payload
	testPayload := "68656c6c6f776f726c64" // "helloworld" in hex

	// Manually encode as referendum vote for ballot 255
	ballotNum := 255

	// Decode the hex payload
	payloadBytes, _ := hex.DecodeString(testPayload)

	// Build referendum vote manually:
	// [0x00][varint ballot][compact_size len][payload]
	voteBytes := []byte{0x00} // leaf type

	// Ballot number as varint
	voteBytes = append(voteBytes, byte(ballotNum)) // Simple varint for small numbers

	// Payload length as compact size
	voteBytes = append(voteBytes, byte(len(payloadBytes)))

	// Payload
	voteBytes = append(voteBytes, payloadBytes...)

	voteHex := hex.EncodeToString(voteBytes)

	fmt.Printf("Test submission:\n")
	fmt.Printf("  Ballot: %d\n", ballotNum)
	fmt.Printf("  Original payload: %s\n", testPayload)
	fmt.Printf("  Vote hex: %s\n", voteHex)
	fmt.Printf("  Vote bytes: %d\n", len(voteBytes))

	// Submit
	response, err := client.AddBambooKV(cfg.AppPreimage, voteHex, false)
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
		return
	}

	fmt.Printf("\nResponse: %+v\n", response)

	// Check response
	domainHex := fmt.Sprintf("%x", cfg.AppPreimage)
	if accepted, ok := response[domainHex]; ok {
		fmt.Printf("Accepted: %v\n", accepted)
	} else {
		fmt.Printf("Domain key not found in response\n")
		fmt.Printf("Response keys:\n")
		for k, v := range response {
			fmt.Printf("  %s: %v\n", k, v)
		}
	}

	// Wait and check if it made it into the decision roll
	fmt.Printf("\nWaiting 5 seconds for ballot to be decided...\n")
	// time.Sleep(5 * time.Second)

	roll, err := client.GetReferendumDecisionRoll(cfg.AppPreimage, ballotNum, 1)
	if err != nil {
		fmt.Printf("ERROR checking ballot: %v\n", err)
		return
	}

	fmt.Printf("\nBallot %d:\n", ballotNum)
	fmt.Printf("  Found: %v\n", roll.Found)
	if roll.Found && roll.DecisionRoll != nil {
		fmt.Printf("  Has data: %v\n", roll.DecisionRoll.Data != "")
		if roll.DecisionRoll.Data != "" {
			fmt.Printf("  Data length: %d\n", len(roll.DecisionRoll.Data))
			fmt.Printf("  Data (first 100): %s\n", roll.DecisionRoll.Data[:min(100, len(roll.DecisionRoll.Data))])
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
