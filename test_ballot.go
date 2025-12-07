package main

import (
	"encoding/json"
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

	for ballotNum := 0; ballotNum <= 2; ballotNum++ {
		roll, err := client.GetReferendumDecisionRoll(cfg.AppPreimage, ballotNum, 1)
		if err != nil {
			fmt.Printf("Ballot %d: ERROR - %v\n", ballotNum, err)
			continue
		}

		fmt.Printf("\n=== Ballot %d ===\n", ballotNum)
		fmt.Printf("Found: %v\n", roll.Found)
		if roll.Found {
			if roll.DecisionRoll != nil {
				fmt.Printf("Data (hex, first 200 chars): %s\n", truncate(roll.DecisionRoll.Data, 200))
				fmt.Printf("Data length: %d\n", len(roll.DecisionRoll.Data))

				// Print full structure
				jsonBytes, _ := json.MarshalIndent(roll, "", "  ")
				fmt.Printf("Full response:\n%s\n", string(jsonBytes))
			} else {
				fmt.Printf("DecisionRoll is nil!\n")
			}
		}
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
