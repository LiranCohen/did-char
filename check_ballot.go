package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/yourusername/did-char/pkg/char"
	"github.com/yourusername/did-char/pkg/config"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run check_ballot.go <ballot_number>")
		os.Exit(1)
	}

	ballotNum, _ := strconv.Atoi(os.Args[1])

	cfg := &config.CHARConfig{
		RPCHost:     "100.67.0.7",
		RPCPort:     18443,
		RPCUser:     "char",
		RPCPassword: "char",
		AppPreimage: "did-char-domain",
	}

	client := char.NewClient(cfg)
	roll, err := client.GetReferendumDecisionRoll(cfg.AppPreimage, ballotNum, 0)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Ballot %d:\n", ballotNum)
	fmt.Printf("  Found: %v\n", roll.Found)
	if roll.Found {
		fmt.Printf("  Leader: %s\n", roll.Leader)
		fmt.Printf("  Leader is mine: %v\n", roll.LeaderIsMine)
		if roll.DecisionRoll != nil {
			fmt.Printf("  Data length: %d\n", len(roll.DecisionRoll.Data))
		}
	}
}
