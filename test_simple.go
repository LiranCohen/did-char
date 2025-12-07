package main

import (
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

	// Try submitting plain data with slotize=true (let CHAR wrap it)
	testData := "68656c6c6f" // "hello"
	
	fmt.Println("Testing with slotize=true...")
	resp, err := client.AddBambooKV(cfg.AppPreimage, testData, true)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Success! Response: %+v\n", resp)
	}
}
