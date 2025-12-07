package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// Config holds all configuration for the did-char CLI
type Config struct {
	CHAR     CHARConfig     `yaml:"char"`
	Database DatabaseConfig `yaml:"database"`
	Polling  PollingConfig  `yaml:"polling"`
}

// CHARConfig contains CHAR node connection settings
type CHARConfig struct {
	RPCHost     string `yaml:"rpc_host"`
	RPCPort     int    `yaml:"rpc_port"`
	RPCUser     string `yaml:"rpc_user"`
	RPCPassword string `yaml:"rpc_password"`
	Network     string `yaml:"network"`
	AppDomain   string `yaml:"app_domain"`
	AppPreimage string `yaml:"app_preimage"`
}

// DatabaseConfig contains database settings
type DatabaseConfig struct {
	Path string `yaml:"path"`
}

// PollingConfig contains polling behavior settings
type PollingConfig struct {
	MaxAttempts    int `yaml:"max_attempts"`
	IntervalMS     int `yaml:"interval_ms"`
	TimeoutSeconds int `yaml:"timeout_seconds"`
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	return &Config{
		CHAR: CHARConfig{
			RPCHost:     "100.67.0.7",
			RPCPort:     18443,
			RPCUser:     "char",
			RPCPassword: "char",
			Network:     "regtest",
			AppDomain:   "did-char-domain",
			AppPreimage: "did-char-domain", // Plain text, will be hex-encoded by client
		},
		Database: DatabaseConfig{
			Path: "./did-char.db",
		},
		Polling: PollingConfig{
			MaxAttempts:    300,  // Poll for up to 30 seconds
			IntervalMS:     100,  // Check every 100ms
			TimeoutSeconds: 10,
		},
	}
}

// LoadConfig loads configuration from file or environment variables
func LoadConfig(cfgFile string) (*Config, error) {
	cfg := DefaultConfig()

	// If config file specified, try to load it
	if cfgFile != "" {
		// For now, just use defaults
		// TODO: Implement YAML parsing if needed
		if _, err := os.Stat(cfgFile); err != nil {
			return nil, fmt.Errorf("config file not found: %w", err)
		}
	}

	// Override with environment variables
	if val := os.Getenv("CHAR_RPC_HOST"); val != "" {
		cfg.CHAR.RPCHost = val
	}
	if val := os.Getenv("CHAR_RPC_PORT"); val != "" {
		fmt.Sscanf(val, "%d", &cfg.CHAR.RPCPort)
	}
	if val := os.Getenv("CHAR_RPC_USER"); val != "" {
		cfg.CHAR.RPCUser = val
	}
	if val := os.Getenv("CHAR_RPC_PASSWORD"); val != "" {
		cfg.CHAR.RPCPassword = val
	}
	if val := os.Getenv("CHAR_APP_DOMAIN"); val != "" {
		cfg.CHAR.AppDomain = val
	}
	if val := os.Getenv("DB_PATH"); val != "" {
		cfg.Database.Path = val
	}

	// Ensure database directory exists
	dbDir := filepath.Dir(cfg.Database.Path)
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	return cfg, nil
}

// BitcoinCLIArgs returns the bitcoin-cli arguments for CHAR node
func (c *CHARConfig) BitcoinCLIArgs() []string {
	return []string{
		"-" + c.Network,
		"-rpcconnect=" + c.RPCHost,
		fmt.Sprintf("-rpcport=%d", c.RPCPort),
		"-rpcuser=" + c.RPCUser,
		"-rpcpassword=" + c.RPCPassword,
	}
}
