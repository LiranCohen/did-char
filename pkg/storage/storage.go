package storage

import (
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
)

// Store manages the SQLite database
type Store struct {
	db *sql.DB
}

// NewStore creates a new storage instance
func NewStore(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	store := &Store{db: db}

	// Run migrations
	if err := store.migrate(); err != nil {
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	return store, nil
}

// Close closes the database connection
func (s *Store) Close() error {
	return s.db.Close()
}

// migrate creates the database schema
func (s *Store) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS dids (
		did TEXT PRIMARY KEY,
		status TEXT NOT NULL CHECK(status IN ('active', 'deactivated')),
		document TEXT NOT NULL,
		update_commitment TEXT,
		recovery_commitment TEXT,
		created_at_ballot INTEGER NOT NULL,
		last_operation_ballot INTEGER NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS operations (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		did TEXT NOT NULL,
		ballot_number INTEGER NOT NULL,
		operation_type TEXT NOT NULL CHECK(operation_type IN ('create', 'update', 'recover', 'deactivate')),
		operation_data TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (did) REFERENCES dids(did),
		UNIQUE(ballot_number)
	);

	CREATE INDEX IF NOT EXISTS idx_operations_ballot ON operations(ballot_number);
	CREATE INDEX IF NOT EXISTS idx_operations_did ON operations(did);

	CREATE TABLE IF NOT EXISTS sync_state (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	`

	_, err := s.db.Exec(schema)
	return err
}

// SetSyncState sets a sync state value
func (s *Store) SetSyncState(key, value string) error {
	_, err := s.db.Exec(`
		INSERT INTO sync_state (key, value, updated_at)
		VALUES (?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(key) DO UPDATE SET
			value = excluded.value,
			updated_at = CURRENT_TIMESTAMP
	`, key, value)
	return err
}

// GetSyncState gets a sync state value
func (s *Store) GetSyncState(key string) (string, error) {
	var value string
	err := s.db.QueryRow("SELECT value FROM sync_state WHERE key = ?", key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}
