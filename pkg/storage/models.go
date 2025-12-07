package storage

import (
	"database/sql"
	"time"
)

// DIDRecord represents a DID in the database
type DIDRecord struct {
	DID                  string
	Status               string
	Document             string
	UpdateCommitment     string
	RecoveryCommitment   string
	CreatedAtBallot      int
	LastOperationBallot  int
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// OperationRecord represents an operation in the database
type OperationRecord struct {
	ID            int
	DID           string
	BallotNumber  int
	OperationType string
	OperationData string
	CreatedAt     time.Time
}

// SaveDID saves or updates a DID record
func (s *Store) SaveDID(record *DIDRecord) error {
	_, err := s.db.Exec(`
		INSERT INTO dids (
			did, status, document, update_commitment, recovery_commitment,
			created_at_ballot, last_operation_ballot, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(did) DO UPDATE SET
			status = excluded.status,
			document = excluded.document,
			update_commitment = excluded.update_commitment,
			recovery_commitment = excluded.recovery_commitment,
			last_operation_ballot = excluded.last_operation_ballot,
			updated_at = CURRENT_TIMESTAMP
	`, record.DID, record.Status, record.Document, record.UpdateCommitment,
		record.RecoveryCommitment, record.CreatedAtBallot, record.LastOperationBallot)
	return err
}

// GetDID retrieves a DID record by DID
func (s *Store) GetDID(did string) (*DIDRecord, error) {
	record := &DIDRecord{}
	err := s.db.QueryRow(`
		SELECT did, status, document, update_commitment, recovery_commitment,
			   created_at_ballot, last_operation_ballot, created_at, updated_at
		FROM dids WHERE did = ?
	`, did).Scan(
		&record.DID, &record.Status, &record.Document, &record.UpdateCommitment,
		&record.RecoveryCommitment, &record.CreatedAtBallot, &record.LastOperationBallot,
		&record.CreatedAt, &record.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return record, err
}

// SaveOperation saves an operation record
func (s *Store) SaveOperation(record *OperationRecord) error {
	_, err := s.db.Exec(`
		INSERT INTO operations (did, ballot_number, operation_type, operation_data)
		VALUES (?, ?, ?, ?)
	`, record.DID, record.BallotNumber, record.OperationType, record.OperationData)
	return err
}

// GetOperations retrieves all operations for a DID
func (s *Store) GetOperations(did string) ([]*OperationRecord, error) {
	rows, err := s.db.Query(`
		SELECT id, did, ballot_number, operation_type, operation_data, created_at
		FROM operations WHERE did = ?
		ORDER BY ballot_number ASC
	`, did)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ops []*OperationRecord
	for rows.Next() {
		op := &OperationRecord{}
		if err := rows.Scan(&op.ID, &op.DID, &op.BallotNumber, &op.OperationType, &op.OperationData, &op.CreatedAt); err != nil {
			return nil, err
		}
		ops = append(ops, op)
	}
	return ops, rows.Err()
}

// GetLastBallotNumber gets the highest ballot number processed
func (s *Store) GetLastBallotNumber() (int, error) {
	var ballot int
	err := s.db.QueryRow("SELECT COALESCE(MAX(ballot_number), -1) FROM operations").Scan(&ballot)
	return ballot, err
}

// GetAllDIDs retrieves all DIDs
func (s *Store) GetAllDIDs() ([]*DIDRecord, error) {
	rows, err := s.db.Query(`
		SELECT did, status, document, update_commitment, recovery_commitment,
			   created_at_ballot, last_operation_ballot, created_at, updated_at
		FROM dids
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var dids []*DIDRecord
	for rows.Next() {
		record := &DIDRecord{}
		if err := rows.Scan(
			&record.DID, &record.Status, &record.Document, &record.UpdateCommitment,
			&record.RecoveryCommitment, &record.CreatedAtBallot, &record.LastOperationBallot,
			&record.CreatedAt, &record.UpdatedAt,
		); err != nil {
			return nil, err
		}
		dids = append(dids, record)
	}
	return dids, rows.Err()
}

// GetDIDCount returns the count of DIDs by status
func (s *Store) GetDIDCount(status string) (int, error) {
	var count int
	var err error
	if status == "" {
		err = s.db.QueryRow("SELECT COUNT(*) FROM dids").Scan(&count)
	} else {
		err = s.db.QueryRow("SELECT COUNT(*) FROM dids WHERE status = ?", status).Scan(&count)
	}
	return count, err
}

// GetOperationCount returns the total number of operations
func (s *Store) GetOperationCount() (int, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM operations").Scan(&count)
	return count, err
}

// DIDExists checks if a DID exists
func (s *Store) DIDExists(did string) (bool, error) {
	var exists bool
	err := s.db.QueryRow("SELECT EXISTS(SELECT 1 FROM dids WHERE did = ?)", did).Scan(&exists)
	return exists, err
}

// GetRecentOperations gets the N most recent operations
func (s *Store) GetRecentOperations(limit int) ([]*OperationRecord, error) {
	rows, err := s.db.Query(`
		SELECT id, did, ballot_number, operation_type, operation_data, created_at
		FROM operations
		ORDER BY ballot_number DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ops []*OperationRecord
	for rows.Next() {
		op := &OperationRecord{}
		if err := rows.Scan(&op.ID, &op.DID, &op.BallotNumber, &op.OperationType, &op.OperationData, &op.CreatedAt); err != nil {
			return nil, err
		}
		ops = append(ops, op)
	}
	return ops, rows.Err()
}
