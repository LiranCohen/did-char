package encoding

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
)

const PayloadVersion byte = 0x01

// OperationType represents the type of DID operation
type OperationType byte

const (
	OperationTypeCreate     OperationType = 0x01
	OperationTypeUpdate     OperationType = 0x02
	OperationTypeRecover    OperationType = 0x03
	OperationTypeDeactivate OperationType = 0x04
)

// EncodePayload encodes a DID operation into a binary payload
func EncodePayload(opType OperationType, didSuffix string, operationData interface{}) (string, error) {
	buf := new(bytes.Buffer)

	// Version
	buf.WriteByte(PayloadVersion)

	// Operation type
	buf.WriteByte(byte(opType))

	// DID suffix
	suffixBytes := []byte(didSuffix)
	if err := writeVarint(buf, uint64(len(suffixBytes))); err != nil {
		return "", err
	}
	buf.Write(suffixBytes)

	// Operation data as JSON
	jsonBytes, err := json.Marshal(operationData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal operation data: %w", err)
	}

	if err := writeVarint(buf, uint64(len(jsonBytes))); err != nil {
		return "", err
	}
	buf.Write(jsonBytes)

	// Return as hex string
	return hex.EncodeToString(buf.Bytes()), nil
}

// DecodePayload decodes a binary payload into operation components
func DecodePayload(hexData string) (version byte, opType OperationType, didSuffix string, operationJSON []byte, err error) {
	data, err := hex.DecodeString(hexData)
	if err != nil {
		return 0, 0, "", nil, fmt.Errorf("invalid hex: %w", err)
	}

	buf := bytes.NewReader(data)

	// Version
	version, err = buf.ReadByte()
	if err != nil {
		return 0, 0, "", nil, fmt.Errorf("failed to read version: %w", err)
	}

	// Operation type
	opTypeByte, err := buf.ReadByte()
	if err != nil {
		return 0, 0, "", nil, fmt.Errorf("failed to read operation type: %w", err)
	}
	opType = OperationType(opTypeByte)

	// DID suffix
	suffixLen, err := readVarint(buf)
	if err != nil {
		return 0, 0, "", nil, fmt.Errorf("failed to read suffix length: %w", err)
	}
	suffixBytes := make([]byte, suffixLen)
	if _, err := io.ReadFull(buf, suffixBytes); err != nil {
		return 0, 0, "", nil, fmt.Errorf("failed to read suffix: %w", err)
	}
	didSuffix = string(suffixBytes)

	// Operation JSON
	jsonLen, err := readVarint(buf)
	if err != nil {
		return 0, 0, "", nil, fmt.Errorf("failed to read JSON length: %w", err)
	}
	operationJSON = make([]byte, jsonLen)
	if _, err := io.ReadFull(buf, operationJSON); err != nil {
		return 0, 0, "", nil, fmt.Errorf("failed to read JSON: %w", err)
	}

	return version, opType, didSuffix, operationJSON, nil
}

// writeVarint writes a varint to the buffer
func writeVarint(buf *bytes.Buffer, n uint64) error {
	tmp := make([]byte, binary.MaxVarintLen64)
	size := binary.PutUvarint(tmp, n)
	_, err := buf.Write(tmp[:size])
	return err
}

// readVarint reads a varint from the reader
func readVarint(r io.ByteReader) (uint64, error) {
	return binary.ReadUvarint(r)
}
