package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

func writeCompactSize(buf *bytes.Buffer, n uint64) {
	if n < 0xfd {
		buf.WriteByte(byte(n))
	} else if n <= 0xffff {
		buf.WriteByte(0xfd)
		binary.Write(buf, binary.LittleEndian, uint16(n))
	} else if n <= 0xffffffff {
		buf.WriteByte(0xfe)
		binary.Write(buf, binary.LittleEndian, uint32(n))
	} else {
		buf.WriteByte(0xff)
		binary.Write(buf, binary.LittleEndian, n)
	}
}

func encodeReferendumVote(ballotNumber int, payloadHex string) string {
	payload, _ := hex.DecodeString(payloadHex)
	buf := new(bytes.Buffer)
	buf.WriteByte(0x00) // leaf type
	writeCompactSize(buf, uint64(ballotNumber))
	writeCompactSize(buf, uint64(len(payload)))
	buf.Write(payload)
	return hex.EncodeToString(buf.Bytes())
}

func main() {
	// Test with ballot 0
	testPayload := "68656c6c6f"  // "hello"
	vote0 := encodeReferendumVote(0, testPayload)
	fmt.Printf("Ballot 0: %s\n", vote0)

	// Test with ballot 298
	vote298 := encodeReferendumVote(298, testPayload)
	fmt.Printf("Ballot 298: %s\n", vote298)

	// Test with ballot 340
	vote340 := encodeReferendumVote(340, testPayload)
	fmt.Printf("Ballot 340: %s\n", vote340)
}
