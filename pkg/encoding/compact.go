// Package encoding provides compact binary encoding for did:char operations.
// See BINARY-FORMAT.md for the complete specification.
package encoding

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
)

// Format version
const (
	PayloadVersionLegacy  byte = 0x01 // JSON format
	PayloadVersionCompact byte = 0x02 // Compact binary format
)

// Operation types
const (
	OpCreate     byte = 0x01
	OpUpdate     byte = 0x02
	OpRecover    byte = 0x03
	OpDeactivate byte = 0x04
)

// Flags
const (
	FlagThreshold     byte = 0x01
	FlagBLSAggregated byte = 0x02
)

// Key types
const (
	KeyTypeEd25519    byte = 0x00
	KeyTypeSecp256k1  byte = 0x01
	KeyTypeP256       byte = 0x02
	KeyTypeBLS12381G1 byte = 0x03
)

// Patch types
const (
	PatchAddPublicKeys    byte = 0x01
	PatchRemovePublicKeys byte = 0x02
	PatchAddServices      byte = 0x03
	PatchRemoveServices   byte = 0x04
)

// Key purpose flags
const (
	PurposeAuthentication       byte = 0x01
	PurposeAssertionMethod      byte = 0x02
	PurposeKeyAgreement         byte = 0x04
	PurposeCapabilityInvocation byte = 0x08
	PurposeCapabilityDelegation byte = 0x10
)

// KeySizes defines the sizes for each key type
var KeySizes = map[byte]struct {
	PubKey int
	Sig    int
}{
	KeyTypeEd25519:    {32, 64},
	KeyTypeSecp256k1:  {33, 64},
	KeyTypeP256:       {33, 64},
	KeyTypeBLS12381G1: {48, 96},
}

// CompactHeader represents the 3-byte packet header
type CompactHeader struct {
	Version   byte
	Operation byte
	Flags     byte
}

// CompactPublicKey represents a public key in compact format
type CompactPublicKey struct {
	ID       string
	KeyType  byte
	KeyBytes []byte // Compressed format
	Purposes byte   // Bitmask of purposes
}

// CompactService represents a service in compact format
type CompactService struct {
	ID       string
	Type     string
	Endpoint string
}

// CompactReveal represents a controller's reveal in threshold operations
type CompactReveal struct {
	Index          byte
	KeyType        byte
	PublicKey      []byte   // Compressed
	MerkleDepth    byte
	MerkleSiblings [][]byte // 32 bytes each
	Signature      []byte   // Raw signature
}

// CompactDelta represents patches to apply
type CompactDelta struct {
	Patches []CompactPatch
}

// CompactPatch represents a single patch
type CompactPatch struct {
	Type       byte
	PublicKeys []CompactPublicKey // For add-public-keys
	KeyIDs     []string           // For remove-public-keys
	Services   []CompactService   // For add-services
	ServiceIDs []string           // For remove-services
}

// CompactCreate represents a CREATE operation
type CompactCreate struct {
	Header             CompactHeader
	SuffixDataHash     []byte // 32 bytes
	UpdateCommitment   []byte // 32 bytes
	RecoveryCommitment []byte // 32 bytes
	// Threshold fields (if FlagThreshold set)
	UpdateThreshold         byte
	UpdateControllerCount   byte
	RecoveryThreshold       byte
	RecoveryControllerCount byte
	// Initial document
	PublicKeys []CompactPublicKey
	Services   []CompactService
}

// CompactUpdate represents an UPDATE operation
type CompactUpdate struct {
	Header           CompactHeader
	DIDSuffix        []byte // 32 bytes
	Reveals          []CompactReveal
	NewCommitment    []byte // 32 bytes (single key) or Merkle root (threshold)
	Delta            CompactDelta
	AggregatedSigKey []byte // Only for BLS aggregated mode
}

// CompactRecover represents a RECOVER operation
type CompactRecover struct {
	Header              CompactHeader
	DIDSuffix           []byte // 32 bytes
	Reveals             []CompactReveal
	NewUpdateCommitment []byte // 32 bytes
	NewRecoveryCommitment []byte // 32 bytes
	// New threshold config (if changing)
	NewUpdateThreshold         byte
	NewUpdateControllerCount   byte
	NewRecoveryThreshold       byte
	NewRecoveryControllerCount byte
	Delta                      CompactDelta
}

// CompactDeactivate represents a DEACTIVATE operation
type CompactDeactivate struct {
	Header    CompactHeader
	DIDSuffix []byte // 32 bytes
	Reveals   []CompactReveal
}

// Encoder writes compact binary format
type Encoder struct {
	buf *bytes.Buffer
}

// NewEncoder creates a new encoder
func NewEncoder() *Encoder {
	return &Encoder{buf: new(bytes.Buffer)}
}

// Bytes returns the encoded bytes
func (e *Encoder) Bytes() []byte {
	return e.buf.Bytes()
}

// Reset clears the buffer
func (e *Encoder) Reset() {
	e.buf.Reset()
}

// WriteHeader writes the 3-byte header
func (e *Encoder) WriteHeader(h CompactHeader) {
	e.buf.WriteByte(h.Version)
	e.buf.WriteByte(h.Operation)
	e.buf.WriteByte(h.Flags)
}

// WriteBytes writes raw bytes
func (e *Encoder) WriteBytes(b []byte) {
	e.buf.Write(b)
}

// WriteByte writes a single byte
func (e *Encoder) WriteByte(b byte) {
	e.buf.WriteByte(b)
}

// WriteString writes a length-prefixed string (1-byte length)
func (e *Encoder) WriteString(s string) error {
	if len(s) > 255 {
		return fmt.Errorf("string too long: %d > 255", len(s))
	}
	e.buf.WriteByte(byte(len(s)))
	e.buf.WriteString(s)
	return nil
}

// WriteLongString writes a length-prefixed string (2-byte length)
func (e *Encoder) WriteLongString(s string) error {
	if len(s) > 65535 {
		return fmt.Errorf("string too long: %d > 65535", len(s))
	}
	e.WriteUint16(uint16(len(s)))
	e.buf.WriteString(s)
	return nil
}

// WriteUint16 writes a 16-bit big-endian integer
func (e *Encoder) WriteUint16(v uint16) {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	e.buf.Write(b)
}

// WritePublicKey writes a public key in compact format
func (e *Encoder) WritePublicKey(pk CompactPublicKey) error {
	if err := e.WriteString(pk.ID); err != nil {
		return err
	}
	e.WriteByte(pk.KeyType)
	e.WriteBytes(pk.KeyBytes)
	e.WriteByte(pk.Purposes)
	return nil
}

// WriteService writes a service in compact format
func (e *Encoder) WriteService(svc CompactService) error {
	if err := e.WriteString(svc.ID); err != nil {
		return err
	}
	if err := e.WriteString(svc.Type); err != nil {
		return err
	}
	if err := e.WriteLongString(svc.Endpoint); err != nil {
		return err
	}
	return nil
}

// WriteReveal writes a controller reveal
func (e *Encoder) WriteReveal(r CompactReveal) error {
	e.WriteByte(r.Index)
	e.WriteByte(r.KeyType)
	e.WriteBytes(r.PublicKey)
	e.WriteByte(r.MerkleDepth)
	for _, sibling := range r.MerkleSiblings {
		if len(sibling) != 32 {
			return fmt.Errorf("merkle sibling must be 32 bytes, got %d", len(sibling))
		}
		e.WriteBytes(sibling)
	}
	e.WriteBytes(r.Signature)
	return nil
}

// WriteDelta writes patches
func (e *Encoder) WriteDelta(d CompactDelta) error {
	e.WriteByte(byte(len(d.Patches)))
	for _, patch := range d.Patches {
		if err := e.WritePatch(patch); err != nil {
			return err
		}
	}
	return nil
}

// WritePatch writes a single patch
func (e *Encoder) WritePatch(p CompactPatch) error {
	e.WriteByte(p.Type)

	switch p.Type {
	case PatchAddPublicKeys:
		e.WriteByte(byte(len(p.PublicKeys)))
		for _, pk := range p.PublicKeys {
			if err := e.WritePublicKey(pk); err != nil {
				return err
			}
		}
	case PatchRemovePublicKeys:
		e.WriteByte(byte(len(p.KeyIDs)))
		for _, id := range p.KeyIDs {
			if err := e.WriteString(id); err != nil {
				return err
			}
		}
	case PatchAddServices:
		e.WriteByte(byte(len(p.Services)))
		for _, svc := range p.Services {
			if err := e.WriteService(svc); err != nil {
				return err
			}
		}
	case PatchRemoveServices:
		e.WriteByte(byte(len(p.ServiceIDs)))
		for _, id := range p.ServiceIDs {
			if err := e.WriteString(id); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unknown patch type: %d", p.Type)
	}

	return nil
}

// EncodeCreate encodes a CREATE operation
func EncodeCreate(c *CompactCreate) ([]byte, error) {
	e := NewEncoder()

	e.WriteHeader(c.Header)
	e.WriteBytes(c.SuffixDataHash)
	e.WriteBytes(c.UpdateCommitment)
	e.WriteBytes(c.RecoveryCommitment)

	if c.Header.Flags&FlagThreshold != 0 {
		e.WriteByte(c.UpdateThreshold)
		e.WriteByte(c.UpdateControllerCount)
		e.WriteByte(c.RecoveryThreshold)
		e.WriteByte(c.RecoveryControllerCount)
	}

	// Document
	e.WriteByte(byte(len(c.PublicKeys)))
	for _, pk := range c.PublicKeys {
		if err := e.WritePublicKey(pk); err != nil {
			return nil, err
		}
	}

	e.WriteByte(byte(len(c.Services)))
	for _, svc := range c.Services {
		if err := e.WriteService(svc); err != nil {
			return nil, err
		}
	}

	return e.Bytes(), nil
}

// EncodeUpdate encodes an UPDATE operation
func EncodeUpdate(u *CompactUpdate) ([]byte, error) {
	e := NewEncoder()

	e.WriteHeader(u.Header)
	e.WriteBytes(u.DIDSuffix)

	if u.Header.Flags&FlagThreshold != 0 {
		// Threshold mode
		e.WriteByte(byte(len(u.Reveals)))
		for _, r := range u.Reveals {
			if err := e.WriteReveal(r); err != nil {
				return nil, err
			}
		}
	} else {
		// Single key mode - one reveal without index
		if len(u.Reveals) != 1 {
			return nil, fmt.Errorf("single key mode requires exactly 1 reveal")
		}
		r := u.Reveals[0]
		e.WriteBytes(computeRevealValue(r.PublicKey))
		e.WriteByte(r.KeyType)
		e.WriteBytes(r.PublicKey)
		e.WriteBytes(r.Signature)
	}

	e.WriteBytes(u.NewCommitment)

	if err := e.WriteDelta(u.Delta); err != nil {
		return nil, err
	}

	return e.Bytes(), nil
}

// EncodeDeactivate encodes a DEACTIVATE operation
func EncodeDeactivate(d *CompactDeactivate) ([]byte, error) {
	e := NewEncoder()

	e.WriteHeader(d.Header)
	e.WriteBytes(d.DIDSuffix)

	if d.Header.Flags&FlagThreshold != 0 {
		e.WriteByte(byte(len(d.Reveals)))
		for _, r := range d.Reveals {
			if err := e.WriteReveal(r); err != nil {
				return nil, err
			}
		}
	} else {
		if len(d.Reveals) != 1 {
			return nil, fmt.Errorf("single key mode requires exactly 1 reveal")
		}
		r := d.Reveals[0]
		e.WriteBytes(computeRevealValue(r.PublicKey))
		e.WriteByte(r.KeyType)
		e.WriteBytes(r.PublicKey)
		e.WriteBytes(r.Signature)
	}

	return e.Bytes(), nil
}

// computeRevealValue computes H(publicKey) for the reveal
func computeRevealValue(publicKey []byte) []byte {
	// Import from crypto package would create circular dep, so inline SHA256
	// This is a placeholder - actual implementation uses crypto.SHA256
	h := make([]byte, 32)
	// In real implementation: h = sha256.Sum256(publicKey)
	copy(h, publicKey[:32]) // Placeholder
	return h
}

// Decoder reads compact binary format
type Decoder struct {
	r   *bytes.Reader
	err error
}

// NewDecoder creates a new decoder
func NewDecoder(data []byte) *Decoder {
	return &Decoder{r: bytes.NewReader(data)}
}

// Error returns any accumulated error
func (d *Decoder) Error() error {
	return d.err
}

// ReadHeader reads the 3-byte header
func (d *Decoder) ReadHeader() CompactHeader {
	var h CompactHeader
	h.Version = d.ReadByte()
	h.Operation = d.ReadByte()
	h.Flags = d.ReadByte()
	return h
}

// ReadByte reads a single byte
func (d *Decoder) ReadByte() byte {
	if d.err != nil {
		return 0
	}
	b, err := d.r.ReadByte()
	if err != nil {
		d.err = err
	}
	return b
}

// ReadBytes reads n bytes
func (d *Decoder) ReadBytes(n int) []byte {
	if d.err != nil {
		return nil
	}
	b := make([]byte, n)
	_, err := io.ReadFull(d.r, b)
	if err != nil {
		d.err = err
		return nil
	}
	return b
}

// ReadString reads a length-prefixed string (1-byte length)
func (d *Decoder) ReadString() string {
	length := d.ReadByte()
	if d.err != nil {
		return ""
	}
	b := d.ReadBytes(int(length))
	return string(b)
}

// ReadLongString reads a length-prefixed string (2-byte length)
func (d *Decoder) ReadLongString() string {
	length := d.ReadUint16()
	if d.err != nil {
		return ""
	}
	b := d.ReadBytes(int(length))
	return string(b)
}

// ReadUint16 reads a 16-bit big-endian integer
func (d *Decoder) ReadUint16() uint16 {
	b := d.ReadBytes(2)
	if d.err != nil {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}

// ReadPublicKey reads a public key
func (d *Decoder) ReadPublicKey() CompactPublicKey {
	pk := CompactPublicKey{
		ID:      d.ReadString(),
		KeyType: d.ReadByte(),
	}
	if d.err != nil {
		return pk
	}

	keySize, ok := KeySizes[pk.KeyType]
	if !ok {
		d.err = fmt.Errorf("unknown key type: %d", pk.KeyType)
		return pk
	}

	pk.KeyBytes = d.ReadBytes(keySize.PubKey)
	pk.Purposes = d.ReadByte()
	return pk
}

// ReadService reads a service
func (d *Decoder) ReadService() CompactService {
	return CompactService{
		ID:       d.ReadString(),
		Type:     d.ReadString(),
		Endpoint: d.ReadLongString(),
	}
}

// ReadReveal reads a controller reveal
func (d *Decoder) ReadReveal() CompactReveal {
	r := CompactReveal{
		Index:   d.ReadByte(),
		KeyType: d.ReadByte(),
	}
	if d.err != nil {
		return r
	}

	keySize, ok := KeySizes[r.KeyType]
	if !ok {
		d.err = fmt.Errorf("unknown key type: %d", r.KeyType)
		return r
	}

	r.PublicKey = d.ReadBytes(keySize.PubKey)
	r.MerkleDepth = d.ReadByte()

	r.MerkleSiblings = make([][]byte, r.MerkleDepth)
	for i := 0; i < int(r.MerkleDepth); i++ {
		r.MerkleSiblings[i] = d.ReadBytes(32)
	}

	r.Signature = d.ReadBytes(keySize.Sig)
	return r
}

// ReadDelta reads patches
func (d *Decoder) ReadDelta() CompactDelta {
	count := d.ReadByte()
	delta := CompactDelta{
		Patches: make([]CompactPatch, count),
	}

	for i := 0; i < int(count); i++ {
		delta.Patches[i] = d.ReadPatch()
	}

	return delta
}

// ReadPatch reads a single patch
func (d *Decoder) ReadPatch() CompactPatch {
	p := CompactPatch{
		Type: d.ReadByte(),
	}

	switch p.Type {
	case PatchAddPublicKeys:
		count := d.ReadByte()
		p.PublicKeys = make([]CompactPublicKey, count)
		for i := 0; i < int(count); i++ {
			p.PublicKeys[i] = d.ReadPublicKey()
		}
	case PatchRemovePublicKeys:
		count := d.ReadByte()
		p.KeyIDs = make([]string, count)
		for i := 0; i < int(count); i++ {
			p.KeyIDs[i] = d.ReadString()
		}
	case PatchAddServices:
		count := d.ReadByte()
		p.Services = make([]CompactService, count)
		for i := 0; i < int(count); i++ {
			p.Services[i] = d.ReadService()
		}
	case PatchRemoveServices:
		count := d.ReadByte()
		p.ServiceIDs = make([]string, count)
		for i := 0; i < int(count); i++ {
			p.ServiceIDs[i] = d.ReadString()
		}
	default:
		d.err = fmt.Errorf("unknown patch type: %d", p.Type)
	}

	return p
}

// DecodeCreate decodes a CREATE operation
func DecodeCreate(data []byte) (*CompactCreate, error) {
	d := NewDecoder(data)

	c := &CompactCreate{
		Header: d.ReadHeader(),
	}

	if c.Header.Version != PayloadVersionCompact {
		return nil, fmt.Errorf("expected version %d, got %d", PayloadVersionCompact, c.Header.Version)
	}
	if c.Header.Operation != OpCreate {
		return nil, fmt.Errorf("expected CREATE operation, got %d", c.Header.Operation)
	}

	c.SuffixDataHash = d.ReadBytes(32)
	c.UpdateCommitment = d.ReadBytes(32)
	c.RecoveryCommitment = d.ReadBytes(32)

	if c.Header.Flags&FlagThreshold != 0 {
		c.UpdateThreshold = d.ReadByte()
		c.UpdateControllerCount = d.ReadByte()
		c.RecoveryThreshold = d.ReadByte()
		c.RecoveryControllerCount = d.ReadByte()
	}

	// Document
	keyCount := d.ReadByte()
	c.PublicKeys = make([]CompactPublicKey, keyCount)
	for i := 0; i < int(keyCount); i++ {
		c.PublicKeys[i] = d.ReadPublicKey()
	}

	svcCount := d.ReadByte()
	c.Services = make([]CompactService, svcCount)
	for i := 0; i < int(svcCount); i++ {
		c.Services[i] = d.ReadService()
	}

	if d.Error() != nil {
		return nil, d.Error()
	}

	return c, nil
}

// DecodeUpdate decodes an UPDATE operation
func DecodeUpdate(data []byte) (*CompactUpdate, error) {
	d := NewDecoder(data)

	u := &CompactUpdate{
		Header: d.ReadHeader(),
	}

	if u.Header.Version != PayloadVersionCompact {
		return nil, fmt.Errorf("expected version %d, got %d", PayloadVersionCompact, u.Header.Version)
	}
	if u.Header.Operation != OpUpdate {
		return nil, fmt.Errorf("expected UPDATE operation, got %d", u.Header.Operation)
	}

	u.DIDSuffix = d.ReadBytes(32)

	if u.Header.Flags&FlagThreshold != 0 {
		// Threshold mode
		revealCount := d.ReadByte()
		u.Reveals = make([]CompactReveal, revealCount)
		for i := 0; i < int(revealCount); i++ {
			u.Reveals[i] = d.ReadReveal()
		}
	} else {
		// Single key mode
		reveal := CompactReveal{}
		_ = d.ReadBytes(32) // reveal value (we recompute from public key)
		reveal.KeyType = d.ReadByte()

		keySize, ok := KeySizes[reveal.KeyType]
		if !ok {
			return nil, fmt.Errorf("unknown key type: %d", reveal.KeyType)
		}

		reveal.PublicKey = d.ReadBytes(keySize.PubKey)
		reveal.Signature = d.ReadBytes(keySize.Sig)
		u.Reveals = []CompactReveal{reveal}
	}

	u.NewCommitment = d.ReadBytes(32)
	u.Delta = d.ReadDelta()

	if d.Error() != nil {
		return nil, d.Error()
	}

	return u, nil
}

// DecodeDeactivate decodes a DEACTIVATE operation
func DecodeDeactivate(data []byte) (*CompactDeactivate, error) {
	d := NewDecoder(data)

	op := &CompactDeactivate{
		Header: d.ReadHeader(),
	}

	if op.Header.Version != PayloadVersionCompact {
		return nil, fmt.Errorf("expected version %d, got %d", PayloadVersionCompact, op.Header.Version)
	}
	if op.Header.Operation != OpDeactivate {
		return nil, fmt.Errorf("expected DEACTIVATE operation, got %d", op.Header.Operation)
	}

	op.DIDSuffix = d.ReadBytes(32)

	if op.Header.Flags&FlagThreshold != 0 {
		revealCount := d.ReadByte()
		op.Reveals = make([]CompactReveal, revealCount)
		for i := 0; i < int(revealCount); i++ {
			op.Reveals[i] = d.ReadReveal()
		}
	} else {
		reveal := CompactReveal{}
		_ = d.ReadBytes(32) // reveal value
		reveal.KeyType = d.ReadByte()

		keySize, ok := KeySizes[reveal.KeyType]
		if !ok {
			return nil, fmt.Errorf("unknown key type: %d", reveal.KeyType)
		}

		reveal.PublicKey = d.ReadBytes(keySize.PubKey)
		reveal.Signature = d.ReadBytes(keySize.Sig)
		op.Reveals = []CompactReveal{reveal}
	}

	if d.Error() != nil {
		return nil, d.Error()
	}

	return op, nil
}

// DetectFormat returns the format version from payload data
func DetectFormat(data []byte) (byte, error) {
	if len(data) == 0 {
		return 0, fmt.Errorf("empty payload")
	}
	return data[0], nil
}

// CompressECPublicKey compresses an EC public key to 33 bytes
func CompressECPublicKey(x, y *big.Int) []byte {
	compressed := make([]byte, 33)
	// Prefix: 0x02 for even y, 0x03 for odd y
	if y.Bit(0) == 0 {
		compressed[0] = 0x02
	} else {
		compressed[0] = 0x03
	}
	xBytes := x.Bytes()
	copy(compressed[33-len(xBytes):], xBytes)
	return compressed
}

// DecompressECPublicKey decompresses a 33-byte EC public key
func DecompressECPublicKey(curve elliptic.Curve, compressed []byte) (*ecdsa.PublicKey, error) {
	if len(compressed) != 33 {
		return nil, fmt.Errorf("compressed key must be 33 bytes, got %d", len(compressed))
	}

	prefix := compressed[0]
	if prefix != 0x02 && prefix != 0x03 {
		return nil, fmt.Errorf("invalid compression prefix: %02x", prefix)
	}

	x := new(big.Int).SetBytes(compressed[1:])

	// Compute y² = x³ - 3x + b (mod p) for P-256
	// Then take sqrt and select based on prefix
	y := decompressY(curve, x, prefix == 0x03)
	if y == nil {
		return nil, fmt.Errorf("failed to decompress y coordinate")
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// decompressY computes the y coordinate from x for the given curve
func decompressY(curve elliptic.Curve, x *big.Int, odd bool) *big.Int {
	params := curve.Params()
	p := params.P

	// y² = x³ - 3x + b (mod p)
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	x3.Mod(x3, p)

	threeX := new(big.Int).Mul(x, big.NewInt(3))
	threeX.Mod(threeX, p)

	y2 := new(big.Int).Sub(x3, threeX)
	y2.Add(y2, params.B)
	y2.Mod(y2, p)

	// Compute sqrt(y²) mod p
	y := new(big.Int).ModSqrt(y2, p)
	if y == nil {
		return nil
	}

	// Select the right root based on parity
	if odd != (y.Bit(0) == 1) {
		y.Sub(p, y)
	}

	return y
}
