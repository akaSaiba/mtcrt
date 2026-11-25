package wire

import (
	"encoding/binary"
	"fmt"

	"mtcrt/merkle"
)

// This file implements the encoding of the messages.
// Messages are encoded into an array of bytes to accurately measure the size of the message.

// Sizes splits an encoded RP sync response (from the distributor) into separate parts for benchmarking.
type Sizes struct {
	Header int // contains the kind of sync response, epoch fields, and the number of blocks.
	Blocks int // block ids and their contents
	Auth   int // A_n root and the cosignature set, used to authenticate the response.
}

// Returns the total encoded size.
func (s Sizes) Total() int { return s.Header + s.Blocks + s.Auth }

// Returns the encoded size of each message part.
func (r SyncResponse) Sizes() Sizes {
	return Sizes{
		Header: len(r.marshalHeader()),
		Blocks: len(r.marshalBlocks()),
		Auth:   len(r.marshalAuth()),
	}
}

// Encodes the sync response into an array of bytes.
func (r SyncResponse) Marshal() []byte {
	out := r.marshalHeader()
	out = append(out, r.marshalBlocks()...)

	return append(out, r.marshalAuth()...)
}

// Encodes header information into an array of bytes.
func (r SyncResponse) marshalHeader() []byte {
	var e encoder
	e.u8(uint8(r.Kind))

	if r.Kind == SyncUpdate || r.Kind == SyncFull {
		e.u64(r.State.P)
		e.u64(r.State.TreeSize)
		e.u64(r.State.MinSerial)
		e.hash(r.State.BlockRoot)
		e.u64(uint64(r.State.TPublish.UnixMilli()))
		e.u32(uint32(len(r.Blocks)))
	}

	return e.buf
}

// Encodes each sync response block into an array of bytes.
func (r SyncResponse) marshalBlocks() []byte {
	var e encoder
	for _, b := range r.Blocks {
		e.u64(b.ID)
		e.raw(b.Content)
	}

	return e.buf
}

// Encodes the A_n root and the cosignature set into an array of bytes.
func (r SyncResponse) marshalAuth() []byte {
	var e encoder

	if r.Kind == SyncUpdate || r.Kind == SyncFull {
		e.hash(r.State.AnRoot)
		e.cosignatures(r.Cosignatures)
	}

	return e.buf
}

// Encodes a cosigner proposal response: events, then prefix hashes into an array of bytes.
func (r ProposalResponse) Marshal() []byte {
	var e encoder
	e.u32(uint32(len(r.Events)))
	for _, idx := range r.Events {
		e.u64(idx)
	}

	e.u8(uint8(len(r.PrefixHashes)))
	for _, h := range r.PrefixHashes {
		e.hash(h)
	}

	return e.buf
}

type encoder struct{ buf []byte }

func (e *encoder) u8(v uint8)         { e.buf = append(e.buf, v) }
func (e *encoder) u16(v uint16)       { e.buf = binary.BigEndian.AppendUint16(e.buf, v) }
func (e *encoder) u32(v uint32)       { e.buf = binary.BigEndian.AppendUint32(e.buf, v) }
func (e *encoder) u64(v uint64)       { e.buf = binary.BigEndian.AppendUint64(e.buf, v) }
func (e *encoder) hash(h merkle.Hash) { e.buf = append(e.buf, h[:]...) }
func (e *encoder) raw(b []byte)       { e.buf = append(e.buf, b...) }

// Appends a byte to the encoded buffer.
func (e *encoder) bytes8(b []byte) {
	if len(b) > 255 {
		panic(fmt.Sprintf("wire: %d bytes do not fit a one-byte length", len(b)))
	}

	e.u8(uint8(len(b)))
	e.raw(b)
}

// Appends two bytes to the encoded buffer.
func (e *encoder) bytes16(b []byte) {
	if len(b) > 65535 {
		panic(fmt.Sprintf("wire: %d bytes do not fit a two-byte length", len(b)))
	}

	e.u16(uint16(len(b)))
	e.raw(b)
}

// Appends cosignatures to the encoded buffer.
func (e *encoder) cosignatures(set []Cosignature) {
	e.u8(uint8(len(set)))

	for _, c := range set {
		e.bytes8([]byte(c.CosignerID))
		e.bytes16(c.Signature)
	}
}
