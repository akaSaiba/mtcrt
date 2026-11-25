// This package encodes crv_bits blocks as Roaring bitmaps.
//
// This is used to benchmark the effects of compression in the system.
package compress

import (
	"bytes"
	"fmt"

	"github.com/RoaringBitmap/roaring/v2"

	"mtcrt/crv"
	"mtcrt/wire"
)

// Encodes a block as a Roaring bitmap.
func EncodeBlock(raw []byte) ([]byte, error) {
	encoded, err := encodeBlock(raw)
	if err != nil {
		return nil, err
	}

	decoded, err := DecodeBlock(encoded, len(raw))
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(decoded, raw) {
		return nil, fmt.Errorf("Roaring block round trip differs")
	}

	return encoded, nil
}

// Encodes a block into a Roaring bitmap.
func encodeBlock(raw []byte) ([]byte, error) {
	bm := roaring.New()
	for byteIndex, value := range raw {
		for bit := range 8 {
			if value&(0x80>>bit) != 0 {
				bm.Add(uint32(byteIndex*8 + bit))
			}
		}
	}
	bm.RunOptimize()

	var buf bytes.Buffer
	if _, err := bm.WriteTo(&buf); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// Decodes block.
func DecodeBlock(encoded []byte, rawBytes int) ([]byte, error) {
	bm := roaring.New()
	if _, err := bm.ReadFrom(bytes.NewReader(encoded)); err != nil {
		return nil, err
	}

	raw := make([]byte, rawBytes)
	for _, offset := range bm.ToArray() {
		if int(offset) >= rawBytes*8 {
			return nil, fmt.Errorf("Roaring offset %d outside %d-byte block", offset, rawBytes)
		}

		raw[offset/8] |= 0x80 >> (offset % 8)
	}

	return raw, nil
}

// Checks if a specific bit is set in an encoded block.
func BlockContains(encoded []byte, offset uint32) (bool, error) {
	bm := roaring.New()
	if _, err := bm.ReadFrom(bytes.NewReader(encoded)); err != nil {
		return false, err
	}

	return bm.Contains(offset), nil
}

// Encodes every block in the vector and returns the sum of their sizes.
func PerBlockRoaringSize(vec *crv.Vector) (uint64, error) {
	var total uint64
	for i := uint64(0); i < vec.NumBlocks(); i++ {
		encoded, err := EncodeBlock(vec.Block(i))
		if err != nil {
			return 0, fmt.Errorf("block %d: %w", i, err)
		}

		total += uint64(len(encoded))
	}

	return total, nil
}

// Encodes every given block and returns the sum of their sizes.
func EncodeWireBlocks(blocks []wire.Block) (uint64, error) {
	var total uint64
	for _, block := range blocks {
		encoded, err := EncodeBlock(block.Content)
		if err != nil {
			return 0, fmt.Errorf("block %d: %w", block.ID, err)
		}

		// includes 8 bytes of the block ID (required for RP sync)
		total += 8 + uint64(len(encoded))
	}

	return total, nil
}
