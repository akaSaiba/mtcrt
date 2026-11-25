// This package implements crv_bits and crv_tree.
package crv

import (
	"bytes"
	"fmt"
	"slices"

	"mtcrt/merkle"
)

// Vector is crv_bits together with crv_tree.
//
// Index idx is in block idx/B, at bit idx%B.
type Vector struct {
	blockSize uint64      // B
	size      uint64      // number of indices covered
	blocks    [][]byte    // crv_bits
	tree      merkle.Tree // crv_tree
	zeroLeaf  merkle.Hash // hash of an all-zero block so that it doesn't need to be computed each time
	undo      *undoLog    // enables staging
}

// Creates a new vector.
func New(blockSize int) (*Vector, error) {
	if blockSize <= 0 || blockSize%8 != 0 {
		return nil, fmt.Errorf("crv: block size %d bits is not a positive multiple of 8", blockSize)
	}

	return &Vector{
		blockSize: uint64(blockSize),
		zeroLeaf:  merkle.LeafHash(make([]byte, blockSize/8)),
	}, nil
}

// Returns the number of blocks required to cover treeSize indices.
func BlocksFor(treeSize uint64, blockSize int) uint64 {
	b := uint64(blockSize)

	return (treeSize + b - 1) / b
}

// Returns the number of indices covered by the vector.
func (v *Vector) Size() uint64 { return v.size }

// Returns the number of blocks in the vector.
func (v *Vector) NumBlocks() uint64 { return uint64(len(v.blocks)) }

// Grows the vector to cover treeSize indices.
// New bits are initialized to 0.
func (v *Vector) Expand(treeSize uint64) {
	if treeSize <= v.size {
		return
	}

	for uint64(len(v.blocks)) < BlocksFor(treeSize, int(v.blockSize)) {
		v.blocks = append(v.blocks, make([]byte, v.blockSize/8))
		v.tree.Append(v.zeroLeaf)
	}

	v.size = treeSize
}

// Returns true if the certificate at index idx is revoked, false otherwise.
func (v *Vector) Get(idx uint64) bool {
	v.checkIndex(idx)
	block, byteIdx, mask := v.locate(idx)

	return v.blocks[block][byteIdx]&mask != 0
}

// Sets every index in idxs, then rehashes each block that changed.
// Returns the ids of the blocks that were changed.
func (v *Vector) SetBits(idxs []uint64) (changed []uint64) {
	touched := make(map[uint64]bool)
	for _, idx := range idxs {
		v.checkIndex(idx)
		block, byteIdx, mask := v.locate(idx)

		if v.blocks[block][byteIdx]&mask != 0 {
			continue
		}

		v.remember(block)
		v.blocks[block][byteIdx] |= mask
		touched[block] = true
	}

	for block := range touched {
		changed = append(changed, block)
	}
	slices.Sort(changed)

	for _, block := range changed {
		v.tree.Set(block, merkle.LeafHash(v.blocks[block]))
	}

	return changed
}

// Returns a copy of the block at index id.
func (v *Vector) Block(id uint64) []byte {
	return slices.Clone(v.blocks[id])
}

// Replaces the block at index id with the given content.
func (v *Vector) SetBlock(id uint64, content []byte) error {
	if id >= uint64(len(v.blocks)) {
		return fmt.Errorf("crv: block %d does not exist (have %d blocks)", id, len(v.blocks))
	}

	if uint64(len(content)) != v.blockSize/8 {
		return fmt.Errorf("crv: block %d is %d bytes, want %d", id, len(content), v.blockSize/8)
	}

	if bytes.Equal(v.blocks[id], content) {
		return nil
	}

	v.remember(id)
	v.blocks[id] = slices.Clone(content)
	v.tree.Set(id, merkle.LeafHash(v.blocks[id]))

	return nil
}

// Returns block_root for the first treeSize indices.
func (v *Vector) Root(treeSize uint64) merkle.Hash {
	if treeSize > v.size {
		panic(fmt.Sprintf("crv: root over %d indices, but the vector covers %d", treeSize, v.size))
	}

	return v.tree.Root(BlocksFor(treeSize, int(v.blockSize)))
}

// Given an index, returns the block, byte, and a bit mask to retrieve the bit at the index.
func (v *Vector) locate(idx uint64) (block, byteIdx uint64, mask byte) {
	block = idx / v.blockSize
	bit := idx % v.blockSize

	return block, bit / 8, 0x80 >> (bit % 8)
}

// Checks if index idx is within the bounds of the vector.
func (v *Vector) checkIndex(idx uint64) {
	if idx >= v.size {
		panic(fmt.Sprintf("crv: index %d is not below tree_size %d", idx, v.size))
	}
}
