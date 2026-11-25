package merkle

import (
	"fmt"
	"math/bits"
	"slices"
)

// CompactRange is the prefix hashes of a tree. Used to rebuild a tree without storing all the leaves.
type CompactRange struct {
	size   uint64
	hashes []Hash
}

// Builds a compact range from prefix hashes.
func NewCompactRange(size uint64, prefix []Hash) (*CompactRange, error) {
	// Check if the number of prefix hashes is correct.
	if want := bits.OnesCount64(size); len(prefix) != want {
		return nil, fmt.Errorf("merkle: size %d needs %d prefix hashes, got %d", size, want, len(prefix))
	}

	return &CompactRange{size: size, hashes: slices.Clone(prefix)}, nil
}

// Returns the root of the tree.
func (c *CompactRange) Root() Hash { return rootFromPrefix(c.hashes) }

// Adds one leaf hash.
func (c *CompactRange) Append(leaf Hash) {
	c.hashes = append(c.hashes, leaf)

	for s := c.size; s&1 == 1; s >>= 1 {
		n := len(c.hashes)
		merged := NodeHash(c.hashes[n-2], c.hashes[n-1])

		c.hashes = append(c.hashes[:n-2], merged)
	}

	c.size++
}
