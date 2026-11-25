package merkle

import (
	"fmt"
	"math/bits"
)

// Tree is a Merkle tree that stores the hash of every complete subtree
//
// levels[0] holds the leaf hashes. levels[k][i] is the hash of the complete
// subtree over leaves [i * 2^k, (i+1) * 2^k). A subtree is stored only once all
// of its leaves exist, so len(levels[k+1]) is always len(levels[k]) / 2.
type Tree struct {
	levels [][]Hash
}

// Returns number of leaves in the tree.
func (t *Tree) Size() uint64 {
	if len(t.levels) == 0 {
		return 0
	}
	return uint64(len(t.levels[0]))
}

// Append adds a leaf at the right edge of the tree.
func (t *Tree) Append(leaf Hash) {
	if len(t.levels) == 0 {
		t.levels = append(t.levels, nil)
	}

	t.levels[0] = append(t.levels[0], leaf)

	// If new node is a right child, then its parent is a complete subtree.
	// So we add the parent and keep going up the tree while the parent is a right child.
	i := len(t.levels[0]) - 1
	for k := 0; i%2 == 1; k++ {
		parent := NodeHash(t.levels[k][i-1], t.levels[k][i])

		if k+1 == len(t.levels) {
			t.levels = append(t.levels, nil)
		}

		t.levels[k+1] = append(t.levels[k+1], parent)
		i /= 2
	}
}

// Replaces leaf i with new leaf hash and recomputes every stored subtree above it.
func (t *Tree) Set(i uint64, leaf Hash) {
	t.levels[0][i] = leaf
	for k := 0; k+1 < len(t.levels); k++ {
		parent := i / 2

		if parent >= uint64(len(t.levels[k+1])) {
			break
		}

		t.levels[k+1][parent] = NodeHash(t.levels[k][2*parent], t.levels[k][2*parent+1])
		i = parent
	}
}

// Drops every leaf at/after size.
func (t *Tree) Truncate(size uint64) {
	for k := range t.levels {
		if keep := size >> k; uint64(len(t.levels[k])) > keep {
			t.levels[k] = t.levels[k][:keep]
		}
	}
}

// Returns prefix hashes of the first size leaves.
func (t *Tree) PrefixHashes(size uint64) []Hash {
	if size > t.Size() {
		panic(fmt.Sprintf("merkle: prefix of size %d from a tree of size %d", size, t.Size()))
	}

	prefix := make([]Hash, 0, bits.OnesCount64(size))
	start := uint64(0)

	for k := bits.Len64(size) - 1; k >= 0; k-- {
		if size&(1<<k) == 0 {
			continue
		}
		prefix = append(prefix, t.levels[k][start>>k])
		start += 1 << k
	}
	return prefix
}

// Returns root of the tree made of the first size leaves.
func (t *Tree) Root(size uint64) Hash {
	return rootFromPrefix(t.PrefixHashes(size))
}
