// This package implements A_n, the revocation accumulator.
//
// A_n is an append-only Merkle tree. Each leaf is one revocation event,
// recorded as the revoked index.
package accum

import (
	"encoding/binary"
	"errors"
	"slices"

	"mtcrt/merkle"
)

// Returns the A_n leaf (hash) for a revocation of idx.
// Big endian is used for consistency throughout the code.
func LeafHash(idx uint64) merkle.Hash {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], idx)

	return merkle.LeafHash(b[:])
}

// Log is the CA's copy of A_n.
// It also stores revocation events.
type Log struct {
	tree   merkle.Tree
	events []uint64
}

// Records a revocation event.
func (a *Log) Append(idx uint64) {
	a.events = append(a.events, idx)
	a.tree.Append(LeafHash(idx))
}

// Returns the number of revocation events.
func (a *Log) Size() uint64 { return uint64(len(a.events)) }

// Returns the current root.
func (a *Log) Root() merkle.Hash { return a.tree.Root(a.Size()) }

// Returns the prefix hashes of an earlier size.
func (a *Log) PrefixHashes(size uint64) []merkle.Hash {
	return a.tree.PrefixHashes(size)
}

// Returns the events at positions [from, to).
func (a *Log) Events(from, to uint64) []uint64 {
	return slices.Clone(a.events[from:to])
}

// Extends a tree without storing all the leaves.
// Used by a cosigner to check a new A_n root.
func Extend(oldSize uint64, oldRoot merkle.Hash, prefix []merkle.Hash, events []uint64) (merkle.Hash, error) {
	r, err := merkle.NewCompactRange(oldSize, prefix)
	if err != nil {
		return merkle.Hash{}, err
	}

	if r.Root() != oldRoot {
		return merkle.Hash{}, errors.New("accum: prefix hashes do not match the last-verified root")
	}

	for _, idx := range events {
		r.Append(LeafHash(idx))
	}

	return r.Root(), nil
}
