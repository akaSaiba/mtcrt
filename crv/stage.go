package crv

import (
	"slices"

	"mtcrt/merkle"
)

// This file implements crv_bits staging. Allows to undo changes to the vector if the verified roots don't match.
// While roots will never not match in benchmarking, this is still required to simulate real-world behavior.

type undoLog struct {
	size  uint64            // Size when staging began
	saved map[uint64][]byte // original content of each block changed since then
}

// Starts recording changes.
func (v *Vector) Stage() {
	if v.undo != nil {
		panic("crv: Stage called twice without Commit or Rollback")
	}

	v.undo = &undoLog{size: v.size, saved: make(map[uint64][]byte)}
}

// Keeps every change made since Stage.
func (v *Vector) Commit() { v.undo = nil }

// Undos every change made since Stage.
func (v *Vector) Rollback() {
	u := v.undo
	v.undo = nil

	for id, content := range u.saved {
		v.blocks[id] = content
		v.tree.Set(id, merkle.LeafHash(content))
	}

	// Revert added blocks.
	keep := BlocksFor(u.size, int(v.blockSize))
	v.blocks = v.blocks[:keep]
	v.tree.Truncate(keep)
	v.size = u.size
}

// Saves state before a block is changed, allowing for rollback.
func (v *Vector) remember(block uint64) {
	if v.undo == nil || block >= BlocksFor(v.undo.size, int(v.blockSize)) {
		return
	}

	if _, done := v.undo.saved[block]; !done {
		v.undo.saved[block] = slices.Clone(v.blocks[block])
	}
}
