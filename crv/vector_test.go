package crv

import (
	"testing"

	"mtcrt/merkle"
)

func TestSetAndGet(t *testing.T) {
	v, err := New(8)
	if err != nil {
		t.Fatal(err)
	}

	v.Expand(16)

	changed := v.SetBits([]uint64{1, 9})
	if len(changed) != 2 || changed[0] != 0 || changed[1] != 1 {
		t.Fatalf("changed blocks %v, want [0 1]", changed)
	}

	if !v.Get(1) || !v.Get(9) {
		t.Fatal("set bits are not revoked")
	}

	if v.Get(0) {
		t.Fatal("an unset bit is revoked")
	}

	var tree merkle.Tree
	tree.Append(merkle.LeafHash(v.Block(0)))
	tree.Append(merkle.LeafHash(v.Block(1)))

	if v.Root(16) != tree.Root(2) {
		t.Fatal("block_root does not match hashing the two blocks")
	}
}
