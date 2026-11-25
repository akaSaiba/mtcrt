package merkle

import "testing"

func TestRoot(t *testing.T) {
	a := LeafHash([]byte("a"))
	b := LeafHash([]byte("b"))
	c := LeafHash([]byte("c"))

	var tree Tree
	if tree.Root(0) != EmptyRoot() {
		t.Fatal("empty tree")
	}

	tree.Append(a)
	if tree.Root(1) != a {
		t.Fatal("one leaf: the root is the leaf")
	}

	tree.Append(b)
	if tree.Root(2) != NodeHash(a, b) {
		t.Fatal("two leaves")
	}

	tree.Append(c)
	if tree.Root(3) != NodeHash(NodeHash(a, b), c) {
		t.Fatal("three leaves")
	}
}

func TestSet(t *testing.T) {
	a := LeafHash([]byte("a"))
	b := LeafHash([]byte("b"))
	c := LeafHash([]byte("c"))

	var tree Tree
	tree.Append(a)
	tree.Append(b)
	tree.Set(0, c)
	if tree.Root(2) != NodeHash(c, b) {
		t.Fatal("replacing leaf 0")
	}
}

func TestTruncate(t *testing.T) {
	a := LeafHash([]byte("a"))
	b := LeafHash([]byte("b"))

	var tree Tree
	tree.Append(a)
	tree.Append(b)
	tree.Truncate(1)
	if tree.Size() != 1 || tree.Root(1) != a {
		t.Fatal("truncate back to the first leaf")
	}
}

func TestCompactRange(t *testing.T) {
	a := LeafHash([]byte("a"))
	b := LeafHash([]byte("b"))

	var tree Tree
	tree.Append(a)
	c, err := NewCompactRange(1, tree.PrefixHashes(1))
	if err != nil {
		t.Fatal(err)
	}
	if c.Root() != a {
		t.Fatal("compact range of one leaf")
	}
	c.Append(b)
	if c.Root() != NodeHash(a, b) {
		t.Fatal("appending a leaf to a compact range")
	}

	// Size 3 needs two prefix hashes (the pair, then the leftover leaf).
	if _, err := NewCompactRange(3, nil); err == nil {
		t.Fatal("accepted the wrong number of prefix hashes")
	}
}
