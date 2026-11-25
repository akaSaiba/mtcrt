// This package implements the Merkle tree of RFC 9162 Section 2.1, which
// MTC-RT uses for both of its trees:
//
//   - A_n, the revocation accumulator, whose leaves are revoked indices, and
//   - crv_tree, whose leaves are the blocks of crv_bits.
package merkle

import (
	"crypto/sha256"
	"encoding/hex"
)

// Sha256 type.
type Hash [sha256.Size]byte

// Returns hash of some data.
func LeafHash(data []byte) Hash {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	var out Hash
	h.Sum(out[:0])
	return out
}

// Hashes two child hashes to make a parent.
func NodeHash(left, right Hash) Hash {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left[:])
	h.Write(right[:])
	var out Hash
	h.Sum(out[:0])
	return out
}

// Root of tree with no leaves. SHA-256 of the empty string.
func EmptyRoot() Hash {
	return sha256.Sum256(nil)
}

// Hashes prefix hashes into a root.
func rootFromPrefix(prefix []Hash) Hash {
	if len(prefix) == 0 {
		return EmptyRoot()
	}

	root := prefix[len(prefix)-1]
	for i := len(prefix) - 2; i >= 0; i-- {
		root = NodeHash(prefix[i], root)
	}

	return root
}

// Returns hash in hex.
func (h Hash) String() string { return hex.EncodeToString(h[:]) }

// Encodes hash as a hex (as a byte array).
func (h Hash) MarshalText() ([]byte, error) { return []byte(h.String()), nil }
