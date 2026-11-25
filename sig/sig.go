// This package signs and verifies revocation digests with ML-DSA-44.
//
// Every signature is over the digest bytes. Keys in this harness sign only
// those digests.
package sig

import (
	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"

	"mtcrt/merkle"
)

// PrivateKey used to sign digests.
type PrivateKey interface {
	Public() PublicKey
	Sign(digest merkle.Hash) []byte
}

// PublicKey used to verify signatures over digests.
type PublicKey interface {
	Verify(digest merkle.Hash, signature []byte) bool
}

// ML-DSA-44 private key.
type mldsaPrivate struct {
	pub mldsaPublic
	sk  sign.PrivateKey
}

// ML-DSA-44 public key.
type mldsaPublic struct {
	impl sign.Scheme
	pk   sign.PublicKey
}

// Creates a new ML-DSA-44 key pair.
func GenerateKey() (PrivateKey, error) {
	impl := mldsa44.Scheme()
	pk, sk, err := impl.GenerateKey()
	if err != nil {
		return nil, err
	}

	return mldsaPrivate{pub: mldsaPublic{impl, pk}, sk: sk}, nil
}

// Returns the public key corresponding to the private key.
func (k mldsaPrivate) Public() PublicKey { return k.pub }

// Signs a digest.
func (k mldsaPrivate) Sign(digest merkle.Hash) []byte {
	return k.pub.impl.Sign(k.sk, digest[:], nil)
}

// Verifies a signature over a digest.
func (k mldsaPublic) Verify(digest merkle.Hash, signature []byte) bool {
	return k.impl.Verify(k.pk, digest[:], signature, nil)
}
