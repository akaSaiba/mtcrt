package sig

import (
	"testing"

	"mtcrt/merkle"
)

func TestSignAndVerify(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	
	digest := merkle.LeafHash([]byte("epoch"))
	signature := key.Sign(digest)
	if !key.Public().Verify(digest, signature) {
		t.Fatal("signature did not verify")
	}

	tampered := append([]byte(nil), signature...)
	tampered[0] ^= 1
	if key.Public().Verify(digest, tampered) {
		t.Fatal("tampered signature verified")
	}
}
