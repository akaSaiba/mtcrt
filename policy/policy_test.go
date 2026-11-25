package policy

import (
	"testing"

	"mtcrt/merkle"
	"mtcrt/sig"
	"mtcrt/wire"
)

func TestCheck(t *testing.T) {
	caKey, err := sig.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	other, err := sig.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	p := Policy{
		Required: "ca",
		Keys:     map[string]sig.PublicKey{"ca": caKey.Public(), "a": other.Public()},
		Min:      2,
	}

	digest := merkle.LeafHash([]byte("epoch"))
	signed := func(id string, key sig.PrivateKey) wire.Cosignature {
		return wire.Cosignature{CosignerID: id, Signature: key.Sign(digest)}
	}

	full := []wire.Cosignature{signed("ca", caKey), signed("a", other)}
	if err := p.Check(digest, full); err != nil {
		t.Fatal(err)
	}

	if p.Check(digest, []wire.Cosignature{signed("a", other)}) == nil {
		t.Fatal("accepted a set with no CA signature")
	}
}
