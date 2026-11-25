package epoch

import (
	"testing"

	"mtcrt/rp"
	"mtcrt/wire"
)

func TestEpochAndLookup(t *testing.T) {
	n, err := New(Config{
		LogID:     []byte("test-log"),
		LogNumber: 1,
		BlockSize: 64,
		Cosigners: 1,
		RecordDir: t.TempDir(),
	})

	if err != nil {
		t.Fatal(err)
	}

	n.Issue(100)
	n.Checkpoint()
	if err := n.Revoke(n.Serial(7)); err != nil {
		t.Fatal(err)
	}

	if _, err := n.RunEpoch(); err != nil {
		t.Fatal(err)
	}

	r, err := n.NewRP()
	if err != nil {
		t.Fatal(err)
	}

	resp := n.CA.Distributor().Serve(wire.SyncRequest{})
	if err := r.ApplySync(resp); err != nil {
		t.Fatal(err)
	}

	if r.Lookup(n.Serial(7)) != rp.Revoked {
		t.Fatal("revoked certificate looks valid")
	}

	if r.Lookup(n.Serial(8)) != rp.Valid {
		t.Fatal("live certificate looks revoked")
	}
}
