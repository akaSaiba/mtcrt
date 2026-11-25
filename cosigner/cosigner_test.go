package cosigner

import (
	"path/filepath"
	"testing"
	"time"

	"mtcrt/ca"
	"mtcrt/sig"
	"mtcrt/wire"
)

// Test setup for a single CA and cosigner.
type setup struct {
	t   *testing.T
	ca  *ca.CA
	cos *Cosigner
}

func newSetup(t *testing.T) *setup {
	t.Helper()
	now := time.Unix(1_800_000_000, 0)
	clock := func() time.Time { return now }

	caKey, err := sig.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	cosKey, err := sig.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	logID := []byte("test-log")

	issuer, err := ca.New(ca.Config{
		LogID: logID, LogNumber: 1, BlockSize: 64,
		ID: "ca", Key: caKey,
		Cosigners: map[string]sig.PublicKey{"c0": cosKey.Public()},
		Quorum:    1,
		Clock:     clock,
	})

	if err != nil {
		t.Fatal(err)
	}

	cos, err := New(Config{
		ID: "c0", LogID: logID, LogNumber: 1, BlockSize: 64, Key: cosKey,
		CAKey:         caKey.Public(),
		MaxClockDelta: 5 * time.Second, Clock: clock,
		RecordPath: filepath.Join(t.TempDir(), "c0.json"),
	})

	if err != nil {
		t.Fatal(err)
	}
	return &setup{t: t, ca: issuer, cos: cos}
}

func TestHonestEpoch(t *testing.T) {
	f := newSetup(t)

	f.ca.Issue(10)
	f.cos.ObserveCheckpoint(f.ca.Checkpoint())
	if err := f.ca.SubmitRevocation(wire.Serial(1, 3)); err != nil {
		t.Fatal(err)
	}

	ann, err := f.ca.ProcessEpoch()
	if err != nil {
		t.Fatal(err)
	}

	cs, err := f.cos.ReceiveProposal(ann, f.ca.ServeProposal)
	if err != nil {
		t.Fatal(err)
	}

	if err := f.ca.AddCosignature(ann.State.P, cs); err != nil {
		t.Fatal(err)
	}
}
