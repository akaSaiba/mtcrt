package wire

import (
	"testing"
	"time"

	"mtcrt/merkle"
)

func TestSignedDigest(t *testing.T) {
	s := EpochState{
		P: 1, TreeSize: 8,
		AnRoot: merkle.LeafHash([]byte("a")), BlockRoot: merkle.LeafHash([]byte("b")),
		TPublish: time.UnixMilli(1_800_000_000_000),
	}
	d := s.SignedDigest([]byte("log"))

	s.P = 2
	if s.SignedDigest([]byte("log")) == d {
		t.Fatal("changing the epoch left the digest the same")
	}
	s.P = 1
	if s.SignedDigest([]byte("other")) == d {
		t.Fatal("changing log_id left the digest the same")
	}
}

func TestSerial(t *testing.T) {
	logNumber, idx := SplitSerial(Serial(5, 12345))
	if logNumber != 5 || idx != 12345 {
		t.Fatalf("got log %d, index %d", logNumber, idx)
	}
}

func TestSizesMatchEncoding(t *testing.T) {
	r := SyncResponse{
		Kind:         SyncUpdate,
		Blocks:       []Block{{ID: 1, Content: make([]byte, 8)}},
		Cosignatures: []Cosignature{{CosignerID: "ca", Signature: make([]byte, 4)}},
	}
	if r.Sizes().Total() != len(r.Marshal()) {
		t.Fatalf("parts sum to %d, encoding is %d bytes", r.Sizes().Total(), len(r.Marshal()))
	}
}
