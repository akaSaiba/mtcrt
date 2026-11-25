package compress

import (
	"bytes"
	"testing"
)

func TestEncodeBlockRoundTrip(t *testing.T) {
	raw := []byte{0x80, 0x01}
	encoded, err := EncodeBlock(raw)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeBlock(encoded, len(raw))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, raw) {
		t.Fatalf("got %x, want %x", decoded, raw)
	}
}
