package accum

import "testing"

func TestExtend(t *testing.T) {
	var a Log
	a.Append(7)

	oldSize := a.Size()
	oldRoot := a.Root()
	prefix := a.PrefixHashes(oldSize)

	a.Append(9)
	got, err := Extend(oldSize, oldRoot, prefix, []uint64{9})
	if err != nil {
		t.Fatal(err)
	}
	
	if got != a.Root() {
		t.Fatal("extended root does not match the log")
	}
}

func TestExtendFromEmpty(t *testing.T) {
	var a Log
	empty := a.Root()
	a.Append(7)
	got, err := Extend(0, empty, nil, []uint64{7})

	if err != nil || got != a.Root() {
		t.Fatal("extending an empty log")
	}
}
