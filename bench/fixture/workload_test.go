package fixture

import "testing"

func TestSelectIndices(t *testing.T) {
	excluded := map[uint64]struct{}{1: {}}
	got, err := SelectIndices(RNG(1, 1), 10, 3, "uniform", excluded)
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 3 {
		t.Fatalf("got %d indices, want 3", len(got))
	}
	
	seen := map[uint64]bool{}
	for _, idx := range got {
		if idx >= 10 || idx == 1 || seen[idx] {
			t.Fatalf("index %d", idx)
		}
		seen[idx] = true
	}
}
