package report

import "testing"

func TestMean(t *testing.T) {
	values := []float64{1, 2, 3}
	if Mean(values) != 2 {
		t.Fatalf("mean = %v, want 2", Mean(values))
	}
}
