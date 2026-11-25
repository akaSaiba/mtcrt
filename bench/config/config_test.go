package config

import "testing"

func TestExpandOneCase(t *testing.T) {
	cfg := Config{
		Benchmarks: []string{"storage"},
		Out:        "out",
		Seed:       1,
		Reps:       1,
		Sweep: Sweep{
			N: []uint64{100}, R: []float64{0.1}, K: []int{1}, BlockSize: []int{64},
			M: []int{1}, T: []int{1}, Placement: []string{"uniform"},
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	cases, err := cfg.Expand("storage")
	if err != nil {
		t.Fatal(err)
	}
	
	if len(cases) != 1 || cases[0].N != 100 || cases[0].BlockSize != 64 || cases[0].Placement != "uniform" {
		t.Fatalf("got %+v", cases)
	}
}
