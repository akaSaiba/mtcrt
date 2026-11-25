package config

import "fmt"

// A Case refers to a specific combination of parameters created from a Sweep.
type Case struct {
	Kind      string
	N         uint64
	R         float64
	K         int
	BlockSize int
	M         int
	T         int
	Placement string
}

// Expands a benchmark into the combinations of parameters it uses.
func (c Config) Expand(name string) ([]Case, error) {
	s := c.ForBenchmark(name)
	var out []Case
	add := func(x Case) error {
		initial := uint64(float64(x.N)*x.R + 0.5)
		if initial >= x.N {
			return fmt.Errorf("%s: r leaves no valid certificate at N=%d", name, x.N)
		}

		if x.K > 0 && uint64(x.K) > x.N-initial {
			return fmt.Errorf("%s: k=%d exceeds unrevoked population for N=%d r=%g", name, x.K, x.N, x.R)
		}

		if x.M > 0 && x.K > 0 && uint64(x.M)*uint64(x.K) > x.N-initial {
			return fmt.Errorf("%s: m*k exceeds unrevoked population for N=%d r=%g", name, x.N, x.R)
		}

		out = append(out, x)

		return nil
	}

	switch name {
	case "storage", "lookup":
		for _, n := range s.N {
			for _, r := range s.R {
				for _, blockSize := range s.BlockSize {
					for _, placement := range s.Placement {
						if err := add(Case{Kind: name, N: n, R: r, BlockSize: blockSize, Placement: placement}); err != nil {
							return nil, err
						}
					}
				}
			}
		}
	case "rp-sync":
		for _, n := range s.N {
			for _, r := range s.R {
				for _, blockSize := range s.BlockSize {
					for _, t := range s.T {
						for _, placement := range s.Placement {
							if err := add(Case{Kind: "full", N: n, R: r, BlockSize: blockSize, T: t, Placement: placement}); err != nil {
								return nil, err
							}

							for _, k := range s.K {
								for _, m := range s.M {
									if err := add(Case{Kind: "incremental", N: n, R: r, K: k, BlockSize: blockSize, M: m, T: t, Placement: placement}); err != nil {
										return nil, err
									}
								}
							}
						}
					}
				}
			}
		}
	case "disclosure":
		for _, n := range s.N {
			for _, r := range s.R {
				for _, k := range s.K {
					for _, blockSize := range s.BlockSize {
						for _, m := range s.M {
							for _, t := range s.T {
								for _, placement := range s.Placement {
									if err := add(Case{Kind: name, N: n, R: r, K: k, BlockSize: blockSize, M: m, T: t, Placement: placement}); err != nil {
										return nil, err
									}
								}
							}
						}
					}
				}
			}
		}
	case "epoch":
		for _, n := range s.N {
			for _, r := range s.R {
				for _, k := range s.K {
					for _, blockSize := range s.BlockSize {
						for _, t := range s.T {
							for _, placement := range s.Placement {
								if err := add(Case{Kind: name, N: n, R: r, K: k, BlockSize: blockSize, T: t, Placement: placement}); err != nil {
									return nil, err
								}
							}
						}
					}
				}
			}
		}
	default:
		return nil, fmt.Errorf("unknown benchmark %q", name)
	}

	return out, nil
}

// Returns the number of cases for the specified benchmark.
func (c Config) Count() (int, error) {
	total := 0
	for _, name := range c.Benchmarks {
		cases, err := c.Expand(name)
		if err != nil {
			return 0, err
		}

		total += len(cases)
	}

	return total, nil
}
