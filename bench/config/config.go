// This package loads a benchmark config and checks it before any run.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"slices"
)

var validBenchmarks = []string{"storage", "rp-sync", "disclosure", "epoch", "lookup"}

// Sweep defines a set of parameter values that will be swept over in a benchmark.
type Sweep struct {
	N         []uint64  `json:"N"`
	R         []float64 `json:"r"`
	K         []int     `json:"k"`
	BlockSize []int     `json:"B"`
	M         []int     `json:"m"`
	T         []int     `json:"t"`
	Placement []string  `json:"placement"`
}

// Config is the JSON benchmark configuration.
type Config struct {
	Benchmarks []string         `json:"benchmarks"` // the benchmarks to run (from validBenchmarks)
	Out        string           `json:"out"`  // output directory for benchmark results
	Seed       uint64           `json:"seed"`  // seed for reproducibility
	Reps       int              `json:"reps"`  // number of times to run each benchmark
	Warmup     int              `json:"warmup"` // number of warmup runs before the main benchmark
	Sweep      Sweep            `json:"sweep"`  // the parameters to sweep over
	Overrides  map[string]Sweep `json:"overrides"` // overrides for specific benchmarks
}

// Loads a config file. Checks that the config is valid.
func Load(path string) (Config, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, nil, err
	}

	var cfg Config
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, nil, fmt.Errorf("config: %w", err)
	}

	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Config{}, nil, fmt.Errorf("config: trailing JSON value")
		}

		return Config{}, nil, fmt.Errorf("config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, nil, err
	}

	return cfg, data, nil
}

// Checks that config is valid.
func (c Config) Validate() error {
	if len(c.Benchmarks) == 0 {
		return fmt.Errorf("config: benchmarks must be non-empty")
	}

	for _, name := range c.Benchmarks {
		if !slices.Contains(validBenchmarks, name) {
			return fmt.Errorf("config: benchmarks contains unknown benchmark %q", name)
		}
	}

	if c.Out == "" {
		return fmt.Errorf("config: out must be non-empty")
	}

	if c.Reps < 1 {
		return fmt.Errorf("config: reps must be at least 1")
	}

	if c.Warmup < 0 {
		return fmt.Errorf("config: warmup must be non-negative")
	}

	if err := validateSweep(c.Sweep, true, "sweep"); err != nil {
		return err
	}

	for name, override := range c.Overrides {
		if !slices.Contains(validBenchmarks, name) {
			return fmt.Errorf("config: overrides names unknown benchmark %q", name)
		}

		if err := validateSweep(override, false, "overrides."+name); err != nil {
			return err
		}
	}

	for _, name := range c.Benchmarks {
		if err := validateSweep(c.ForBenchmark(name), true, "effective."+name); err != nil {
			return err
		}
	}

	return nil
}

// Checks that sweep is valid.
// requireAll means every field must be present, e.g. it is used for the main sweep, whereas overrides may only specify a subset of the fields to be overriden.
func validateSweep(s Sweep, requireAll bool, prefix string) error {
	type field struct {
		name string
		n    int
		nil  bool
	}

	fields := []field{
		{"N", len(s.N), s.N == nil}, {"r", len(s.R), s.R == nil},
		{"k", len(s.K), s.K == nil}, {"B", len(s.BlockSize), s.BlockSize == nil},
		{"m", len(s.M), s.M == nil}, {"t", len(s.T), s.T == nil},
		{"placement", len(s.Placement), s.Placement == nil},
	}

	for _, f := range fields {
		if requireAll && f.nil {
			return fmt.Errorf("config: %s.%s must be present and non-empty", prefix, f.name)
		}

		if !f.nil && f.n == 0 {
			return fmt.Errorf("config: %s.%s must be non-empty", prefix, f.name)
		}
	}

	for _, n := range s.N {
		if n < 1 || n >= 1<<48 {
			return fmt.Errorf("config: %s.N value %d must be in [1, 2^48)", prefix, n)
		}
	}

	for _, r := range s.R {
		if math.IsNaN(r) || r < 0 || r >= 1 {
			return fmt.Errorf("config: %s.r value %v must be in [0, 1)", prefix, r)
		}

		for _, n := range s.N {
			if r != 0 && math.Round(r*float64(n)) < 1 {
				return fmt.Errorf("config: %s.r value %v rounds to no revocations for N=%d", prefix, r, n)
			}
		}
	}

	for _, k := range s.K {
		if k < 1 {
			return fmt.Errorf("config: %s.k value %d must be at least 1", prefix, k)
		}
	}

	for _, blockSize := range s.BlockSize {
		if blockSize < 8 || blockSize&(blockSize-1) != 0 {
			return fmt.Errorf("config: %s.B value %d must be a power of two and at least 8", prefix, blockSize)
		}
	}

	for _, m := range s.M {
		if m < 1 {
			return fmt.Errorf("config: %s.m value %d must be at least 1", prefix, m)
		}
	}

	for _, t := range s.T {
		if t < 1 {
			return fmt.Errorf("config: %s.t value %d must be at least 1", prefix, t)
		}
	}

	for _, p := range s.Placement {
		if p != "uniform" && p != "clustered" {
			return fmt.Errorf("config: %s.placement value %q must be uniform or clustered", prefix, p)
		}
	}

	return nil
}

// Returns the sweep for one benchmark, with overrides applied.
func (c Config) ForBenchmark(name string) Sweep {
	s := c.Sweep
	o, ok := c.Overrides[name]
	if !ok {
		return s
	}

	if o.N != nil {
		s.N = o.N
	}
	if o.R != nil {
		s.R = o.R
	}
	if o.K != nil {
		s.K = o.K
	}
	if o.BlockSize != nil {
		s.BlockSize = o.BlockSize
	}
	if o.M != nil {
		s.M = o.M
	}
	if o.T != nil {
		s.T = o.T
	}
	if o.Placement != nil {
		s.Placement = o.Placement
	}

	return s
}
