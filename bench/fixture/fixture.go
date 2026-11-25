// This package builds Fixtures for the benchmarks. 
// A Fixture is an instance of a network with a set of revoked indices based on parameters from a Case.
// 
// 
// Note that one fixture may be reused multiple times in a benchmark, which means the rate of revocation grows
// with each reuse. This is why Drifted() is used to detect if the fixture is still valid. If Drifted() returns true, the fixture is no longer valid and is replaced with a fresh one.
// 
// This does mean that benchmark numbers will be slightly worse than what they would be if a fresh fixture is used for every benchmark.
// However, this way of implementation allows for faster benchmarking (especially for higher loads) as the network does not have to be rebuilt each time.
package fixture

import (
	"fmt"
	"math"
	"math/rand/v2"
	"os"

	"mtcrt/bench/config"
	"mtcrt/crv"
	"mtcrt/epoch"
)

// Definition of a Fixture as defined above.
type Fixture struct {
	Net       *epoch.Network
	N         uint64
	TargetR   float64
	Placement string
	Revoked   map[uint64]struct{}

	dir       string
	rngStream uint64
	seed      uint64
}

// Builds a new network and runs one epoch to simulate an ongoing network state.
func New(c config.Case, seed uint64) (*Fixture, error) {
	real, shadows := signatureParties(c.T)
	dir, err := os.MkdirTemp("", "mtcrt-bench-")
	if err != nil {
		return nil, err
	}

	net, err := epoch.New(epoch.Config{
		LogID: []byte("bench-log"), LogNumber: 1, BlockSize: c.BlockSize,
		Cosigners: real, Shadows: shadows, RecordDir: dir,
	})

	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}

	f := &Fixture{
		Net: net, N: c.N, TargetR: c.R, Placement: c.Placement,
		Revoked: make(map[uint64]struct{}), dir: dir, seed: seed,
	}
	net.Issue(c.N)
	net.Checkpoint()

	initial := int(math.Round(c.R * float64(c.N)))
	indices, err := SelectIndices(f.nextRNG(), c.N, initial, c.Placement, f.Revoked)
	if err != nil {
		f.Close()
		return nil, err
	}

	for _, idx := range indices {
		if err := net.Revoke(net.Serial(idx)); err != nil {
			f.Close()
			return nil, err
		}

		f.Revoked[idx] = struct{}{}
	}

	if _, err := net.RunEpoch(); err != nil {
		f.Close()
		return nil, fmt.Errorf("building fixture epoch: %w", err)
	}

	return f, nil
}

// Splits t signatures into one real cosigner and shadow cosigners.
func signatureParties(t int) (real, shadows int) {
	if t <= 1 {
		return 0, 0
	}

	return 1, t - 2
}

// Returns the next generator and advances the stream.
// Ensures that indices are selected independently for each fixture.
func (f *Fixture) nextRNG() *rand.Rand {
	r := RNG(f.seed, f.rngStream)
	f.rngStream++

	return r
}

// Submits count new revocations and runs one epoch.
func (f *Fixture) AddEpoch(count int) (epoch.EpochResult, []uint64, error) {
	indices, err := f.SubmitRevocations(count)
	if err != nil {
		return epoch.EpochResult{}, nil, err
	}

	res, err := f.Net.RunEpoch()

	return res, indices, err
}

// Queues count new revocations and does not advance the epoch.
// This is used to avoid timing initial revocation submissions in the benchmarks.
func (f *Fixture) SubmitRevocations(count int) ([]uint64, error) {
	rng := RNG(f.seed, f.rngStream)
	f.rngStream++

	indices, err := SelectIndices(rng, f.N, count, f.Placement, f.Revoked)
	if err != nil {
		return nil, err
	}

	for _, idx := range indices {
		if err := f.Net.Revoke(f.Net.Serial(idx)); err != nil {
			return nil, err
		}

		f.Revoked[idx] = struct{}{}
	}

	return indices, nil
}

// Returns the fraction of indices that are revoked in the fixture.
func (f *Fixture) RActual() float64 {
	return float64(len(f.Revoked)) / float64(f.N)
}

// Reports whether measured epochs pushed the revoked fraction more than 5% above the target.
func (f *Fixture) Drifted() bool {
	return f.RActual()-f.TargetR > 0.05*f.TargetR
}

// Deletes the temporary cosigner signing record directory.
func (f *Fixture) Close() error { return os.RemoveAll(f.dir) }

// Builds crv_bits and the set of revoked indices, with no network.
// Used to benchmark storage sizes as it is independent of the network.
func BuildVector(c config.Case, seed uint64) (*crv.Vector, map[uint64]struct{}, error) {
	vec, err := crv.New(c.BlockSize)
	if err != nil {
		return nil, nil, err
	}

	vec.Expand(c.N)
	revoked := make(map[uint64]struct{})
	count := int(math.Round(c.R * float64(c.N)))
	indices, err := SelectIndices(RNG(seed, 0), c.N, count, c.Placement, revoked)
	if err != nil {
		return nil, nil, err
	}

	for _, idx := range indices {
		revoked[idx] = struct{}{}
	}
	vec.SetBits(indices)

	return vec, revoked, nil
}
