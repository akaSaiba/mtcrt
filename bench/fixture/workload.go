package fixture

import (
	"fmt"
	"math/rand/v2"
)

// Mean length of a clustered run of revoked indices.
const clusterMean = 64.0

// Returns a deterministic generator given a seed and a stream.
func RNG(seed, stream uint64) *rand.Rand {
	// the or operation is used to make simple seed and streams such as seed=0, stream=0 into more random ones.
	return rand.New(rand.NewPCG(seed^0x9e3779b97f4a7c15, stream^0xda3e39cb94b95bdb))
}

// Picks count indices from [0, n), (random revocation selection)
// placement is "uniform" or "clustered".
// Returns a list of chosen indices
func SelectIndices(rng *rand.Rand, n uint64, count int, placement string, excluded map[uint64]struct{}) ([]uint64, error) {
	if n == 0 || count < 0 || uint64(count) > n-uint64(len(excluded)) {
		return nil, fmt.Errorf("cannot choose %d indices from %d with %d excluded", count, n, len(excluded))
	}

	chosen := make(map[uint64]struct{}, count)
	out := make([]uint64, 0, count)
	add := func(idx uint64) {
		if _, found := excluded[idx]; found {
			return
		}

		if _, found := chosen[idx]; found {
			return
		}

		chosen[idx] = struct{}{}
		out = append(out, idx)
	}

	switch placement {
	case "uniform":
		attempts := 0 // infinite loop prevention, *20 + 555 is just a random number
		for len(out) < count && attempts < count*20+555 {
			add(rng.Uint64N(n))
			attempts++
		}
	case "clustered":
		for rounds := 0; len(out) < count && rounds < count*20+555; rounds++ {
			start := rng.Uint64N(n)

			// simulates runs of expected length of clusterMean
			length := 1
			for rng.Float64() >= 1/clusterMean {
				length++
			}

			for j := 0; j < length && len(out) < count && start+uint64(j) < n; j++ {
				add(start + uint64(j))
			}
		}
	default:
		return nil, fmt.Errorf("unknown placement %q", placement)
	}

	if len(out) != count {
		// this is very unlikely to happen, but it's possible that the random indices selection has a collision.
		return nil, fmt.Errorf("selected %d indices, want %d", len(out), count)
	}

	return out, nil
}
