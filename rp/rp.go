// This package is a relying party receiving updates from one distributor for one log.
package rp

import (
	"errors"
	"fmt"
	"time"

	"mtcrt/crv"
	"mtcrt/policy"
	"mtcrt/wire"
)

// Error for when the distributor has no signed epoch yet.
var ErrNothingCosigned = errors.New("rp: distributor has no cosigned epoch yet")

// Rejection is a sync response that failed a check. State is unmodified.
type Rejection struct {
	Step   int
	Reason string
}

// Returns the step and the reason for rejection.
func (r *Rejection) Error() string {
	return fmt.Sprintf("rp rejected sync (Verifying a Synchronization, step %d): %s", r.Step, r.Reason)
}

// Creates a rejection for a failed check.
func reject(step int, format string, args ...any) error {
	return &Rejection{Step: step, Reason: fmt.Sprintf(format, args...)}
}

// Status is the result of a lookup. Used to determine if a certificate is revoked.
type Status int

const (
	Valid   Status = iota // not revoked
	Revoked               // revoked, or below minSerial
	Unknown               // this party cannot say
)

// Config for a relying party for one log.
type Config struct {
	LogID     []byte
	LogNumber uint64
	BlockSize int
	Policy    policy.Policy
}

// RP is a relying party's revocation state for one log.
type RP struct {
	cfg    Config
	synced bool
	state  wire.EpochState
	vec    *crv.Vector
	last   Timings
}

// How long the last sync took.
type Timings struct {
	Total time.Duration
}

// Creates a relying party with no state.
func New(cfg Config) (*RP, error) {
	if err := wire.ValidateLogID(cfg.LogID); err != nil {
		return nil, err
	}

	vec, err := crv.New(cfg.BlockSize)
	if err != nil {
		return nil, err
	}

	return &RP{cfg: cfg, vec: vec}, nil
}

// Returns the last accepted epoch, and whether there is one.
func (r *RP) State() (wire.EpochState, bool) { return r.state, r.synced }

// Returns the timings of the last sync.
func (r *RP) LastTimings() Timings { return r.last }

// Checks a sync response and, if every check passes, updates state.
// On any error, the state is unmodified.
func (r *RP) ApplySync(resp wire.SyncResponse) error {
	r.last = Timings{}

	// Time the total duration of the sync.
	totalStart := time.Now()
	defer func() { r.last.Total = time.Since(totalStart) }()

	switch resp.Kind {
	case wire.SyncUnavailable:
		return ErrNothingCosigned
	case wire.SyncUpToDate:
		return nil
	case wire.SyncUpdate:
		if !r.synced {
			return reject(3, "incremental update, but this RP has no state to update")
		}
	case wire.SyncFull:
	default:
		return reject(3, "unknown response kind %v", resp.Kind)
	}

	s := resp.State

	// The digest uses the log id we asked about, never one from the message.
	digest := s.SignedDigest(r.cfg.LogID)
	if err := r.cfg.Policy.Check(digest, resp.Cosignatures); err != nil {
		return reject(2, "%v", err)
	}

	// An older epoch is refused, even when its signatures are valid.
	if r.synced && s.P < r.state.P {
		return reject(3, "epoch %d is older than our epoch %d", s.P, r.state.P)
	}

	if resp.Kind == wire.SyncFull {
		return r.applyFullSync(resp)
	}

	if s.TreeSize < r.state.TreeSize {
		return reject(5, "tree_size decreased from %d to %d", r.state.TreeSize, s.TreeSize)
	}

	// Grow the vector, then overwrite the changed blocks.
	// If a mismatch occurs, roll back the entire vector.
	r.vec.Stage()
	r.vec.Expand(s.TreeSize)
	for _, b := range resp.Blocks {
		if err := r.vec.SetBlock(b.ID, b.Content); err != nil {
			r.vec.Rollback()
			return reject(5, "%v", err)
		}
	}

	if r.vec.Root(s.TreeSize) != s.BlockRoot {
		r.vec.Rollback()
		return reject(6, "block_root does not match the blocks received")
	}

	r.vec.Commit()
	r.state = s
	r.synced = true

	return nil
}

// Rebuilds the vector from every block, and keeps it only if the root matches.
func (r *RP) applyFullSync(resp wire.SyncResponse) error {
	s := resp.State
	vec, err := crv.New(r.cfg.BlockSize)
	if err != nil {
		return err
	}

	vec.Expand(s.TreeSize)
	for _, b := range resp.Blocks {
		if err := vec.SetBlock(b.ID, b.Content); err != nil {
			return reject(5, "%v", err)
		}
	}

	if vec.Root(s.TreeSize) != s.BlockRoot {
		return reject(6, "block_root does not match the blocks received")
	}

	r.vec = vec
	r.state = s
	r.synced = true

	return nil
}

// Performs a lookup for a certificate.
func (r *RP) Lookup(serial uint64) Status {
	// Everything below minSerial is revoked.
	if r.synced && serial < r.state.MinSerial {
		return Revoked
	}

	logNumber, idx := wire.SplitSerial(serial)
	if logNumber != r.cfg.LogNumber || !r.synced || idx >= r.state.TreeSize {
		return Unknown
	}

	if r.vec.Get(idx) {
		return Revoked
	}

	return Valid
}
