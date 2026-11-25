// This package is one cosigner for one log.
//
// It follows the issuance log, checks each epoch the CA proposes, and
// signs only what it has checked.
package cosigner

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"mtcrt/accum"
	"mtcrt/crv"
	"mtcrt/merkle"
	"mtcrt/sig"
	"mtcrt/wire"
)

// Possibler errors for cosigners. Error messages are not used in benchmarking, just used as error return values since the cosigner still needs to simulate error checks.
var (
	ErrBadCASignature     = errors.New("cosigner: proposal's CA signature does not verify; ignored")
	ErrNotNewer           = errors.New("cosigner: proposed epoch is not later than the last one signed")
	ErrAnRootMismatch     = errors.New("cosigner: A_n root does not match the events")
	ErrStaleTime          = errors.New("cosigner: T_publish is outside Δ_clk")
	ErrTreeSizeDecreased  = errors.New("cosigner: tree_size decreased")
	ErrTreeSizeUnobserved = errors.New("cosigner: tree_size larger than observed in the issuance log")
	ErrMinSerialDecreased = errors.New("cosigner: minSerial decreased")
	ErrIndexOutOfRange    = errors.New("cosigner: event index is not below tree_size")
	ErrBelowMinSerial     = errors.New("cosigner: event is below minSerial")
	ErrBlockRootMismatch  = errors.New("cosigner: block_root does not match our own crv_bits")
)

// Config sets up a cosigner for one log.
type Config struct {
	ID        string
	LogID     []byte
	LogNumber uint64
	BlockSize int
	Key       sig.PrivateKey

	CAKey sig.PublicKey

	MaxClockDelta time.Duration // how far T_publish may be from the clock
	Clock         func() time.Time

	RecordPath string // path where the signing record is persisted
}

// Asks the CA for what is needed to check an epoch.
type ProposalSource func(wire.ProposalRequest) (wire.ProposalResponse, error)

// Cosigner state for one log.
type Cosigner struct {
	mu  sync.Mutex // for cosigner signing and state update atomicity
	cfg Config

	records *recordStore
	record  *SigningRecord

	state  wire.EpochState
	anSize uint64
	vec    *crv.Vector
}

// Creates a new cosigner.
func New(cfg Config) (*Cosigner, error) {
	if err := checkConfig(&cfg); err != nil {
		return nil, err
	}

	records, err := createRecordStore(cfg.RecordPath)
	if err != nil {
		return nil, err
	}

	vec, err := crv.New(cfg.BlockSize)
	if err != nil {
		return nil, err
	}

	return &Cosigner{
		cfg:     cfg,
		records: records,
		state:   wire.EpochState{AnRoot: merkle.EmptyRoot(), BlockRoot: merkle.EmptyRoot()},
		vec:     vec,
	}, nil
}

// checks that the config is valid.
func checkConfig(cfg *Config) error {
	if err := wire.ValidateLogID(cfg.LogID); err != nil {
		return err
	}

	if cfg.Key == nil || cfg.CAKey == nil {
		return errors.New("cosigner: missing key or CA key")
	}

	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}

	return nil
}

// Returns the cosigner's ID.
func (c *Cosigner) ID() string { return c.cfg.ID }

// Expands the vector to the given tree size.
func (c *Cosigner) ObserveCheckpoint(treeSize uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.vec.Expand(treeSize)
}

// Receives a proposal from the CA and returns a cosignature if it is accepted.
func (c *Cosigner) ReceiveProposal(ann wire.Proposal, fetch ProposalSource) (wire.Cosignature, error) {
	// atomic verification, signing, and record persistence.
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.cfg.CAKey.Verify(ann.State.SignedDigest(c.cfg.LogID), ann.CASignature) {
		return wire.Cosignature{}, ErrBadCASignature
	}

	if ann.State.P <= c.state.P {
		return wire.Cosignature{}, ErrNotNewer
	}

	resp, err := fetch(wire.ProposalRequest{P: ann.State.P, FromSize: c.anSize})
	if err != nil {
		return wire.Cosignature{}, fmt.Errorf("cosigner: fetching proposal: %w", err)
	}

	return c.verifyAndSign(ann, resp)
}

// Verifies the proposal and provides a cosignature.
func (c *Cosigner) verifyAndSign(ann wire.Proposal, resp wire.ProposalResponse) (wire.Cosignature, error) {
	claimed := ann.State

	// The new A_n root must be exactly the old tree plus these events.
	anRoot, err := accum.Extend(c.anSize, c.state.AnRoot, resp.PrefixHashes, resp.Events)
	if err != nil {
		return wire.Cosignature{}, fmt.Errorf("%w: %v", ErrAnRootMismatch, err)
	}

	if anRoot != claimed.AnRoot {
		return wire.Cosignature{}, ErrAnRootMismatch
	}

	// T_publish must sit within MaxClockDelta of the cosigner clock.
	now := c.cfg.Clock()
	if claimed.TPublish.Before(now.Add(-c.cfg.MaxClockDelta)) || claimed.TPublish.After(now.Add(c.cfg.MaxClockDelta)) {
		return wire.Cosignature{}, ErrStaleTime
	}

	switch {
	case claimed.TreeSize < c.state.TreeSize:
		return wire.Cosignature{}, ErrTreeSizeDecreased
	case claimed.TreeSize > c.vec.Size():
		return wire.Cosignature{}, ErrTreeSizeUnobserved
	case claimed.MinSerial < c.state.MinSerial:
		return wire.Cosignature{}, ErrMinSerialDecreased
	}

	for _, idx := range resp.Events {
		if idx >= claimed.TreeSize {
			return wire.Cosignature{}, ErrIndexOutOfRange
		}

		if wire.Serial(c.cfg.LogNumber, idx) < claimed.MinSerial {
			return wire.Cosignature{}, ErrBelowMinSerial
		}
	}

	c.vec.Stage()
	c.vec.SetBits(resp.Events)

	blockRoot := c.vec.Root(claimed.TreeSize)
	if blockRoot != claimed.BlockRoot {
		c.vec.Rollback()
		return wire.Cosignature{}, ErrBlockRootMismatch
	}

	// Sign and persist record.
	own := wire.EpochState{
		P:         claimed.P,
		TreeSize:  claimed.TreeSize,
		MinSerial: claimed.MinSerial,
		AnRoot:    anRoot,
		BlockRoot: blockRoot,
		TPublish:  claimed.TPublish,
	}

	signature := c.cfg.Key.Sign(own.SignedDigest(c.cfg.LogID))

	rec := SigningRecord{
		LogID:       c.cfg.LogID,
		State:       own,
		AnSize:      c.anSize + uint64(len(resp.Events)),
		Signature:   signature,
		CASignature: ann.CASignature,
	}

	if err := c.records.save(rec); err != nil {
		c.vec.Rollback()
		return wire.Cosignature{}, fmt.Errorf("cosigner: signing record not persisted, signature withheld: %w", err)
	}

	c.vec.Commit()
	c.record = &rec
	c.state = own
	c.anSize = rec.AnSize

	return wire.Cosignature{CosignerID: c.cfg.ID, Signature: signature}, nil
}
