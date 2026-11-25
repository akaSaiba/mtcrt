// This package implements the CA.
package ca

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"mtcrt/accum"
	"mtcrt/crv"
	"mtcrt/sig"
	"mtcrt/wire"
)

// Possible Errors. Erros never occur in benchmarking, just used as error return values since the CA still needs to simulate error checks.
var (
	ErrNothingToDo     = errors.New("ca: no new revocations and no new blocks, so no epoch to advance")
	ErrWrongLog        = errors.New("ca: serial number is from a different log")
	ErrNotIssued       = errors.New("ca: index is not below tree_size")
	ErrBelowMinSerial  = errors.New("ca: serial number is below minSerial")
	ErrAlreadyRevoked  = errors.New("ca: certificate is already revoked or queued")
	ErrUnknownEpoch    = errors.New("ca: no such epoch")
	ErrUnknownCosigner = errors.New("ca: signature from a cosigner the CA does not use")
	ErrBadCosignature  = errors.New("ca: cosignature does not verify")
)

// Config for a CA.
type Config struct {
	LogID     []byte
	LogNumber uint64
	BlockSize int

	ID  string
	Key sig.PrivateKey

	// Cosigners are the extra signers. Quorum is how many of them must
	// sign before the epoch is handed to the distributor.
	Cosigners map[string]sig.PublicKey
	Quorum    int

	Clock func() time.Time
}

// What the CA keeps for one epoch.
type epochRecord struct {
	Proposal wire.Proposal
	anSize   uint64
	cosigs   map[string][]byte
}

// CA state.
type CA struct {
	cfg Config

	an  accum.Log
	vec *crv.Vector

	queue     []uint64
	queued    map[uint64]bool
	minSerial uint64

	liveSize       uint64 // tree size right now
	checkpointSize uint64 // tree size of the latest checkpoint (a checkpoint is the last signed tree size for the issuance tree)

	epochs []epochRecord
	dist   *Distributor

	lastCosignatureTimings CosignatureTimings
}

// Splits timing data for checking and adding cosignatures, then publishing the epoch to a distributor.
type CosignatureTimings struct {
	Add     time.Duration
	Publish time.Duration
}

// Creates a CA.
func New(cfg Config) (*CA, error) {
	if err := wire.ValidateLogID(cfg.LogID); err != nil {
		return nil, err
	}

	if cfg.Key == nil {
		return nil, errors.New("ca: no CA key")
	}

	if cfg.Quorum < 0 || cfg.Quorum > len(cfg.Cosigners) {
		return nil, fmt.Errorf("ca: quorum %d with %d cosigners", cfg.Quorum, len(cfg.Cosigners))
	}

	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}

	vec, err := crv.New(cfg.BlockSize)
	if err != nil {
		return nil, err
	}

	dist, err := newDistributor(cfg.BlockSize)
	if err != nil {
		return nil, err
	}

	c := &CA{cfg: cfg, vec: vec, queued: make(map[uint64]bool), dist: dist}
	initial := wire.EpochState{
		P:         0,
		AnRoot:    c.an.Root(),
		BlockRoot: c.vec.Root(0),
		TPublish:  c.now(),
	}

	c.epochs = append(c.epochs, epochRecord{
		Proposal: wire.Proposal{State: initial},
		cosigs:   make(map[string][]byte),
	})

	return c, nil
}

// Returns the distributor for the CA.
func (c *CA) Distributor() *Distributor { return c.dist }

// Returns the timings of the last AddCosignature.
func (c *CA) LastCosignatureTimings() CosignatureTimings {
	return c.lastCosignatureTimings
}

// Adds count certificates. Certificates are kept as a vector, doesn't model MTC issuance tree.
func (c *CA) Issue(count uint64) {
	c.liveSize += count
	c.vec.Expand(c.liveSize)
}

// Simulates a checkpoint created for the issuance tree.
func (c *CA) Checkpoint() uint64 {
	c.checkpointSize = c.liveSize

	return c.checkpointSize
}

// Queues a revocation. The index must be below the current tree size.
func (c *CA) SubmitRevocation(serial uint64) error {
	logNumber, idx := wire.SplitSerial(serial)

	switch {
	case logNumber != c.cfg.LogNumber:
		return ErrWrongLog
	case idx >= c.liveSize:
		return ErrNotIssued
	case serial < c.minSerial:
		return ErrBelowMinSerial
	case c.vec.Get(idx) || c.queued[idx]:
		return ErrAlreadyRevoked
	}

	c.queue = append(c.queue, idx)
	c.queued[idx] = true

	return nil
}

// Processes an epoch. Returns cosigner proposal for the epoch.
func (c *CA) ProcessEpoch() (wire.Proposal, error) {
	prev := c.epochs[len(c.epochs)-1].Proposal.State
	p := prev.P + 1
	np := c.checkpointSize

	// Drop events below minSerial.
	var batch, keep []uint64
	for _, idx := range c.queue {
		switch {
		case wire.Serial(c.cfg.LogNumber, idx) < c.minSerial:
			delete(c.queued, idx)
		case idx >= np:
			keep = append(keep, idx)
		default:
			batch = append(batch, idx)
		}
	}
	c.queue = keep

	grew := crv.BlocksFor(np, c.cfg.BlockSize) > crv.BlocksFor(prev.TreeSize, c.cfg.BlockSize)
	if len(batch) == 0 && !grew {
		return wire.Proposal{}, ErrNothingToDo
	}

	for _, idx := range batch {
		delete(c.queued, idx)
		c.an.Append(idx)
	}

	// Set bits in local crv_bits.
	c.vec.SetBits(batch)

	state := wire.EpochState{
		P:         p,
		TreeSize:  np,
		MinSerial: c.minSerial,
		AnRoot:    c.an.Root(),
		BlockRoot: c.vec.Root(np),
		TPublish:  c.now(),
	}

	// Cosigner proposal announcement.
	ann := wire.Proposal{
		State:       state,
		CASignature: c.cfg.Key.Sign(state.SignedDigest(c.cfg.LogID)),
	}

	c.epochs = append(c.epochs, epochRecord{
		Proposal: ann,
		anSize:   c.an.Size(),
		cosigs:   make(map[string][]byte),
	})

	if c.cfg.Quorum == 0 {
		if err := c.distribute(p); err != nil {
			return ann, err
		}
	}

	return ann, nil
}

// Serves a proposal to the cosigner, i.e. provides events and consistency proof.
func (c *CA) ServeProposal(req wire.ProposalRequest) (wire.ProposalResponse, error) {
	if req.P >= uint64(len(c.epochs)) {
		return wire.ProposalResponse{}, ErrUnknownEpoch
	}

	rec := c.epochs[req.P]
	if req.FromSize > rec.anSize {
		return wire.ProposalResponse{}, fmt.Errorf("ca: cosigner claims %d events, epoch %d has %d", req.FromSize, req.P, rec.anSize)
	}

	return wire.ProposalResponse{
		Events:       c.an.Events(req.FromSize, rec.anSize),
		PrefixHashes: c.an.PrefixHashes(req.FromSize),
	}, nil
}

// Records one cosigner's signature to the epoch. Once Quorum of them have signed, the epoch goes to the distributor.
func (c *CA) AddCosignature(p uint64, cs wire.Cosignature) error {
	c.lastCosignatureTimings = CosignatureTimings{}

	// t_add_cosig: check one signature and store it.
	start := time.Now()
	if p == 0 || p >= uint64(len(c.epochs)) {
		c.lastCosignatureTimings.Add = time.Since(start)
		return ErrUnknownEpoch
	}

	key, ok := c.cfg.Cosigners[cs.CosignerID]
	if !ok {
		c.lastCosignatureTimings.Add = time.Since(start)
		return ErrUnknownCosigner
	}

	rec := &c.epochs[p]
	if !key.Verify(rec.Proposal.State.SignedDigest(c.cfg.LogID), cs.Signature) {
		c.lastCosignatureTimings.Add = time.Since(start)
		return ErrBadCosignature
	}

	rec.cosigs[cs.CosignerID] = cs.Signature
	c.lastCosignatureTimings.Add = time.Since(start)

	if len(rec.cosigs) >= c.cfg.Quorum && p > c.dist.epoch() {
		start = time.Now()
		err := c.distribute(p)
		c.lastCosignatureTimings.Publish = time.Since(start)

		return err
	}

	return nil
}

// Distributes epoch p to the distributor.
func (c *CA) distribute(p uint64) error {
	from := c.epochs[c.dist.epoch()].anSize
	rec := c.epochs[p]
	events := c.an.Events(from, rec.anSize)

	return c.dist.publish(rec.Proposal.State, c.cosignatureSet(p), events)
}

// Returns cosignature set for the epoch.
func (c *CA) cosignatureSet(p uint64) []wire.Cosignature {
	rec := c.epochs[p]
	set := []wire.Cosignature{{CosignerID: c.cfg.ID, Signature: rec.Proposal.CASignature}}

	ids := make([]string, 0, len(rec.cosigs))
	for id := range rec.cosigs {
		ids = append(ids, id)
	}
	slices.Sort(ids)

	for _, id := range ids {
		set = append(set, wire.Cosignature{CosignerID: id, Signature: rec.cosigs[id]})
	}

	return set
}

// Clock time
func (c *CA) now() time.Time {
	return time.UnixMilli(c.cfg.Clock().UnixMilli())
}
