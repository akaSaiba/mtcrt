package ca

import (
	"fmt"
	"slices"

	"mtcrt/crv"
	"mtcrt/wire"
)

// Distributor serves relying parties.
//
// It keeps its own copy of the bit vector, updated only when an epoch is
// fully signed. The CA can be ahead of that: it sets the new bits as soon
// as it announces an epoch, but parties must still be served the last
// signed epoch.
type Distributor struct {
	vec         *crv.Vector
	lastChanged []uint64 // epoch that last changed each block

	published bool
	state     wire.EpochState
	cosigs    []wire.Cosignature
}

// Returns an empty distributor.
func newDistributor(blockSize int) (*Distributor, error) {
	vec, err := crv.New(blockSize)
	if err != nil {
		return nil, err
	}

	return &Distributor{vec: vec}, nil
}

// Returns the latest epoch served, and whether any epoch has been served.
func (d *Distributor) Epoch() (uint64, bool) { return d.state.P, d.published }

// Returns the latest epoch served, or 0 before the first.
func (d *Distributor) epoch() uint64 { return d.state.P }

// Moves to a newly signed epoch and applies the events added since the last one.
func (d *Distributor) publish(state wire.EpochState, cosigs []wire.Cosignature, events []uint64) error {
	d.vec.Expand(state.TreeSize)

	for uint64(len(d.lastChanged)) < d.vec.NumBlocks() {
		d.lastChanged = append(d.lastChanged, 0)
	}

	for _, block := range d.vec.SetBits(events) {
		d.lastChanged[block] = state.P
	}

	if d.vec.Root(state.TreeSize) != state.BlockRoot {
		return fmt.Errorf("ca: distributor's block_root for epoch %d differs from the CA's", state.P)
	}

	d.state = state
	d.cosigs = cosigs
	d.published = true

	return nil
}

// Answers a sync request: nothing yet, already current, a full copy, or
// the blocks that changed.
func (d *Distributor) Serve(req wire.SyncRequest) wire.SyncResponse {
	switch {
	case !d.published:
		return wire.SyncResponse{Kind: wire.SyncUnavailable}
	case req.HasState && req.LastP >= d.state.P:
		return wire.SyncResponse{Kind: wire.SyncUpToDate}
	}

	resp := wire.SyncResponse{
		Kind:         wire.SyncUpdate,
		State:        d.state,
		Cosignatures: d.cosignatures(),
	}
	if !req.HasState {
		resp.Kind = wire.SyncFull
	}

	// Send every block a revocation changed after the party's epoch.
	// A full sync sends every block. New all-zero blocks are not sent.
	// The party creates those itself when it grows.
	for id, changedAt := range d.lastChanged {
		if !req.HasState || changedAt > req.LastP {
			resp.Blocks = append(resp.Blocks, wire.Block{ID: uint64(id), Content: d.vec.Block(uint64(id))})
		}
	}

	return resp
}

// Returns a copy of the cosignature set.
func (d *Distributor) cosignatures() []wire.Cosignature { return slices.Clone(d.cosigs) }
