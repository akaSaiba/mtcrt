// This package runs MTC-RT in one process: one CA, its cosigners, and
// any number of relying parties.
//
// It simulates a network of cosigners, RPs, and a CA.
// It records the timings that the benchmarks report
package epoch

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"mtcrt/ca"
	"mtcrt/cosigner"
	"mtcrt/policy"
	"mtcrt/rp"
	"mtcrt/sig"
	"mtcrt/wire"
)

// CAID is the CA's cosigner id in this network.
const CAID = "ca"

// Config describes the configuration of the simulated network.
type Config struct {
	LogID     []byte
	LogNumber uint64
	BlockSize int

	Cosigners int
	Shadows   int // Shadow cosigners who sign without checking

	RecordDir     string
	Clock         func() time.Time // defaults to time.Now
	MaxClockDelta time.Duration    // defaults to 5s
}

// Network runs epochs and simulates RP syncs.
type Network struct {
	cfg Config

	CA        *ca.CA
	Cosigners []*cosigner.Cosigner

	shadows []ShadowCosigner
	keys    map[string]sig.PublicKey
}

// ShadowCosigner entity.
type ShadowCosigner struct {
	id  string
	key sig.PrivateKey
}

// Builds a network for a newly opened log.
func New(cfg Config) (*Network, error) {
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}

	if cfg.MaxClockDelta == 0 {
		cfg.MaxClockDelta = 5 * time.Second
	}

	if cfg.RecordDir == "" {
		return nil, errors.New("P: RecordDir is required for signing records")
	}

	if err := os.MkdirAll(cfg.RecordDir, 0o700); err != nil {
		return nil, err
	}

	n := &Network{cfg: cfg, keys: make(map[string]sig.PublicKey)}
	caKey, err := sig.GenerateKey()

	if err != nil {
		return nil, err
	}
	n.keys[CAID] = caKey.Public()

	additional := make(map[string]sig.PublicKey)
	var realKeys []sig.PrivateKey

	// Generate cosigner keys.
	for i := range cfg.Cosigners {
		key, err := sig.GenerateKey()
		if err != nil {
			return nil, err
		}

		id := fmt.Sprintf("cosigner-%d", i)
		additional[id] = key.Public()
		realKeys = append(realKeys, key)
	}

	// Generate shadow cosigner keys.
	for i := range cfg.Shadows {
		key, err := sig.GenerateKey()
		if err != nil {
			return nil, err
		}

		id := fmt.Sprintf("shadow-%d", i)
		additional[id] = key.Public()
		n.shadows = append(n.shadows, ShadowCosigner{id: id, key: key})
	}

	for id, key := range additional {
		n.keys[id] = key
	}

	// Create the CA.
	n.CA, err = ca.New(ca.Config{
		LogID:     cfg.LogID,
		LogNumber: cfg.LogNumber,
		BlockSize: cfg.BlockSize,
		ID:        CAID,
		Key:       caKey,
		Cosigners: additional,
		Quorum:    len(additional),
		Clock:     cfg.Clock,
	})

	if err != nil {
		return nil, err
	}

	for i, key := range realKeys {
		id := fmt.Sprintf("cosigner-%d", i)
		// Creates a cosigner.
		c, err := cosigner.New(cosigner.Config{
			ID:            id,
			LogID:         cfg.LogID,
			LogNumber:     cfg.LogNumber,
			BlockSize:     cfg.BlockSize,
			Key:           key,
			CAKey:         caKey.Public(),
			MaxClockDelta: cfg.MaxClockDelta,
			Clock:         cfg.Clock,
			RecordPath:    filepath.Join(cfg.RecordDir, id+".json"),
		})
		if err != nil {
			return nil, err
		}

		n.Cosigners = append(n.Cosigners, c)
	}

	return n, nil
}

// Returns the policy used by RPs.
func (n *Network) Policy() policy.Policy {
	return policy.Policy{Required: CAID, Keys: n.keys, Min: len(n.keys)}
}

// Returns the serial number of the certificate at index idx.
func (n *Network) Serial(idx uint64) uint64 { return wire.Serial(n.cfg.LogNumber, idx) }

// Issues count certificates.
func (n *Network) Issue(count uint64) { n.CA.Issue(count) }

// Publishes an issuance checkpoint and tells every cosigner its tree size.
func (n *Network) Checkpoint() {
	size := n.CA.Checkpoint()

	for _, c := range n.Cosigners {
		c.ObserveCheckpoint(size)
	}
}

// Submits a revocation for a serial number.
func (n *Network) Revoke(serial uint64) error { return n.CA.SubmitRevocation(serial) }

// EpochResult is how long each part of one epoch took.
type EpochResult struct {
	CATime        time.Duration   // time the CA spent building and signing the epoch
	CosignerTimes []time.Duration // check, sign and write time for cosigners
	ServeTimes    []time.Duration // time the CA spent answering each cosigner
	AddTimes      []time.Duration // time spent checking and storing each extra signature
	PublishTime   time.Duration   // time spent publishing the epoch
	ProposalBytes []int           // size of the proposal in bytes
}

// Advances one epoch.
func (n *Network) RunEpoch() (EpochResult, error) {
	var res EpochResult

	// t_advance: the CA builds and signs the epoch.
	start := time.Now()
	ann, err := n.CA.ProcessEpoch()
	res.CATime = time.Since(start)
	if err != nil {
		return res, err
	}

	p := ann.State.P

	for _, c := range n.Cosigners {
		var serveTime time.Duration
		var proposal wire.ProposalResponse
		fetch := func(req wire.ProposalRequest) (wire.ProposalResponse, error) {
			// t_serve_proposal: the CA answering one cosigner.
			t0 := time.Now()
			resp, err := n.CA.ServeProposal(req)
			serveTime = time.Since(t0)
			proposal = resp

			return resp, err
		}

		// t_cosigner: ReceiveProposal, minus the time spent in the CA.
		t0 := time.Now()
		cs, err := c.ReceiveProposal(ann, fetch)
		total := time.Since(t0)
		if err != nil {
			return res, fmt.Errorf("%s: %w", c.ID(), err)
		}

		res.CosignerTimes = append(res.CosignerTimes, total-serveTime)
		res.ServeTimes = append(res.ServeTimes, serveTime)
		res.ProposalBytes = append(res.ProposalBytes, len(proposal.Marshal()))

		if err := n.CA.AddCosignature(p, cs); err != nil {
			return res, fmt.Errorf("%s: %w", c.ID(), err)
		}

		timings := n.CA.LastCosignatureTimings()
		res.AddTimes = append(res.AddTimes, timings.Add)
		res.PublishTime += timings.Publish
	}

	digest := ann.State.SignedDigest(n.cfg.LogID)
	for _, s := range n.shadows {
		cs := wire.Cosignature{CosignerID: s.id, Signature: s.key.Sign(digest)}
		if err := n.CA.AddCosignature(p, cs); err != nil {
			return res, fmt.Errorf("%s: %w", s.id, err)
		}

		timings := n.CA.LastCosignatureTimings()
		res.AddTimes = append(res.AddTimes, timings.Add)
		res.PublishTime += timings.Publish
	}

	return res, nil
}

// Creates a relying party for this log.
func (n *Network) NewRP() (*rp.RP, error) {
	return rp.New(rp.Config{
		LogID:     n.cfg.LogID,
		LogNumber: n.cfg.LogNumber,
		BlockSize: n.cfg.BlockSize,
		Policy:    n.Policy(),
	})
}
