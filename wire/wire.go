// This package defines the messages exchanged between different parties.
package wire

import (
	"crypto/sha256"
	"fmt"
	"time"

	"mtcrt/merkle"
)

// IndexBits is how many low bits of a serial number hold the index.
// serial = (log number << 48) | index. As per the MTC specification.
const IndexBits = 48

// Creates a serial number from a log number and an index.
func Serial(logNumber, idx uint64) uint64 { return logNumber<<IndexBits | idx }

// Splits a serial number into a log number and an index.
func SplitSerial(serial uint64) (logNumber, idx uint64) {
	return serial >> IndexBits, serial & (1<<IndexBits - 1)
}

// Validates a log id. It must be 1 to 255 bytes as per the MTC specification.
func ValidateLogID(logID []byte) error {
	if len(logID) == 0 || len(logID) > 255 {
		return fmt.Errorf("wire: log_id must be 1 to 255 bytes, got %d", len(logID))
	}

	return nil
}

// EpochState is everything an epoch commits to, except the log id.
type EpochState struct {
	P         uint64
	TreeSize  uint64
	MinSerial uint64
	AnRoot    merkle.Hash
	BlockRoot merkle.Hash
	TPublish  time.Time
}

// Signed digest: h(log_id ‖ p ‖ tree_size ‖ minSerial ‖ A_n root ‖ block_root ‖ T_publish)
func (s EpochState) SignedDigest(logID []byte) merkle.Hash {
	var e encoder
	e.bytes8(logID)
	e.u64(s.P)
	e.u64(s.TreeSize)
	e.u64(s.MinSerial)
	e.hash(s.AnRoot)
	e.hash(s.BlockRoot)
	e.u64(uint64(s.TPublish.UnixMilli()))

	return sha256.Sum256(e.buf)
}

// Cosignature (from cosigners and CA cosigner)
type Cosignature struct {
	CosignerID string
	Signature  []byte
}

// Proposal is what the CA sends to each cosigner when an processing an epoch.
type Proposal struct {
	State       EpochState
	CASignature []byte
}

// Cosigner request for the data needed to check an epoch.
type ProposalRequest struct {
	P        uint64
	FromSize uint64
}

// Cosigner response with the events and prefix hashes to check.
type ProposalResponse struct {
	Events       []uint64
	PrefixHashes []merkle.Hash
}

// SyncRequest is a relying party asking for an update.
// If HasState is false, the party has no state and needs to sync from scratch.
// LastP is the last verified epoch the party has.
type SyncRequest struct {
	HasState bool
	LastP    uint64
}

// SyncKind contains the type of sync response.
type SyncKind uint8

const (
	SyncUnavailable SyncKind = iota // nothing cosigned yet
	SyncUpToDate                    // the party already has the latest epoch
	SyncUpdate                      // blocks changed since its epoch
	SyncFull                        // every block
)

// A block of crv_bits.
type Block struct {
	ID      uint64
	Content []byte
}

// SyncResponse is what the distributor sends a relying party.
type SyncResponse struct {
	Kind         SyncKind
	State        EpochState
	Blocks       []Block
	Cosignatures []Cosignature
}
