// This package defines a policy for relying parties to use when presented with a cosignature set.
//
// An RP uses it when syncing from the distributor.
package policy

import (
	"fmt"

	"mtcrt/merkle"
	"mtcrt/sig"
	"mtcrt/wire"
)

// Defines a policy.
type Policy struct {
	Required string                   // the public key of the required cosigner (the CA)
	Keys     map[string]sig.PublicKey // a set of every trusted cosigner key, includes Required.
	Min      int                      // number of signatures needed from Keys.
}

// Checks a cosignature set over a digest against the policy.
func (p Policy) Check(digest merkle.Hash, set []wire.Cosignature) error {
	valid := make(map[string]bool)
	for _, c := range set {
		key, trusted := p.Keys[c.CosignerID]

		if !trusted || valid[c.CosignerID] {
			continue
		}

		if key.Verify(digest, c.Signature) {
			valid[c.CosignerID] = true
		}
	}

	if !valid[p.Required] {
		return fmt.Errorf("policy: no valid signature from the required key %q", p.Required)
	}

	if len(valid) < p.Min {
		return fmt.Errorf("policy: %d valid signatures, need %d", len(valid), p.Min)
	}

	return nil
}
