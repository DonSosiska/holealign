// Package facts collects host facts (see docs/contracts.md §3).
package facts

import (
	"context"

	"panoptes/internal/model"
)

// Collect runs all built-in collectors plus the parametrised requests and returns
// the merged fact map. It never returns an error: failing collectors simply omit
// their facts (absent = unknown). Safe to call concurrently.
//
// STUB from wave 0 — the real implementation replaces this body; the signature is a contract.
func Collect(ctx context.Context, reqs []model.FactRequest) model.Facts {
	return model.Facts{}
}
