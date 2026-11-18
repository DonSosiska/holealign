//go:build !unix

package main

import (
	"os"

	"github.com/DonSosiska/holealign/internal/server/config"
)

// prepareCLI creates the data directory (there is no uid to drop to on this platform).
func prepareCLI(cfg *config.Config) error { return os.MkdirAll(cfg.DataDir, 0o750) }
