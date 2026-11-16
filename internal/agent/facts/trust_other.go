//go:build !linux

package facts

import "os"

// ownerIDs is unavailable off Linux; trust checks are then mode-only (the agent
// collects no facts on other platforms; this only keeps tests runnable).
func ownerIDs(os.FileInfo) (uid, gid uint32, ok bool) { return 0, 0, false }
