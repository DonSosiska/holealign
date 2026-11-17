//go:build unix

package collector

import (
	"os"
	"syscall"
)

// fileGID returns the group id owning a file; ok is false when it cannot be determined.
func fileGID(fi os.FileInfo) (gid int, ok bool) {
	st, isStat := fi.Sys().(*syscall.Stat_t)
	if !isStat {
		return 0, false
	}
	return int(st.Gid), true
}
