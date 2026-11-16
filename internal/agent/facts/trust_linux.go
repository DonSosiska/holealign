//go:build linux

package facts

import (
	"os"
	"syscall"
)

func ownerIDs(fi os.FileInfo) (uid, gid uint32, ok bool) {
	st, isStat := fi.Sys().(*syscall.Stat_t)
	if !isStat {
		return 0, 0, false
	}
	return st.Uid, st.Gid, true
}
