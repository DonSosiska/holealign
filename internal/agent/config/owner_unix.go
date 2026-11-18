//go:build unix

package config

import (
	"os"
	"syscall"
)

// matchOwner gives f the owner and group of ref. Nothing is changed when they already match,
// so an unprivileged or seccomp-restricted caller (chown denied) still succeeds when the new
// file is already owned correctly (the root collector runs with Group=holealign).
func matchOwner(f *os.File, ref os.FileInfo) error {
	want, ok := ref.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	same := func() bool {
		cur, err := f.Stat()
		if err != nil {
			return false
		}
		st, ok := cur.Sys().(*syscall.Stat_t)
		return ok && st.Uid == want.Uid && st.Gid == want.Gid
	}
	if same() {
		return nil
	}
	if err := f.Chown(int(want.Uid), int(want.Gid)); err != nil && !same() {
		return err
	}
	return nil
}
