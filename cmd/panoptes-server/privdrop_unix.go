//go:build unix

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"panoptes/internal/server/config"
)

// prepareCLI runs before a token/host/user subcommand opens the database. When started as root
// while the data directory (or DB) belongs to another user - normally the service account - it
// drops to that uid/gid first, so the database, its -wal/-shm files and a missing data directory
// are never created root-owned (which would lock the service out of its own database).
func prepareCLI(cfg *config.Config) error {
	if os.Geteuid() == 0 {
		uid, gid, err := cliOwner(cfg.DataDir, cfg.DBPath())
		if err != nil {
			return err
		}
		if uid != 0 {
			if err := dropTo(uid, gid); err != nil {
				return fmt.Errorf("running as root, but %s is owned by uid %d: could not drop privileges (%v); run this command as that user instead, e.g. 'sudo -u <service-user> panoptes-server ...'",
					cfg.DataDir, uid, err)
			}
		}
	}
	return os.MkdirAll(cfg.DataDir, 0o750)
}

// cliOwner returns the uid/gid that should run the CLI: the owner of the data directory (or of
// its nearest existing parent when it does not exist yet), else of the database file. The first
// non-root owner wins; 0 means everything is root-owned and root may proceed.
func cliOwner(dataDir, dbPath string) (uid, gid int, err error) {
	dir := dataDir
	for {
		if _, serr := os.Stat(dir); serr == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return 0, 0, nil
		}
		dir = parent
	}
	for _, p := range []string{dir, dbPath} {
		fi, serr := os.Stat(p)
		if serr != nil {
			continue
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid != 0 {
			return int(st.Uid), int(st.Gid), nil
		}
	}
	return 0, 0, nil
}

func dropTo(uid, gid int) error {
	if err := syscall.Setgroups([]int{gid}); err != nil {
		return err
	}
	if err := syscall.Setgid(gid); err != nil {
		return err
	}
	if err := syscall.Setuid(uid); err != nil {
		return err
	}
	if os.Geteuid() != uid || os.Getuid() != uid {
		return fmt.Errorf("uid is still %d", os.Geteuid())
	}
	return nil
}
