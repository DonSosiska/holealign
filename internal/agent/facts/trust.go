package facts

import (
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// maxTrustEntries bounds the number of entries inspected per tree check.
const maxTrustEntries = 2000

// ownerIDs (per platform) returns the owning uid/gid of a file; ok is false
// where ownership is unavailable (checks are then mode-only, for tests).

// fileTrust reports whether a file or directory may be trusted by the
// root-running agent: owned by uid 0 and not group- or world-writable.
func fileTrust(p string, fi os.FileInfo) error {
	uid, gid, ok := ownerIDs(fi)
	if ok && uid != 0 {
		return fmt.Errorf("%s owned by uid %d", p, uid)
	}
	perm := fi.Mode().Perm()
	if perm&0o020 != 0 {
		if ok {
			return fmt.Errorf("%s writable by gid %d", p, gid)
		}
		return fmt.Errorf("%s writable by group", p)
	}
	if perm&0o002 != 0 {
		return fmt.Errorf("%s writable by others", p)
	}
	return nil
}

// pathTrust applies fileTrust to what p points to (symlinks followed).
func pathTrust(p string) error {
	fi, err := os.Stat(p)
	if err != nil {
		return err
	}
	return fileTrust(p, fi)
}

// binaryTrust requires an already symlink-resolved binary and its directory to be trusted.
func binaryTrust(resolved string) error {
	if err := pathTrust(resolved); err != nil {
		return err
	}
	return pathTrust(filepath.Dir(resolved))
}

// treeTrusted checks every root (globs allowed; missing roots are skipped), its
// parent directory and everything below it (at most maxTrustEntries entries;
// more fails closed). Symbolic links are checked at their target.
func treeTrusted(roots []string) error {
	count := 0
	for _, pat := range roots {
		matches, _ := filepath.Glob(pat)
		for _, root := range matches {
			if err := pathTrust(filepath.Dir(root)); err != nil {
				return err
			}
			err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if count++; count > maxTrustEntries {
					return fmt.Errorf("%s: more than %d entries, not verified", root, maxTrustEntries)
				}
				if d.Type()&fs.ModeSymlink != 0 {
					target, err := filepath.EvalSymlinks(p)
					if err != nil {
						return nil // dangling: nothing is loaded from it
					}
					return binaryTrust(target)
				}
				info, err := d.Info()
				if err != nil {
					return err
				}
				return fileTrust(p, info)
			})
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// treeOK verifies the config trees of a tool before the agent executes it as
// root; on failure the reason is recorded in the agent.skipped fact.
func (env *Env) treeOK(label string, roots ...string) bool {
	if env.TreeTrust == nil {
		return true
	}
	if err := env.TreeTrust(roots); err != nil {
		env.skip(label + ": " + err.Error())
		return false
	}
	return true
}

type skipLog struct {
	mu   sync.Mutex
	list []string
}

func (env *Env) skip(msg string) {
	log.Printf("facts: skipping %s", msg)
	env.skips.mu.Lock()
	defer env.skips.mu.Unlock()
	env.skips.list = append(env.skips.list, msg)
}

func (env *Env) skipped() []string {
	env.skips.mu.Lock()
	defer env.skips.mu.Unlock()
	out := append([]string(nil), env.skips.list...)
	sort.Strings(out)
	return out
}
