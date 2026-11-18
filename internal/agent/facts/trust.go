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

// binaryTrust requires an already symlink-resolved binary and EVERY ancestor directory up to
// "/" to be trusted (root-owned, not group/world-writable): a writable grandparent lets a
// local user rename the trusted directory away and plant their own.
func binaryTrust(resolved string) error {
	return binaryTrustAbove(resolved, "/")
}

// binaryTrustAbove is binaryTrust with the ancestor walk ending at (and including) top.
func binaryTrustAbove(resolved, top string) error {
	if err := pathTrust(resolved); err != nil {
		return err
	}
	for d := filepath.Dir(resolved); ; d = filepath.Dir(d) {
		if err := pathTrust(d); err != nil {
			return err
		}
		if d == top || d == filepath.Dir(d) {
			return nil
		}
	}
}

// symlinkTargetTrust checks a symlink target and its ancestors (replaced in tests, whose
// temporary directories are not under root-owned parents).
var symlinkTargetTrust = binaryTrust

// treeTrusted checks every root (globs allowed; missing roots are skipped), its
// parent directory and everything below it (at most maxTrustEntries entries in total;
// more fails closed). A symbolic link is checked at its target (and the target's
// ancestors); when the target is a directory its whole tree is walked with the same
// checks, so a symlinked conf.d cannot smuggle in files the agent never looked at.
// Directories are walked once (os.SameFile), which also ends symlink loops.
func treeTrusted(roots []string) error {
	w := &trustWalker{}
	for _, pat := range roots {
		matches, _ := filepath.Glob(pat)
		for _, root := range matches {
			if err := pathTrust(filepath.Dir(root)); err != nil {
				return err
			}
			if err := w.walk(root, root); err != nil {
				return err
			}
		}
	}
	return nil
}

// trustWalker carries the entry budget and the visited directories across all roots.
type trustWalker struct {
	count   int
	visited []os.FileInfo // directories already walked
}

func (w *trustWalker) has(fi os.FileInfo) bool {
	for _, v := range w.visited {
		if os.SameFile(v, fi) {
			return true
		}
	}
	return false
}

// seen records fi and reports whether the same directory was walked before.
func (w *trustWalker) seen(fi os.FileInfo) bool {
	if w.has(fi) {
		return true
	}
	w.visited = append(w.visited, fi)
	return false
}

// walk verifies the tree at top; label names the configured root in messages.
func (w *trustWalker) walk(top, label string) error {
	return filepath.WalkDir(top, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if w.count++; w.count > maxTrustEntries {
			return fmt.Errorf("%s: more than %d entries, not verified", label, maxTrustEntries)
		}
		if d.Type()&fs.ModeSymlink != 0 {
			target, err := filepath.EvalSymlinks(p)
			if err != nil {
				return nil // dangling: nothing is loaded from it
			}
			if err := symlinkTargetTrust(target); err != nil {
				return err
			}
			fi, err := os.Stat(target)
			if err != nil {
				return err
			}
			if !fi.IsDir() {
				return nil
			}
			if w.has(fi) {
				return nil // already verified, or being verified (a loop)
			}
			return w.walk(target, label)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() && w.seen(info) {
			return fs.SkipDir
		}
		return fileTrust(p, info)
	})
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
