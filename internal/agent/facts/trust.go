package facts

import (
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
	if resolved == top || resolved == filepath.Dir(resolved) {
		return nil
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

func globHasMeta(pat string) bool {
	return strings.ContainsAny(pat, "*?[\\")
}

// staticPrefix returns the longest directory/file prefix of pat that contains no glob metacharacters.
func staticPrefix(pat string) string {
	vol := filepath.VolumeName(pat)
	rest := pat[len(vol):]
	sep := string(filepath.Separator)
	abs := strings.HasPrefix(rest, sep)
	if abs {
		rest = rest[len(sep):]
	}
	var kept []string
	for _, seg := range strings.Split(rest, sep) {
		if seg == "" {
			continue
		}
		if globHasMeta(seg) {
			break
		}
		kept = append(kept, seg)
	}
	joined := strings.Join(kept, sep)
	if abs {
		return filepath.Clean(vol + sep + joined)
	}
	if joined == "" {
		return vol + "."
	}
	return filepath.Clean(vol + joined)
}

func nearestExisting(p string) (string, bool) {
	for cur := filepath.Clean(p); ; cur = filepath.Dir(cur) {
		if _, err := os.Lstat(cur); err == nil {
			return cur, true
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", false
		}
	}
}

func checkPrefixTrust(pat string, strict bool) error {
	pref := staticPrefix(pat)
	if target, err := filepath.EvalSymlinks(pref); err == nil {
		return symlinkTargetTrust(target)
	}
	if _, err := os.Lstat(pref); err == nil {
		// Dangling symlink at pref: check its parent directory, and in strict mode its target's nearest ancestor.
		if err := symlinkTargetTrust(filepath.Dir(pref)); err != nil {
			return err
		}
		if !strict {
			return nil
		}
		if link, rerr := os.Readlink(pref); rerr == nil {
			if !filepath.IsAbs(link) {
				link = filepath.Join(filepath.Dir(pref), link)
			}
			if anc, ok := nearestExisting(link); ok {
				if resolved, eerr := filepath.EvalSymlinks(anc); eerr == nil {
					return symlinkTargetTrust(resolved)
				}
				return symlinkTargetTrust(anc)
			}
		}
		return nil
	}
	if !strict {
		return nil
	}
	if anc, ok := nearestExisting(pref); ok {
		if resolved, eerr := filepath.EvalSymlinks(anc); eerr == nil {
			return symlinkTargetTrust(resolved)
		}
		return symlinkTargetTrust(anc)
	}
	return nil
}

// treeTrusted checks every root (globs allowed; missing default candidate roots are skipped), all
// of its ancestor directories up to "/" and everything below it (at most maxTrustEntries entries in
// total; more fails closed). When a glob pattern matches nothing (e.g. an empty directory), its
// static prefix (if existing) and ancestors are still checked. A symbolic link is checked at its
// target (and the target's ancestors); when the target is a directory its whole tree is walked with
// the same checks, so a symlinked conf.d cannot smuggle in files the agent never looked at.
// Directories are walked once (os.SameFile), which also ends symlink loops.
func treeTrusted(roots []string) error {
	return treeTrustedMode(roots, false)
}

// treeTrustedStrict is like treeTrusted, but for explicitly referenced include/config paths it also
// walks up to the nearest existing ancestor when the target path or glob prefix does not yet exist.
func treeTrustedStrict(roots []string) error {
	return treeTrustedMode(roots, true)
}

func treeTrustedMode(roots []string, strict bool) error {
	w := &trustWalker{}
	for _, pat := range roots {
		if _, err := filepath.Match(pat, ""); err != nil {
			return fmt.Errorf("%s: invalid glob: %w", pat, err)
		}
		hasMeta := globHasMeta(pat)
		if hasMeta {
			if err := checkPrefixTrust(pat, strict); err != nil {
				return err
			}
		}
		matches, err := filepath.Glob(pat)
		if err != nil {
			return fmt.Errorf("%s: invalid glob: %w", pat, err)
		}
		if len(matches) == 0 && !hasMeta && strict {
			if err := checkPrefixTrust(pat, true); err != nil {
				return err
			}
		}
		for _, root := range matches {
			parent := filepath.Dir(root)
			if resolved, err := filepath.EvalSymlinks(parent); err == nil {
				parent = resolved
			}
			if err := symlinkTargetTrust(parent); err != nil {
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
	return env.checkTree(env.TreeTrust, label, roots...)
}

// treeOKStrict verifies explicitly referenced include/config locations, checking
// empty glob prefixes and nonexistent targets' nearest existing ancestors.
func (env *Env) treeOKStrict(label string, roots ...string) bool {
	fn := env.TreeTrustStrict
	if fn == nil {
		fn = env.TreeTrust
	}
	return env.checkTree(fn, label, roots...)
}

func (env *Env) checkTree(fn func(roots []string) error, label string, roots ...string) bool {
	if fn == nil {
		return true
	}
	if err := fn(roots); err != nil {
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
