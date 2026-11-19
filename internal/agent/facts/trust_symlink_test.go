//go:build unix

package facts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// symlinkFixture builds base/{good,bad}/ (bad holds a 0666 file) and returns the paths. The
// symlink target ancestor check is relaxed to the target itself for the test's duration.
func symlinkFixture(t *testing.T) (base, good, bad string) {
	t.Helper()
	old := symlinkTargetTrust
	symlinkTargetTrust = pathTrust
	t.Cleanup(func() { symlinkTargetTrust = old })

	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	good, bad = filepath.Join(base, "good"), filepath.Join(base, "bad")
	for _, d := range []string{good, bad} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
		os.Chmod(d, 0o755)
	}
	for p, mode := range map[string]os.FileMode{
		filepath.Join(good, "ok.conf"):  0o644,
		filepath.Join(bad, "evil.conf"): 0o666,
	} {
		if err := os.WriteFile(p, []byte("x"), mode); err != nil {
			t.Fatal(err)
		}
		os.Chmod(p, mode)
	}
	return base, good, bad
}

func mustRejectEvil(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("tree reaching a world-writable file through a symlink must be rejected")
	}
	// Non-root runners (Linux) fail earlier on the owner; as root the file is the reason.
	if ownerIsRoot() && !strings.Contains(err.Error(), "evil.conf") {
		t.Errorf("wrong reason: %v", err)
	}
}

func TestTreeTrustedSymlinkedSubdirIsWalked(t *testing.T) {
	base, _, bad := symlinkFixture(t)
	root := filepath.Join(base, "nginx")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	os.Chmod(root, 0o755)
	if err := os.Symlink(bad, filepath.Join(root, "conf.d")); err != nil {
		t.Fatal(err)
	}
	mustRejectEvil(t, treeTrusted([]string{root}))
}

func TestTreeTrustedSymlinkedRootIsWalked(t *testing.T) {
	base, _, bad := symlinkFixture(t)
	link := filepath.Join(base, "nginx")
	if err := os.Symlink(bad, link); err != nil {
		t.Fatal(err)
	}
	mustRejectEvil(t, treeTrusted([]string{link}))
}

func TestTreeTrustedLegitSymlinkedDirAndLoops(t *testing.T) {
	if !ownerIsRoot() && ownerIDsAvailable() {
		t.Skip("needs root-owned files")
	}
	base, good, _ := symlinkFixture(t)
	root := filepath.Join(base, "nginx")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	os.Chmod(root, 0o755)
	if err := os.Symlink(good, filepath.Join(root, "conf.d")); err != nil {
		t.Fatal(err)
	}
	// a second link to the same directory and a link back to the root (loop)
	if err := os.Symlink(good, filepath.Join(root, "again")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(root, filepath.Join(good, "loop")); err != nil {
		t.Fatal(err)
	}
	if err := treeTrusted([]string{root}); err != nil {
		t.Errorf("root-owned symlinked directory rejected: %v", err)
	}
}

func TestTreeTrustedSymlinkEntriesShareTheCap(t *testing.T) {
	base, good, _ := symlinkFixture(t)
	root := filepath.Join(base, "nginx")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxTrustEntries+5; i++ {
		if err := os.WriteFile(filepath.Join(good, "f"+strings.Repeat("x", 1)+string(rune('a'+i%26))+itoa(i)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(good, filepath.Join(root, "conf.d")); err != nil {
		t.Fatal(err)
	}
	if err := treeTrusted([]string{root}); err == nil {
		t.Error("oversized symlinked tree must fail closed")
	}
}

func TestTreeTrustedRejectsUntrustedGrandparent(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	old := symlinkTargetTrust
	symlinkTargetTrust = func(p string) error { return binaryTrustAbove(p, base) }
	t.Cleanup(func() { symlinkTargetTrust = old })

	// base/grandparent (0777, untrusted) -> parent (0755) -> conf (0755) -> site.conf (0644)
	gp := filepath.Join(base, "grandparent")
	parent := filepath.Join(gp, "parent")
	root := filepath.Join(parent, "conf")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "site.conf"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(gp, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := treeTrusted([]string{root}); err == nil {
		t.Fatal("tree under a world-writable grandparent must be rejected")
	}
}

func TestTreeTrustedRejectsEmptyGlobDirOwnedOrWritable(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	old := symlinkTargetTrust
	symlinkTargetTrust = func(p string) error { return binaryTrustAbove(p, base) }
	t.Cleanup(func() { symlinkTargetTrust = old })

	emptyDir := filepath.Join(base, "conf.d")
	if err := os.MkdirAll(emptyDir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(emptyDir, 0o777); err != nil {
		t.Fatal(err)
	}
	pat := filepath.Join(emptyDir, "*.conf")
	if err := treeTrusted([]string{pat}); err == nil {
		t.Fatal("treeTrusted accepted empty world-writable glob directory")
	}
	if err := treeTrustedStrict([]string{pat}); err == nil {
		t.Fatal("treeTrustedStrict accepted empty world-writable glob directory")
	}
}

func TestTreeTrustedStrictRejectsNonexistentIncludeUnderWritableParent(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	old := symlinkTargetTrust
	symlinkTargetTrust = func(p string) error { return binaryTrustAbove(p, base) }
	t.Cleanup(func() { symlinkTargetTrust = old })

	writableParent := filepath.Join(base, "user-home")
	if err := os.MkdirAll(writableParent, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writableParent, 0o777); err != nil {
		t.Fatal(err)
	}
	pat := filepath.Join(writableParent, "not-yet-created", "*.conf")
	if err := treeTrustedStrict([]string{pat}); err == nil {
		t.Fatal("treeTrustedStrict accepted nonexistent include under world-writable ancestor")
	}
	// Non-glob nonexistent include path under a writable parent is also rejected in strict mode.
	filePat := filepath.Join(writableParent, "future.conf")
	if err := treeTrustedStrict([]string{filePat}); err == nil {
		t.Fatal("treeTrustedStrict accepted nonexistent literal include under world-writable ancestor")
	}
}

func TestTreeTrustedRejectsBadGlob(t *testing.T) {
	if err := treeTrusted([]string{"/etc/["}); err == nil {
		t.Fatal("malformed glob pattern accepted")
	}
	if err := treeTrustedStrict([]string{"/etc/["}); err == nil {
		t.Fatal("malformed glob pattern accepted by strict check")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}

// ownerIDsAvailable reports whether trust checks look at owners on this platform.
func ownerIDsAvailable() bool {
	fi, err := os.Stat("/")
	if err != nil {
		return false
	}
	_, _, ok := ownerIDs(fi)
	return ok
}
