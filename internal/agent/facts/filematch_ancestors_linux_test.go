//go:build linux

package facts

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

// safeOpen must refuse a file below a directory without the "other" execute bit.
func TestSafeOpenRequiresTraversableAncestors(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// make the temporary tree itself traversable (MkdirTemp creates 0700 directories)
	for d := dir; d != "/tmp" && d != "/" && filepath.Dir(d) != d; d = filepath.Dir(d) {
		if err := os.Chmod(d, 0o755); err != nil {
			t.Skipf("cannot adjust %s: %v", d, err)
		}
	}
	open := filepath.Join(dir, "open")
	closed := filepath.Join(dir, "closed")
	for _, d := range []string{open, closed} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "f.conf"), []byte("hello"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(closed, 0o750); err != nil {
		t.Fatal(err)
	}

	f, err := safeOpen(filepath.Join(open, "f.conf"))
	if err != nil {
		t.Skipf("tree not traversable here (%v); ancestors outside the test's control", err)
	}
	data, _ := io.ReadAll(f)
	f.Close()
	if string(data) != "hello" {
		t.Errorf("read %q", data)
	}
	if f, err := safeOpen(filepath.Join(closed, "f.conf")); err == nil {
		f.Close()
		t.Error("file below a 0750 directory opened")
	}
}
