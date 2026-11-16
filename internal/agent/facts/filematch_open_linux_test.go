//go:build linux

package facts

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenNoFollow(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "f.conf")
	if err := os.WriteFile(file, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "l.conf")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	dirLink := filepath.Join(dir, "d")
	if err := os.Symlink(dir, dirLink); err != nil {
		t.Fatal(err)
	}

	f, err := openNoFollow(file)
	if err != nil {
		t.Fatalf("regular file: %v", err)
	}
	data, _ := io.ReadAll(f)
	f.Close()
	if string(data) != "hello" {
		t.Errorf("read %q", data)
	}
	if f, err := openNoFollow(link); err == nil {
		f.Close()
		t.Error("symlink as last component must be refused")
	}
	if f, err := openNoFollow(filepath.Join(dirLink, "f.conf")); err == nil {
		f.Close()
		t.Error("symlink as directory component must be refused")
	}
	if f, err := openNoFollow(filepath.Join(dir, "missing")); err == nil {
		f.Close()
		t.Error("missing file must fail")
	}

	// the component-walk fallback has the same semantics
	root, _ := os.Open("/")
	defer root.Close()
	fd, err := walkOpen(int(root.Fd()), file[1:])
	if err != nil {
		t.Fatalf("walkOpen: %v", err)
	}
	os.NewFile(uintptr(fd), "x").Close()
	if fd, err := walkOpen(int(root.Fd()), link[1:]); err == nil {
		os.NewFile(uintptr(fd), "x").Close()
		t.Error("walkOpen followed a symlink")
	}
}
