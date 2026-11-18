package facts

import (
	"errors"
	"io"
	"io/fs"
	"os"
)

// rootFS is the production Env.FS; openGuarded recognises it to open with O_NONBLOCK.
var rootFS = os.DirFS("/")

var errNotRegularOrDir = errors.New("facts: not a regular file or directory")

// openGuarded opens an absolute path from fsys for reading config-style data. The agent runs
// as root and some of the paths are chosen or writable by local users, so a FIFO or device
// planted there must never make open(2) block: the path is checked with Stat first, the
// production filesystem is opened with O_NONBLOCK|O_NOCTTY (a FIFO then opens at once), and
// the opened handle is checked again, which closes the check/open race. Only regular files
// (wantDir false) or directories (wantDir true) are returned.
func openGuarded(fsys fs.FS, abs string, wantDir bool) (fs.File, error) {
	rel := relPath(abs)
	var (
		f   fs.File
		err error
	)
	if nbOpen != nil && fsys == rootFS {
		f, err = nbOpen(abs)
	} else {
		var st fs.FileInfo
		if st, err = fs.Stat(fsys, rel); err != nil {
			return nil, err
		}
		if !kindOK(st, wantDir) {
			return nil, errNotRegularOrDir
		}
		f, err = fsys.Open(rel)
	}
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !kindOK(st, wantDir) {
		f.Close()
		return nil, errNotRegularOrDir
	}
	return f, nil
}

func kindOK(st fs.FileInfo, wantDir bool) bool {
	if wantDir {
		return st.IsDir()
	}
	return st.Mode().IsRegular()
}

// readFileGuarded reads a whole regular file through openGuarded.
func readFileGuarded(fsys fs.FS, abs string) ([]byte, error) {
	f, err := openGuarded(fsys, abs, false)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}
