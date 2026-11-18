//go:build unix

package facts

import (
	"io/fs"
	"os"
	"syscall"
)

// nbOpen opens abs read-only without ever blocking on a FIFO (symlinks are followed; the
// caller checks the kind of the opened handle).
var nbOpen = func(abs string) (fs.File, error) {
	var fd int
	var err error
	for {
		fd, err = syscall.Open(abs, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
		if err != syscall.EINTR {
			break
		}
	}
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: abs, Err: err}
	}
	return os.NewFile(uintptr(fd), abs), nil
}
