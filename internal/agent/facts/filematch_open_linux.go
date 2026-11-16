//go:build linux

package facts

import (
	"errors"
	"io/fs"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func safeOpen(physical string) (fs.File, error) { return openNoFollow(physical) }

// openNoFollow opens an absolute, already symlink-resolved path with
// O_NOFOLLOW semantics for every component. It prefers openat2 with
// RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH relative to an O_PATH fd of "/" and falls
// back to an openat component walk. The opened fd's /proc/self/fd link must
// still point at the expected path.
func openNoFollow(physical string) (*os.File, error) {
	if !strings.HasPrefix(physical, "/") {
		return nil, errors.New("facts: path not absolute")
	}
	root, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(root)
	rel := strings.TrimPrefix(physical, "/")

	fd, err := unix.Openat2(root, rel, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_NOCTTY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_BENEATH,
	})
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.E2BIG) {
		fd, err = walkOpen(root, rel)
	}
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), physical)
	if link, lerr := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd)); lerr == nil && link != physical {
		f.Close()
		return nil, errors.New("facts: opened file is not at the expected path")
	}
	return f, nil
}

func walkOpen(root int, rel string) (int, error) {
	comps := strings.Split(rel, "/")
	cur, err := unix.Openat(root, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for i, c := range comps {
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NOCTTY
		if i == len(comps)-1 {
			flags |= unix.O_NONBLOCK
		} else {
			flags |= unix.O_DIRECTORY
		}
		next, err := unix.Openat(cur, c, flags, 0)
		unix.Close(cur)
		if err != nil {
			return -1, err
		}
		cur = next
	}
	return cur, nil
}
