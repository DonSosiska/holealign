package facts

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// CommandRunner executes a hard-coded command with a fixed argv (never a shell).
//
// Run returns the combined stdout and stderr (several tools, e.g. nginx -V and
// sshd -V, print to stderr). Output may be non-empty together with a non-nil
// error (non-zero exit status); collectors decide per command whether that
// output is usable. A missing binary is reported as an error wrapping
// exec.ErrNotFound.
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

const (
	maxCommandOut = 4 << 20 // 4 MiB
	fixedPath     = "/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin"
)

// commandTimeout bounds one external command (a variable so tests can shorten it).
var commandTimeout = 10 * time.Second

var errOutputTooLarge = errors.New("facts: command output exceeds 4 MiB")

// execRunner is the production CommandRunner.
type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()

	bin := resolveBinary(name)
	if bin == "" {
		return nil, fmt.Errorf("%w: %s", exec.ErrNotFound, name)
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = []string{"LC_ALL=C", "PATH=" + fixedPath}
	cmd.WaitDelay = time.Second
	// Own process group; on timeout the whole group is killed, so forked helpers (nginx -T
	// workers, php-fpm children, ...) cannot outlive the request.
	setProcessGroup(cmd)

	w := &capWriter{max: maxCommandOut}
	// Same writer for both streams: os/exec serialises writes to a shared writer.
	cmd.Stdout = w
	cmd.Stderr = w

	err := cmd.Run()
	if w.over {
		return w.buf.Bytes(), errOutputTooLarge
	}
	return w.buf.Bytes(), err
}

// resolveBinary looks the name up in a fixed set of directories (system
// directories before /usr/local) so that a caller's PATH cannot redirect a
// hard-coded command. A candidate is only used when, after symlink resolution,
// the file and its directory are root-owned and not group/world-writable;
// others are skipped (logged once). When nothing qualifies it returns "" (the caller reports exec.ErrNotFound);
// the agent's own PATH is never consulted.
func resolveBinary(name string) string {
	if strings.Contains(name, "/") {
		return name
	}
	return resolveBinaryIn(name, strings.Split(fixedPath, ":"), binaryTrust, warnSkippedOnce)
}

var skippedBinaries sync.Map

func warnSkippedOnce(path string, err error) {
	if _, dup := skippedBinaries.LoadOrStore(path, true); !dup {
		log.Printf("facts: not executing %s: %v", path, err)
	}
}

func resolveBinaryIn(name string, dirs []string, trust func(resolved string) error, warn func(path string, err error)) string {
	for _, dir := range dirs {
		p := dir + "/" + name
		resolved, err := filepath.EvalSymlinks(p)
		if err != nil {
			continue
		}
		fi, err := os.Stat(resolved)
		if err != nil || !fi.Mode().IsRegular() || fi.Mode()&0o111 == 0 {
			continue
		}
		if err := trust(resolved); err != nil {
			warn(p, err)
			continue
		}
		return resolved
	}
	return ""
}

// capWriter keeps at most max bytes and silently discards the rest, so the
// child process never blocks on a full pipe.
type capWriter struct {
	buf  bytes.Buffer
	max  int
	over bool
}

func (w *capWriter) Write(p []byte) (int, error) {
	room := w.max - w.buf.Len()
	switch {
	case room <= 0:
		w.over = true
	case len(p) <= room:
		w.buf.Write(p)
	default:
		w.buf.Write(p[:room])
		w.over = true
	}
	return len(p), nil
}

// isMissing reports whether a command could not be started because the binary
// does not exist.
func isMissing(err error) bool {
	return errors.Is(err, exec.ErrNotFound)
}

// run executes a command through the environment's runner.
func (env *Env) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if env.Runner == nil {
		return nil, exec.ErrNotFound
	}
	return env.Runner.Run(ctx, name, args...)
}

// readFile reads a file from the environment's root filesystem. name is
// relative to "/" (e.g. "etc/os-release").
func (env *Env) readFile(name string) ([]byte, error) {
	if env.FS == nil {
		return nil, fs.ErrNotExist
	}
	data, err := readFileGuarded(env.FS, "/"+name)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// readFirstFile returns the content of the first readable file in names.
func (env *Env) readFirstFile(names ...string) ([]byte, error) {
	var lastErr error = fs.ErrNotExist
	for _, n := range names {
		data, err := env.readFile(n)
		if err == nil {
			return data, nil
		}
		lastErr = err
	}
	return nil, lastErr
}
