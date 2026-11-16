package facts

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"strings"
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
	commandTimeout = 10 * time.Second
	maxCommandOut  = 4 << 20 // 4 MiB
	fixedPath      = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
)

var errOutputTooLarge = errors.New("facts: command output exceeds 4 MiB")

// execRunner is the production CommandRunner.
type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, resolveBinary(name), args...)
	cmd.Env = []string{"LC_ALL=C", "PATH=" + fixedPath}
	cmd.WaitDelay = time.Second

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

// resolveBinary looks the name up in a fixed set of directories so that a
// caller's PATH cannot redirect a hard-coded command. Unknown names are passed
// through and resolved by os/exec (which then reports exec.ErrNotFound).
func resolveBinary(name string) string {
	if strings.Contains(name, "/") {
		return name
	}
	for _, dir := range strings.Split(fixedPath, ":") {
		p := dir + "/" + name
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
			return p
		}
	}
	return name
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
	data, err := fs.ReadFile(env.FS, name)
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
