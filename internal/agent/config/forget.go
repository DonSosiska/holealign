package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
)

// enrollTokenDir is the only directory whose agent.yaml may be rewritten by
// ForgetEnrollToken (a variable so tests can use a temporary directory).
var enrollTokenDir = "/etc/panoptes"

const maxConfigBytes = 1 << 20

// reEnrollToken matches the top-level enroll_token line (the key may be quoted); the
// capture keeps the key and colon.
var reEnrollToken = regexp.MustCompile(`(?m)^(["']?enroll_token["']?[ \t]*:)[^\r\n]*`)

// ForgetEnrollToken removes the enrollment token from the config file by atomically
// rewriting it with `enroll_token: ""`. Everything else (other keys, comments), the mode and
// the owner/group are preserved. It only touches a regular file (not a symlink) directly
// inside /etc/panoptes/, so a compromised caller cannot make the root collector rewrite an
// arbitrary file. A file without an enroll_token line is left alone.
func ForgetEnrollToken(path string) error {
	clean := filepath.Clean(path)
	dir := filepath.Dir(clean)
	if !filepath.IsAbs(clean) || dir != filepath.Clean(enrollTokenDir) {
		return fmt.Errorf("config: refusing to rewrite %s: not a file directly in %s", path, enrollTokenDir)
	}
	if real, err := filepath.EvalSymlinks(dir); err != nil || real != dir {
		return fmt.Errorf("config: %s is not a plain directory", dir)
	}
	fi, err := os.Lstat(clean)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("config: %s is not a regular file", clean)
	}
	f, err := os.Open(clean)
	if err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	f.Close()
	if err != nil {
		return err
	}
	if len(data) > maxConfigBytes {
		return errors.New("config: file too large")
	}
	out := reEnrollToken.ReplaceAll(data, []byte(`${1} ""`))
	if bytes.Equal(out, data) {
		return nil
	}

	tmp, err := os.CreateTemp(dir, ".agent.yaml.*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(out); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(fi.Mode().Perm()); err != nil {
		tmp.Close()
		return err
	}
	if err := matchOwner(tmp, fi); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, clean); err != nil {
		return err
	}
	ok = true
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}
