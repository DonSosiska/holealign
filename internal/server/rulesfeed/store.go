package rulesfeed

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"time"
)

// Dir is the directory below data_dir that holds the accepted bundle.
const Dir = "rules-feed"

const stateFile = "state.json"

var persistedRe = regexp.MustCompile(`^rules-([0-9]{1,18})\.tar\.gz$`)

// State is the small status record kept next to the bundle (state.json) so the CLI can report it
// without opening the database. The same values are mirrored into the kv table for the web UI.
type State struct {
	Seq       uint64 `json:"seq"`
	UpdatedAt string `json:"updated_at,omitempty"` // RFC 3339, last time a bundle was installed
	CheckedAt string `json:"checked_at,omitempty"` // last successful poll
	LastError string `json:"last_error,omitempty"`
	Failures  int    `json:"failures"` // consecutive failed polls
}

// Installed is a verified, persisted bundle.
type Installed struct {
	Bundle  *Bundle
	Sig     Sig
	Tarball []byte
}

// persistedSeqs lists the sequence numbers of rules-<seq>.tar.gz files in dir, highest first.
func persistedSeqs(dir string) []uint64 {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []uint64
	for _, e := range ents {
		if m := persistedRe.FindStringSubmatch(e.Name()); m != nil && !e.IsDir() {
			if n, err := strconv.ParseUint(m[1], 10, 64); err == nil && n > 0 {
				out = append(out, n)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] > out[j] })
	return out
}

// LoadInstalled re-verifies (signature, hashes, rules, tests) the persisted bundles from the
// highest sequence down and returns the first that is fully valid. Problems with skipped bundles
// are returned in skipped. A nil result means nothing usable is installed.
func LoadInstalled(dir string, keys []ed25519.PublicKey, serverVersion string) (inst *Installed, skipped []error) {
	for _, seq := range persistedSeqs(dir) {
		in, err := loadOne(dir, seq, keys, serverVersion)
		if err != nil {
			skipped = append(skipped, fmt.Errorf("%s: %w", TarballName(seq), err))
			continue
		}
		return in, skipped
	}
	return nil, skipped
}

func loadOne(dir string, seq uint64, keys []ed25519.PublicKey, serverVersion string) (*Installed, error) {
	tb, err := readLimited(filepath.Join(dir, TarballName(seq)), MaxBundleBytes)
	if err != nil {
		return nil, err
	}
	sb, err := readLimited(filepath.Join(dir, TarballName(seq)+".sig"), MaxPointerBytes)
	if err != nil {
		return nil, err
	}
	var sig Sig
	if err := json.Unmarshal(sb, &sig); err != nil {
		return nil, fmt.Errorf("signature file: %w", err)
	}
	if err := VerifySig(tb, sig, keys); err != nil {
		return nil, err
	}
	b, err := Open(tb, serverVersion)
	if err != nil {
		return nil, err
	}
	if b.Index.Seq != seq {
		return nil, fmt.Errorf("index.json says seq %d", b.Index.Seq)
	}
	return &Installed{Bundle: b, Sig: sig, Tarball: tb}, nil
}

func readLimited(path string, max int64) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Size() > max {
		return nil, fmt.Errorf("%s is larger than %d bytes", filepath.Base(path), max)
	}
	return os.ReadFile(path)
}

// persist writes the bundle and its signature atomically (temp file + rename) and removes older
// bundles. The directory is created with mode 0750.
func persist(dir string, seq uint64, tarball []byte, sig Sig) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	sb, err := MarshalJSONFile(sig)
	if err != nil {
		return err
	}
	// signature first: a bundle without a signature is ignored at load, never trusted
	if err := writeAtomic(filepath.Join(dir, TarballName(seq)+".sig"), sb); err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(dir, TarballName(seq)), tarball); err != nil {
		return err
	}
	for _, old := range persistedSeqs(dir) {
		if old < seq {
			_ = os.Remove(filepath.Join(dir, TarballName(old)))
			_ = os.Remove(filepath.Join(dir, TarballName(old)+".sig"))
		}
	}
	return nil
}

func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, werr := tmp.Write(data)
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Chmod(name, 0o640)
	}
	if werr == nil {
		werr = os.Rename(name, path)
	}
	if werr != nil {
		_ = os.Remove(name)
	}
	return werr
}

// ReadState reads state.json (a zero State when absent).
func ReadState(dir string) State {
	var s State
	if b, err := readLimited(filepath.Join(dir, stateFile), MaxPointerBytes); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	return s
}

func writeState(dir string, s State) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	b, err := MarshalJSONFile(s)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, stateFile), b)
}

// Import verifies a tarball and its signature against the trusted keys, applies the anti-rollback
// rule (the sequence must be higher than the installed one) and installs it into dir. It is used
// by `rules import` for air-gapped servers; a running server picks the bundle up within a minute.
func Import(dir string, keys []ed25519.PublicKey, serverVersion string, tarball []byte, sig Sig, now time.Time) (*Bundle, error) {
	if len(tarball) > MaxBundleBytes {
		return nil, fmt.Errorf("bundle is larger than %d bytes", MaxBundleBytes)
	}
	if err := VerifySig(tarball, sig, keys); err != nil {
		return nil, err
	}
	b, err := Open(tarball, serverVersion)
	if err != nil {
		return nil, err
	}
	if cur, _ := LoadInstalled(dir, keys, serverVersion); cur != nil && b.Index.Seq <= cur.Bundle.Index.Seq {
		if b.Index.Seq == cur.Bundle.Index.Seq {
			return nil, fmt.Errorf("bundle %d is already installed", b.Index.Seq)
		}
		return nil, fmt.Errorf("rollback refused: bundle %d is older than the installed bundle %d", b.Index.Seq, cur.Bundle.Index.Seq)
	}
	if err := persist(dir, b.Index.Seq, tarball, sig); err != nil {
		return nil, fmt.Errorf("install: %w", err)
	}
	st := ReadState(dir)
	st.Seq, st.UpdatedAt, st.LastError = b.Index.Seq, now.UTC().Format(time.RFC3339), ""
	if err := writeState(dir, st); err != nil {
		return b, fmt.Errorf("bundle installed but state not written: %w", err)
	}
	return b, nil
}

// ErrNotInstalled is returned by Status when no valid bundle is installed.
var ErrNotInstalled = errors.New("no rules feed bundle is installed")
