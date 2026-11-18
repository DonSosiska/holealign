// Package rulesfeed implements the signed central rules feed (docs/rules-feed.md): the bundle
// format, ed25519 signing, strict in-memory extraction and validation, and the server-side
// poller that installs accepted bundles as the "feed" rule layer.
package rulesfeed

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/DonSosiska/holealign/internal/model"
	"github.com/DonSosiska/holealign/internal/server/rules"
)

// FormatVersion is the only bundle format this server understands.
const FormatVersion = 1

// Limits enforced when a bundle is accepted (and respected by Build).
const (
	MaxPointerBytes   = 64 << 10 // latest.json
	MaxBundleBytes    = 10 << 20 // the .tar.gz
	MaxEntries        = 5000     // tar entries
	MaxEntryBytes     = 256 << 10
	maxExpandedBytes  = 64 << 20 // total decompressed size
	IndexName         = "index.json"
	rulesPrefix       = "rules/"
	testsPrefix       = "tests/"
	yamlExt           = ".yaml"
	maxCatalogEntries = 1000
)

var entryNameRe = regexp.MustCompile(`^(rules|tests)/([A-Za-z0-9][A-Za-z0-9._:-]{0,127})\.yaml$`)

// FileEntry lists one file of the bundle in index.json.
type FileEntry struct {
	ID     string `json:"id"`
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
}

// Index is index.json: the signed table of contents of a bundle.
type Index struct {
	Format           int         `json:"format"`
	Seq              uint64      `json:"seq"`
	CreatedAt        string      `json:"created_at"`
	MinServerVersion string      `json:"min_server_version,omitempty"`
	Catalog          []string    `json:"catalog"`
	Rules            []FileEntry `json:"rules"`
	Tests            []FileEntry `json:"tests"`
}

// Bundle is an accepted (verified, validated, tested) rule bundle.
type Bundle struct {
	Index Index
	Rules []model.Rule
	Tests []rules.RuleTests
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// SHA256 returns the lowercase hex SHA-256 of b.
func SHA256(b []byte) string { return sha256Hex(b) }

// TarballName is the canonical file name of the bundle with the given sequence.
func TarballName(seq uint64) string { return fmt.Sprintf("rules-%d.tar.gz", seq) }

// ---------------------------------------------------------------------------
// building
// ---------------------------------------------------------------------------

// BuildOptions are the inputs of Build.
type BuildOptions struct {
	RulesDir         string
	TestsDir         string
	Seq              uint64
	CreatedAt        time.Time // recorded in index.json; the same value gives a byte-identical bundle
	MinServerVersion string
}

// Build validates the rules and tests in the two directories and packs them into a deterministic
// tarball: every rule must be status "reviewed", valid, unique by ID and have tests with at least
// one "exploitable" and one non-exploitable verdict (a rule whose exploitable_if is the literal
// false is exempt from the exploitable case); all tests must pass. Any problem returns an error
// listing every failure and no bundle.
func Build(o BuildOptions) ([]byte, Index, error) {
	var problems []string
	add := func(f string, a ...any) { problems = append(problems, fmt.Sprintf(f, a...)) }
	if o.Seq == 0 {
		add("seq must be at least 1")
	}

	ruleFiles := map[string][]byte{} // id -> raw yaml
	var rs []model.Rule
	names, err := yamlNames(o.RulesDir)
	if err != nil {
		return nil, Index{}, fmt.Errorf("rules dir: %w", err)
	}
	for _, n := range names {
		data, err := os.ReadFile(filepath.Join(o.RulesDir, n))
		if err != nil {
			add("%s: %v", n, err)
			continue
		}
		r, err := rules.ParseRule(data)
		if err != nil {
			add("%s: %v", n, err)
			continue
		}
		if err := rules.Validate(r); err != nil {
			add("%s: %v", n, err)
			continue
		}
		if r.Status != model.RuleReviewed {
			add("%s: rule %s has status %q; only reviewed rules may be published", n, r.ID, r.Status)
			continue
		}
		if !entryNameRe.MatchString(rulesPrefix + r.ID + yamlExt) {
			add("%s: rule id %q cannot be used as a file name", n, r.ID)
			continue
		}
		if _, dup := ruleFiles[r.ID]; dup {
			add("%s: duplicate rule id %s", n, r.ID)
			continue
		}
		ruleFiles[r.ID] = data
		rs = append(rs, r)
	}
	if len(rs) == 0 && len(problems) == 0 {
		add("no rules found in %s", o.RulesDir)
	}

	testFiles := map[string][]byte{}
	var tests []rules.RuleTests
	tnames, err := yamlNames(o.TestsDir)
	if err != nil {
		return nil, Index{}, fmt.Errorf("tests dir: %w", err)
	}
	for _, n := range tnames {
		id := strings.TrimSuffix(strings.TrimSuffix(n, ".yaml"), ".yml")
		if filepath.Ext(n) == ".yml" {
			add("%s: test files must use the .yaml extension", n)
			continue
		}
		data, err := os.ReadFile(filepath.Join(o.TestsDir, n))
		if err != nil {
			add("%s: %v", n, err)
			continue
		}
		cases, err := rules.ParseTests(data)
		if err != nil {
			add("%s: %v", n, err)
			continue
		}
		if _, ok := ruleFiles[id]; !ok {
			add("%s: there is no rule %q for these tests", n, id)
			continue
		}
		testFiles[id] = data
		tests = append(tests, rules.RuleTests{RuleID: id, Cases: cases})
	}
	problems = append(problems, coverageProblems(rs, tests)...)
	for _, f := range rules.RunTests(rs, tests) {
		add("test failed: %s", f)
	}
	if len(problems) > 0 {
		return nil, Index{}, errors.New(strings.Join(problems, "\n"))
	}

	catalog := map[string]bool{}
	for _, r := range rs {
		for _, f := range r.Facts {
			if !strings.HasPrefix(f, rules.FileMatchPrefix) {
				catalog[f] = true
			}
		}
	}
	idx := Index{Format: FormatVersion, Seq: o.Seq, CreatedAt: o.CreatedAt.UTC().Format(time.RFC3339),
		MinServerVersion: o.MinServerVersion, Catalog: sortedKeys(catalog), Rules: []FileEntry{}, Tests: []FileEntry{}}
	files := map[string][]byte{}
	for id, data := range ruleFiles {
		name := rulesPrefix + id + yamlExt
		files[name] = data
		idx.Rules = append(idx.Rules, FileEntry{ID: id, File: name, SHA256: sha256Hex(data)})
	}
	for id, data := range testFiles {
		name := testsPrefix + id + yamlExt
		files[name] = data
		idx.Tests = append(idx.Tests, FileEntry{ID: id, File: name, SHA256: sha256Hex(data)})
	}
	sort.Slice(idx.Rules, func(i, j int) bool { return idx.Rules[i].ID < idx.Rules[j].ID })
	sort.Slice(idx.Tests, func(i, j int) bool { return idx.Tests[i].ID < idx.Tests[j].ID })
	ib, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return nil, Index{}, err
	}
	files[IndexName] = append(ib, '\n')
	tb, err := pack(files)
	if err != nil {
		return nil, Index{}, err
	}
	if len(tb) > MaxBundleBytes {
		return nil, Index{}, fmt.Errorf("bundle is %d bytes, larger than the %d byte limit", len(tb), MaxBundleBytes)
	}
	// Self-check: what was built must be accepted by the same code a server runs.
	if _, err := Open(tb, ""); err != nil {
		return nil, Index{}, fmt.Errorf("internal error: built bundle does not verify: %w", err)
	}
	return tb, idx, nil
}

func yamlNames(dir string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		switch filepath.Ext(e.Name()) {
		case ".yaml", ".yml":
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// CoverageProblems reports the rules that lack an exploitable or a non-exploitable test case (the
// same check Build applies), so authoring tools can check before a pull request.
func CoverageProblems(rs []model.Rule, tests []rules.RuleTests) []string {
	return coverageProblems(rs, tests)
}

// coverageProblems reports rules without a test for "exploitable" and for a non-exploitable verdict.
func coverageProblems(rs []model.Rule, tests []rules.RuleTests) []string {
	by := map[string][]rules.TestCase{}
	for _, t := range tests {
		by[t.RuleID] = t.Cases
	}
	var out []string
	for _, r := range rs {
		cases := by[r.ID]
		if len(cases) == 0 {
			out = append(out, fmt.Sprintf("rule %s has no tests", r.ID))
			continue
		}
		var exp, non bool
		for _, c := range cases {
			switch c.Want {
			case model.VerdictExploitable:
				exp = true
			case model.VerdictNotExploitable, model.VerdictNotAffected:
				non = true
			}
		}
		constFalse := strings.TrimSpace(r.ExploitableIf) == "false"
		if !exp && !constFalse {
			out = append(out, fmt.Sprintf("rule %s needs a test case with want: exploitable", r.ID))
		}
		if !non {
			out = append(out, fmt.Sprintf("rule %s needs a test case with a non-exploitable verdict (affected_not_exploitable)", r.ID))
		}
	}
	return out
}

// pack writes the files as a deterministic .tar.gz: entries sorted by name, fixed mtime, uid/gid 0,
// no owner names, mode 0644, USTAR headers, gzip header without name or time.
func pack(files map[string][]byte) ([]byte, error) {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	zw.Header = gzip.Header{OS: 255} // unknown OS, zero mtime, no name
	tw := tar.NewWriter(zw)
	for _, n := range names {
		data := files[n]
		hdr := &tar.Header{Typeflag: tar.TypeReg, Name: n, Mode: 0o644, Size: int64(len(data)),
			ModTime: time.Unix(0, 0), Format: tar.FormatUSTAR}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ---------------------------------------------------------------------------
// opening (server side, and the build self-check)
// ---------------------------------------------------------------------------

// Open extracts a bundle in memory with strict checks and validates it completely. The caller
// must have verified the signature first. serverVersion is compared with min_server_version
// (empty or non-numeric versions such as "dev" skip the check). Any problem rejects the WHOLE
// bundle: nothing is returned but the error.
func Open(tarball []byte, serverVersion string) (*Bundle, error) {
	if len(tarball) > MaxBundleBytes {
		return nil, fmt.Errorf("bundle is larger than %d bytes", MaxBundleBytes)
	}
	files, err := extract(tarball)
	if err != nil {
		return nil, err
	}
	rawIdx, ok := files[IndexName]
	if !ok {
		return nil, errors.New("bundle has no index.json")
	}
	var idx Index
	if err := json.Unmarshal(rawIdx, &idx); err != nil {
		return nil, fmt.Errorf("index.json: %w", err)
	}
	if idx.Format != FormatVersion {
		return nil, fmt.Errorf("unsupported bundle format %d (this server understands %d)", idx.Format, FormatVersion)
	}
	if idx.Seq == 0 {
		return nil, errors.New("index.json: seq must be at least 1")
	}
	if len(idx.Catalog) > maxCatalogEntries {
		return nil, errors.New("index.json: catalog is too large")
	}
	if idx.MinServerVersion != "" && versionLess(serverVersion, idx.MinServerVersion) {
		return nil, fmt.Errorf("bundle needs holealign-server %s or newer (this is %s)", idx.MinServerVersion, serverVersion)
	}
	known := map[string]bool{}
	for _, n := range rules.CatalogFacts() {
		known[n] = true
	}
	for _, n := range idx.Catalog {
		if !known[n] && !strings.HasPrefix(n, rules.FileMatchPrefix) {
			return nil, fmt.Errorf("bundle uses fact %q that this server does not know; upgrade holealign-server", n)
		}
	}

	listed := map[string]bool{IndexName: true}
	check := func(kind, prefix string, entries []FileEntry) error {
		seen := map[string]bool{}
		for _, e := range entries {
			want := prefix + e.ID + yamlExt
			if e.File != want || !entryNameRe.MatchString(e.File) {
				return fmt.Errorf("index.json: %s entry %q has file %q, want %q", kind, e.ID, e.File, want)
			}
			if seen[e.ID] {
				return fmt.Errorf("index.json: duplicate %s entry %q", kind, e.ID)
			}
			seen[e.ID] = true
			data, ok := files[e.File]
			if !ok {
				return fmt.Errorf("index.json lists %s but the archive does not contain it", e.File)
			}
			if !strings.EqualFold(e.SHA256, sha256Hex(data)) {
				return fmt.Errorf("%s: sha256 does not match index.json", e.File)
			}
			listed[e.File] = true
		}
		return nil
	}
	if err := check("rule", rulesPrefix, idx.Rules); err != nil {
		return nil, err
	}
	if err := check("test", testsPrefix, idx.Tests); err != nil {
		return nil, err
	}
	for n := range files {
		if !listed[n] {
			return nil, fmt.Errorf("archive contains %s which index.json does not list", n)
		}
	}
	if len(idx.Rules) == 0 {
		return nil, errors.New("bundle contains no rules")
	}

	b := &Bundle{Index: idx}
	var problems []string
	for _, e := range idx.Rules {
		r, err := rules.ParseRule(files[e.File])
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", e.File, err))
			continue
		}
		if r.ID != e.ID {
			problems = append(problems, fmt.Sprintf("%s: rule id is %q, want %q", e.File, r.ID, e.ID))
			continue
		}
		if err := rules.Validate(r); err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", e.File, err))
			continue
		}
		if r.Status != model.RuleReviewed {
			problems = append(problems, fmt.Sprintf("%s: status is %q, a feed may only carry reviewed rules", e.File, r.Status))
			continue
		}
		b.Rules = append(b.Rules, r)
	}
	for _, e := range idx.Tests {
		cases, err := rules.ParseTests(files[e.File])
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", e.File, err))
			continue
		}
		b.Tests = append(b.Tests, rules.RuleTests{RuleID: e.ID, Cases: cases})
	}
	if len(problems) == 0 {
		for _, f := range rules.RunTests(b.Rules, b.Tests) {
			problems = append(problems, "test failed: "+f.String())
		}
	}
	if len(problems) > 0 {
		const maxShown = 10
		more := ""
		if len(problems) > maxShown {
			more = fmt.Sprintf(" (and %d more)", len(problems)-maxShown)
			problems = problems[:maxShown]
		}
		return nil, fmt.Errorf("bundle %d rejected: %s%s", idx.Seq, strings.Join(problems, "; "), more)
	}
	return b, nil
}

// extract reads the gzip+tar stream into memory. Only regular files named exactly index.json,
// rules/<id>.yaml or tests/<id>.yaml are allowed; everything else (directories, links, devices,
// pax/global headers, odd names, duplicates, oversized or too many entries) rejects the archive.
func extract(tarball []byte) (map[string][]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(tarball))
	if err != nil {
		return nil, fmt.Errorf("not a gzip file: %w", err)
	}
	defer zr.Close()
	tr := tar.NewReader(io.LimitReader(zr, maxExpandedBytes+1))
	files := map[string][]byte{}
	var total int64
	for n := 0; ; n++ {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar: %w", err)
		}
		if n >= MaxEntries {
			return nil, fmt.Errorf("archive has more than %d entries", MaxEntries)
		}
		name := hdr.Name
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA { //nolint:staticcheck // legacy regular-file flag
			return nil, fmt.Errorf("entry %q is not a regular file (type %q)", name, string(hdr.Typeflag))
		}
		if name != IndexName && !entryNameRe.MatchString(name) {
			return nil, fmt.Errorf("entry %q is not allowed (only index.json, rules/<id>.yaml, tests/<id>.yaml)", name)
		}
		if _, dup := files[name]; dup {
			return nil, fmt.Errorf("duplicate entry %q", name)
		}
		if hdr.Size < 0 || hdr.Size > MaxEntryBytes {
			return nil, fmt.Errorf("entry %q is %d bytes, larger than the %d byte limit", name, hdr.Size, MaxEntryBytes)
		}
		data, err := io.ReadAll(io.LimitReader(tr, MaxEntryBytes+1))
		if err != nil {
			return nil, fmt.Errorf("tar: read %q: %w", name, err)
		}
		if int64(len(data)) != hdr.Size {
			return nil, fmt.Errorf("entry %q is truncated", name)
		}
		if total += hdr.Size; total > maxExpandedBytes {
			return nil, errors.New("archive expands to too much data")
		}
		files[name] = data
	}
	return files, nil
}

// versionLess reports whether dotted-numeric version a is lower than b. A non-numeric a (dev
// builds) or empty a is never "less", so those builds accept every bundle.
func versionLess(a, b string) bool {
	pa, ok := versionParts(a)
	if !ok {
		return false
	}
	pb, ok := versionParts(b)
	if !ok {
		return false
	}
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			return x < y
		}
	}
	return false
}

func versionParts(v string) ([]int, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	if v == "" {
		return nil, false
	}
	var out []int
	for _, p := range strings.Split(v, ".") {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}
