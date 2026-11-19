package rulesfeed

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DonSosiska/holealign/internal/model"
	"github.com/DonSosiska/holealign/internal/server/core"
	"github.com/DonSosiska/holealign/internal/server/rules"
)

const testVuln = "CVE-2000-0001"

var created = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func ruleDoc(id, expr, status string) string {
	return fmt.Sprintf(`id: %s
vulns: [%s]
title: "test rule %s"
packages:
  - {name: "pkg*"}
facts: [os.id]
exploitable_if: '%s'
explanation: "test"
status: %s
source: builtin
`, id, testVuln, id, expr, status)
}

const testsDoc = `- name: matches
  finding: {vuln: CVE-2000-0001, package: pkg1, type: deb}
  facts: {os.id: a}
  want: exploitable
- name: does not match
  finding: {vuln: CVE-2000-0001, package: pkg1, type: deb}
  facts: {os.id: b}
  want: affected_not_exploitable
`

// dirs writes rule and test files into fresh directories.
func dirs(t *testing.T, ruleFiles, testFiles map[string]string) (string, string) {
	t.Helper()
	rd, td := t.TempDir(), t.TempDir()
	for n, c := range ruleFiles {
		if err := os.WriteFile(filepath.Join(rd, n), []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for n, c := range testFiles {
		if err := os.WriteFile(filepath.Join(td, n), []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return rd, td
}

// simpleDirs is one rule R-1, exploitable when os.id == match, with matching tests.
func simpleDirs(t *testing.T, match string) (string, string) {
	tests := strings.Replace(testsDoc, "{os.id: b}", "{os.id: "+match+"-x}", 1)
	tests = strings.Replace(tests, "{os.id: a}", "{os.id: "+match+"}", 1)
	return dirs(t, map[string]string{"R-1.yaml": ruleDoc("R-1", `facts["os.id"] == "`+match+`"`, "reviewed")}, map[string]string{"R-1.yaml": tests})
}

type key struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newKey(t *testing.T) key {
	t.Helper()
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key{pub, priv}
}

// bundle builds and signs a bundle with one rule R-1 that is exploitable when os.id == match.
func bundle(t *testing.T, k key, seq uint64, match string) ([]byte, Sig) {
	t.Helper()
	rd, td := simpleDirs(t, match)
	tb, _, err := Build(BuildOptions{RulesDir: rd, TestsDir: td, Seq: seq, CreatedAt: created})
	if err != nil {
		t.Fatal(err)
	}
	return tb, Sign(k.priv, tb)
}

type memKV struct {
	mu sync.Mutex
	m  map[string]string
}

func (k *memKV) KVGet(_ context.Context, key string) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.m[key], nil
}

func (k *memKV) KVSet(_ context.Context, key, v string, _ time.Time) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.m[key] = v
	return nil
}

func (k *memKV) get(key string) string { v, _ := k.KVGet(context.Background(), key); return v }

// feedServer serves latest.json and tarballs; handlers can be swapped per test.
type feedServer struct {
	*httptest.Server
	mu      sync.Mutex
	pointer []byte
	files   map[string][]byte
	hits    int
}

func newFeedServer(t *testing.T) *feedServer {
	t.Helper()
	fs := &feedServer{files: map[string][]byte{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/feed/latest.json", func(w http.ResponseWriter, r *http.Request) {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		fs.hits++
		_, _ = w.Write(fs.pointer)
	})
	mux.HandleFunc("/feed/", func(w http.ResponseWriter, r *http.Request) {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		b, ok := fs.files[strings.TrimPrefix(r.URL.Path, "/feed/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	})
	mux.HandleFunc("/redir/latest.json", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/feed/latest.json", http.StatusFound)
	})
	fs.Server = httptest.NewTLSServer(mux)
	t.Cleanup(fs.Close)
	return fs
}

// publish makes the server serve tarball under its canonical name with a pointer for seq.
func (fs *feedServer) publish(t *testing.T, seq uint64, tb []byte, sig Sig) {
	t.Helper()
	p, err := MarshalJSONFile(MakePointer(seq, TarballName(seq), tb, sig))
	if err != nil {
		t.Fatal(err)
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.pointer = p
	fs.files[TarballName(seq)] = tb
}

type env struct {
	t       *testing.T
	feed    *Feed
	engine  *rules.Engine
	kv      *memKV
	dir     string
	updated int
	key     key
}

func builtinRule(expr string) model.Rule {
	r, err := rules.ParseRule([]byte(ruleDoc("R-1", expr, "reviewed")))
	if err != nil {
		panic(err)
	}
	return r
}

func newEnv(t *testing.T, k key, url string, client *http.Client) *env {
	t.Helper()
	e := &env{t: t, kv: &memKV{m: map[string]string{}}, dir: filepath.Join(t.TempDir(), Dir), key: k}
	e.engine = rules.New([]model.Rule{builtinRule(`facts["os.id"] == "builtin"`)}, nil)
	e.feed = New(Options{
		URL: url, Interval: time.Hour, Keys: []ed25519.PublicKey{k.pub}, Dir: e.dir, KV: e.kv, Engine: e.engine,
		OnUpdated: func(context.Context) { e.updated++ }, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now: func() time.Time { return created }, Client: client,
	})
	return e
}

func (e *env) verdict(osID string) model.Verdict {
	e.t.Helper()
	ev := e.engine.Evaluate(context.Background(), core.HostContext{Facts: model.Facts{"os.id": osID}},
		model.Finding{VulnID: testVuln, PackageName: "pkg1", PackageType: "deb"})
	return ev.Verdict
}

func TestEndToEndPollInstallsFeedRule(t *testing.T) {
	k := newKey(t)
	srv := newFeedServer(t)
	e := newEnv(t, k, srv.URL+"/feed/latest.json", srv.Client())
	if got := e.verdict("builtin"); got != model.VerdictExploitable {
		t.Fatalf("built-in verdict = %s", got)
	}

	tb, sig := bundle(t, k, 3, "a")
	srv.publish(t, 3, tb, sig)
	if err := e.feed.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	// the feed rule replaces the built-in rule with the same id
	if got := e.verdict("a"); got != model.VerdictExploitable {
		t.Fatalf("feed verdict(a) = %s", got)
	}
	if got := e.verdict("builtin"); got != model.VerdictNotExploitable {
		t.Fatalf("built-in rule still active: %s", got)
	}
	if got := e.engine.Sources()["R-1"]; got != "feed:3" {
		t.Fatalf("source = %q", got)
	}
	if e.feed.Seq() != 3 || e.updated != 1 {
		t.Fatalf("seq=%d updated=%d", e.feed.Seq(), e.updated)
	}
	for k, want := range map[string]string{KVSeq: "3", KVLastError: "", KVFailures: "0", KVUpdatedAt: "2026-01-02T03:04:05Z", KVCheckedAt: "2026-01-02T03:04:05Z"} {
		if got := e.kv.get(k); got != want {
			t.Errorf("kv %s = %q, want %q", k, got, want)
		}
	}
	for _, n := range []string{TarballName(3), TarballName(3) + ".sig", "state.json"} {
		if _, err := os.Stat(filepath.Join(e.dir, n)); err != nil {
			t.Errorf("not persisted: %v", err)
		}
	}
	// the same pointer again changes nothing
	if err := e.feed.Poll(context.Background()); err != nil || e.updated != 1 {
		t.Fatalf("repeat poll: err=%v updated=%d", err, e.updated)
	}
	// a newer bundle replaces it and prunes the old file
	tb4, sig4 := bundle(t, k, 4, "b")
	srv.publish(t, 4, tb4, sig4)
	if err := e.feed.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.verdict("b") != model.VerdictExploitable || e.engine.Sources()["R-1"] != "feed:4" || e.updated != 2 {
		t.Fatalf("bundle 4 not active: %s %v", e.verdict("b"), e.engine.Sources())
	}
	if _, err := os.Stat(filepath.Join(e.dir, TarballName(3))); !os.IsNotExist(err) {
		t.Errorf("old bundle not pruned: %v", err)
	}
}

func TestPollFileURL(t *testing.T) {
	k := newKey(t)
	tb, sig := bundle(t, k, 1, "a")
	pub := t.TempDir()
	ptr, _ := MarshalJSONFile(MakePointer(1, "rules-1.tar.gz", tb, sig)) // relative URL
	for n, b := range map[string][]byte{"latest.json": ptr, "rules-1.tar.gz": tb} {
		if err := os.WriteFile(filepath.Join(pub, n), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	e := newEnv(t, k, (&url.URL{Scheme: "file", Path: filepath.Join(pub, "latest.json")}).String(), nil)
	if err := e.feed.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.verdict("a") != model.VerdictExploitable {
		t.Fatal("file:// feed not applied")
	}
}

func TestRollbackAndReplayRejected(t *testing.T) {
	k := newKey(t)
	srv := newFeedServer(t)
	e := newEnv(t, k, srv.URL+"/feed/latest.json", srv.Client())
	tb2, sig2 := bundle(t, k, 2, "a")
	srv.publish(t, 2, tb2, sig2)
	if err := e.feed.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}

	// a validly signed OLDER bundle served with its own (lower) seq: refused as rollback and recorded as a failure
	tb1, sig1 := bundle(t, k, 1, "z")
	srv.publish(t, 1, tb1, sig1)
	if err := e.feed.Poll(context.Background()); err == nil || !strings.Contains(err.Error(), "rollback refused") {
		t.Fatalf("lower seq pointer must fail as rollback, got %v", err)
	}
	if e.feed.Seq() != 2 || e.verdict("a") != model.VerdictExploitable || e.updated != 1 {
		t.Fatalf("rolled back: seq=%d", e.feed.Seq())
	}
	if !strings.Contains(e.kv.get(KVLastError), "rollback refused") || e.kv.get(KVFailures) != "1" {
		t.Fatalf("rollback error not recorded: %q %q", e.kv.get(KVLastError), e.kv.get(KVFailures))
	}

	// replay: the old bundle behind a pointer that claims a higher seq must not be installed
	p, _ := MarshalJSONFile(MakePointer(9, TarballName(1), tb1, sig1))
	srv.mu.Lock()
	srv.pointer = p
	srv.files[TarballName(1)] = tb1
	srv.mu.Unlock()
	err := e.feed.Poll(context.Background())
	if err == nil || !strings.Contains(err.Error(), "index.json says seq 1") {
		t.Fatalf("replay accepted: %v", err)
	}
	if e.feed.Seq() != 2 {
		t.Fatalf("seq = %d", e.feed.Seq())
	}
	if !strings.Contains(e.kv.get(KVLastError), "index.json says seq") || e.kv.get(KVFailures) != "2" {
		t.Fatalf("error not recorded: %q %q", e.kv.get(KVLastError), e.kv.get(KVFailures))
	}
}

func TestTamperedAndUntrustedBundlesRejected(t *testing.T) {
	k, other := newKey(t), newKey(t)
	srv := newFeedServer(t)
	e := newEnv(t, k, srv.URL+"/feed/latest.json", srv.Client())
	tb, sig := bundle(t, k, 1, "a")

	tamper := func(name string, tarball []byte, ptr Pointer, wantErr string) {
		t.Helper()
		p, _ := MarshalJSONFile(ptr)
		srv.mu.Lock()
		srv.pointer = p
		srv.files[TarballName(1)] = tarball
		srv.mu.Unlock()
		err := e.feed.Poll(context.Background())
		if err == nil || !strings.Contains(err.Error(), wantErr) {
			t.Fatalf("%s: got %v, want %q", name, err, wantErr)
		}
		if e.feed.Seq() != 0 || e.verdict("a") != model.VerdictNotExploitable {
			t.Fatalf("%s: bundle was installed", name)
		}
	}
	bad := append([]byte(nil), tb...)
	bad[len(bad)/2] ^= 0xff
	tamper("hash mismatch", bad, MakePointer(1, TarballName(1), tb, sig), "does not match the pointer")
	// attacker also fixes the hash: the signature no longer matches
	tamper("bad signature", bad, MakePointer(1, TarballName(1), bad, sig), "signature does not match")
	// signature by a key the server does not trust
	otherSig := Sign(other.priv, tb)
	tamper("unknown key", tb, MakePointer(1, TarballName(1), tb, otherSig), "not a trusted key")
	// key_id of a trusted key but a signature made with another key
	forged := otherSig
	forged.KeyID = KeyID(k.pub)
	tamper("forged key id", tb, MakePointer(1, TarballName(1), tb, forged), "signature does not match")
	// unsupported algorithm
	algSig := sig
	algSig.Alg = "rsa"
	tamper("algorithm", tb, MakePointer(1, TarballName(1), tb, algSig), "unsupported signature algorithm")
	// malformed signature
	badB64 := sig
	badB64.Sig = "!!!"
	tamper("malformed", tb, MakePointer(1, TarballName(1), tb, badB64), "malformed signature")
}

func TestHTTPRules(t *testing.T) {
	k := newKey(t)
	srv := newFeedServer(t)
	// redirects are not followed
	e := newEnv(t, k, srv.URL+"/redir/latest.json", srv.Client())
	if err := e.feed.Poll(context.Background()); err == nil || !strings.Contains(err.Error(), "HTTP 302") {
		t.Fatalf("redirect followed: %v", err)
	}
	// oversized pointer
	srv.mu.Lock()
	srv.pointer = bytes.Repeat([]byte("x"), MaxPointerBytes+1)
	srv.mu.Unlock()
	e = newEnv(t, k, srv.URL+"/feed/latest.json", srv.Client())
	if err := e.feed.Poll(context.Background()); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("oversized pointer: %v", err)
	}
	// plain http is refused
	e = newEnv(t, k, "http://example.invalid/latest.json", nil)
	if err := e.feed.Poll(context.Background()); err == nil || !strings.Contains(err.Error(), "unsupported URL scheme") {
		t.Fatalf("http accepted: %v", err)
	}
	// a pointer must not switch scheme to file://
	tb, sig := bundle(t, k, 1, "a")
	p, _ := MarshalJSONFile(MakePointer(1, "file:///etc/passwd", tb, sig))
	srv.mu.Lock()
	srv.pointer = p
	srv.mu.Unlock()
	e = newEnv(t, k, srv.URL+"/feed/latest.json", srv.Client())
	if err := e.feed.Poll(context.Background()); err == nil || !strings.Contains(err.Error(), "scheme") {
		t.Fatalf("scheme switch accepted: %v", err)
	}
	// nor to another host or port of the same scheme (the pointer is unsigned)
	u, _ := url.Parse(srv.URL)
	for _, bad := range []string{
		"https://other.example/rules-1.tar.gz",
		"https://169.254.169.254/latest/meta-data",
		"https://" + u.Hostname() + ":1/rules-1.tar.gz",
		"https://user@" + u.Host + "/rules-1.tar.gz",
		"//other.example/rules-1.tar.gz",
	} {
		p, _ = MarshalJSONFile(MakePointer(1, bad, tb, sig))
		srv.mu.Lock()
		srv.pointer = p
		srv.mu.Unlock()
		e = newEnv(t, k, srv.URL+"/feed/latest.json", srv.Client())
		if err := e.feed.Poll(context.Background()); err == nil || !strings.Contains(err.Error(), "differs from the pointer") {
			t.Fatalf("bundle url %q accepted: %v", bad, err)
		}
	}
}

func TestHostPortDefaults(t *testing.T) {
	a, _ := url.Parse("https://Feed.Example/x")
	b, _ := url.Parse("https://feed.example:443/y")
	if hostPort(a) != hostPort(b) {
		t.Errorf("%q != %q", hostPort(a), hostPort(b))
	}
	c, _ := url.Parse("https://feed.example:8443/y")
	if hostPort(a) == hostPort(c) {
		t.Error("port ignored")
	}
}

// rawBundle writes a tar.gz with arbitrary entries (no validation).
type entry struct {
	name     string
	body     []byte
	typeflag byte
	link     string
}

func rawTar(t *testing.T, entries []entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, e := range entries {
		tf := e.typeflag
		if tf == 0 {
			tf = tar.TypeReg
		}
		h := &tar.Header{Name: e.name, Typeflag: tf, Mode: 0o644, Linkname: e.link}
		if tf == tar.TypeReg {
			h.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if tf == tar.TypeReg {
			if _, err := tw.Write(e.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// goodEntries returns the entries of a valid one-rule bundle, with index.json computed from them.
func goodEntries(t *testing.T) []entry {
	t.Helper()
	rd, td := simpleDirs(t, "a")
	tb, _, err := Build(BuildOptions{RulesDir: rd, TestsDir: td, Seq: 1, CreatedAt: created})
	if err != nil {
		t.Fatal(err)
	}
	files, err := extract(tb)
	if err != nil {
		t.Fatal(err)
	}
	var out []entry
	for n, b := range files {
		out = append(out, entry{name: n, body: b})
	}
	return out
}

func replace(es []entry, name string, body []byte) []entry {
	out := append([]entry(nil), es...)
	for i := range out {
		if out[i].name == name {
			out[i].body = body
		}
	}
	return out
}

func TestOpenRejectsMaliciousArchives(t *testing.T) {
	good := goodEntries(t)
	if _, err := Open(rawTar(t, good), ""); err != nil {
		t.Fatalf("control bundle rejected: %v", err)
	}
	huge := bytes.Repeat([]byte("# x\n"), MaxEntryBytes/4+10)
	tooMany := append([]entry(nil), good...)
	for i := 0; i <= MaxEntries; i++ {
		tooMany = append(tooMany, entry{name: fmt.Sprintf("tests/T-%d.yaml", i), body: []byte("x")})
	}
	cases := map[string]struct {
		entries []entry
		want    string
	}{
		"parent dir":     {append(append([]entry(nil), good...), entry{name: "../x", body: []byte("x")}), "not allowed"},
		"rules parent":   {append(append([]entry(nil), good...), entry{name: "rules/../../x.yaml", body: []byte("x")}), "not allowed"},
		"absolute":       {append(append([]entry(nil), good...), entry{name: "/etc/passwd", body: []byte("x")}), "not allowed"},
		"nested dir":     {append(append([]entry(nil), good...), entry{name: "rules/sub/x.yaml", body: []byte("x")}), "not allowed"},
		"symlink":        {append(append([]entry(nil), good...), entry{name: "rules/evil.yaml", typeflag: tar.TypeSymlink, link: "/etc/passwd"}), "not a regular file"},
		"hardlink":       {append(append([]entry(nil), good...), entry{name: "rules/evil.yaml", typeflag: tar.TypeLink, link: "index.json"}), "not a regular file"},
		"device":         {append(append([]entry(nil), good...), entry{name: "rules/dev.yaml", typeflag: tar.TypeChar}), "not a regular file"},
		"directory":      {append(append([]entry(nil), good...), entry{name: "rules/", typeflag: tar.TypeDir}), "not a regular file"},
		"unlisted rule":  {append(append([]entry(nil), good...), entry{name: "rules/EXTRA.yaml", body: []byte(ruleDoc("EXTRA", "true", "reviewed"))}), "does not list"},
		"unlisted other": {append(append([]entry(nil), good...), entry{name: "README.md", body: []byte("x")}), "not allowed"},
		"oversized":      {append(append([]entry(nil), good...), entry{name: "rules/BIG.yaml", body: huge}), "larger than"},
		"too many":       {tooMany, "more than"},
		"duplicate":      {append(append([]entry(nil), good...), good[0]), "duplicate entry"},
		"no index":       {good[:0:0], "no index.json"},
		"hash mismatch": {replace(good, "rules/R-1.yaml", []byte(ruleDoc("R-1", "true", "reviewed"))),
			"sha256 does not match"},
	}
	for name, c := range cases {
		_, err := Open(rawTar(t, c.entries), "")
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want error containing %q", name, err, c.want)
		}
	}
	if _, err := Open([]byte("not gzip"), ""); err == nil {
		t.Error("garbage accepted")
	}
}

// rawBundle assembles a bundle from rule/test documents with a correct index, bypassing Build's
// checks, to prove the server-side checks reject what a faulty publisher might sign.
func rawBundle(t *testing.T, ruleDocs, testDocs map[string]string) []byte {
	t.Helper()
	idx := Index{Format: 1, Seq: 1, CreatedAt: "2026-01-01T00:00:00Z", Catalog: []string{"os.id"}, Rules: []FileEntry{}, Tests: []FileEntry{}}
	var es []entry
	for id, d := range ruleDocs {
		n := "rules/" + id + ".yaml"
		es = append(es, entry{name: n, body: []byte(d)})
		idx.Rules = append(idx.Rules, FileEntry{ID: id, File: n, SHA256: SHA256([]byte(d))})
	}
	for id, d := range testDocs {
		n := "tests/" + id + ".yaml"
		es = append(es, entry{name: n, body: []byte(d)})
		idx.Tests = append(idx.Tests, FileEntry{ID: id, File: n, SHA256: SHA256([]byte(d))})
	}
	ib, _ := json.Marshal(idx)
	return rawTar(t, append(es, entry{name: "index.json", body: ib}))
}

func TestOpenRejectsWholeBundleOnOneBadRule(t *testing.T) {
	good := ruleDoc("R-1", `facts["os.id"] == "a"`, "reviewed")
	second := ruleDoc("R-2", `facts["os.id"] == "a"`, "reviewed")
	tests := map[string]string{"R-1": testsDoc}
	if _, err := Open(rawBundle(t, map[string]string{"R-1": good}, tests), ""); err != nil {
		t.Fatalf("control: %v", err)
	}
	for name, c := range map[string]struct {
		rules map[string]string
		tests map[string]string
		want  string
	}{
		"draft rule":       {map[string]string{"R-1": good, "R-2": ruleDoc("R-2", "true", "draft")}, tests, "a feed may only carry reviewed rules"},
		"rejected rule":    {map[string]string{"R-1": good, "R-2": ruleDoc("R-2", "true", "rejected")}, tests, "reviewed"},
		"invalid cel":      {map[string]string{"R-1": good, "R-2": ruleDoc("R-2", "((", "reviewed")}, tests, "exploitable_if"},
		"unknown fact":     {map[string]string{"R-1": good, "R-2": strings.Replace(second, "os.id", "os.nope", -1)}, tests, "os.nope"},
		"unknown key":      {map[string]string{"R-1": good, "R-2": second + "bogus: 1\n"}, tests, "bogus"},
		"id mismatch":      {map[string]string{"R-1": good, "R-3": second}, tests, "rule id is"},
		"failing test":     {map[string]string{"R-1": strings.Replace(good, `== "a"`, `== "zzz"`, 1)}, tests, "test failed"},
		"tests for nobody": {map[string]string{"R-1": good}, map[string]string{"R-1": testsDoc, "R-9": testsDoc}, "not in the set"},
		"not yaml":         {map[string]string{"R-1": good, "R-2": "::: not yaml"}, tests, "R-2"},
	} {
		_, err := Open(rawBundle(t, c.rules, c.tests), "")
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want error containing %q", name, err, c.want)
		}
	}
}

func TestOpenCatalogAndMinVersion(t *testing.T) {
	rd, td := simpleDirs(t, "a")
	tb, _, err := Build(BuildOptions{RulesDir: rd, TestsDir: td, Seq: 1, CreatedAt: created, MinServerVersion: "1.2.0"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(tb, "1.1.9"); err == nil || !strings.Contains(err.Error(), "needs holealign-server 1.2.0") {
		t.Fatalf("old server accepted: %v", err)
	}
	for _, v := range []string{"1.2.0", "v1.10.0", "2.0.0-rc1", "dev", ""} {
		if _, err := Open(tb, v); err != nil {
			t.Errorf("server %q rejected: %v", v, err)
		}
	}
	// an unknown catalog fact needs a newer server
	idx := Index{Format: 1, Seq: 1, Catalog: []string{"future.fact"}, Rules: []FileEntry{}, Tests: []FileEntry{}}
	ib, _ := json.Marshal(idx)
	if _, err := Open(rawTar(t, []entry{{name: "index.json", body: ib}}), ""); err == nil || !strings.Contains(err.Error(), "future.fact") {
		t.Fatalf("unknown catalog fact accepted: %v", err)
	}
}

func TestBuildRequirements(t *testing.T) {
	r := func(expr, status string) map[string]string {
		return map[string]string{"R-1.yaml": ruleDoc("R-1", expr, status)}
	}
	t1 := map[string]string{"R-1.yaml": testsDoc}
	onlyPos := map[string]string{"R-1.yaml": strings.Join(strings.SplitAfter(testsDoc, "want: exploitable\n")[:1], "")}
	onlyNeg := map[string]string{"R-1.yaml": `- name: n
  finding: {vuln: CVE-2000-0001, package: pkg1, type: deb}
  facts: {os.id: b}
  want: affected_not_exploitable
`}
	for name, c := range map[string]struct {
		rules, tests map[string]string
		want         string
	}{
		"draft":          {r(`facts["os.id"] == "a"`, "draft"), t1, "only reviewed rules"},
		"no tests":       {r(`facts["os.id"] == "a"`, "reviewed"), nil, "has no tests"},
		"only positive":  {r(`facts["os.id"] == "a"`, "reviewed"), onlyPos, "non-exploitable verdict"},
		"only negative":  {r(`facts["os.id"] == "a"`, "reviewed"), onlyNeg, "want: exploitable"},
		"failing test":   {r(`facts["os.id"] == "q"`, "reviewed"), t1, "test failed"},
		"orphan tests":   {r(`facts["os.id"] == "a"`, "reviewed"), map[string]string{"R-1.yaml": testsDoc, "R-2.yaml": testsDoc}, `no rule "R-2"`},
		"invalid rule":   {r(`((`, "reviewed"), t1, "exploitable_if"},
		"duplicate id":   {map[string]string{"a.yaml": ruleDoc("R-1", "true", "reviewed"), "b.yaml": ruleDoc("R-1", "true", "reviewed")}, t1, "duplicate rule id"},
		"no rules":       {nil, nil, "no rules found"},
		"bad test file":  {r(`facts["os.id"] == "a"`, "reviewed"), map[string]string{"R-1.yaml": "- {name: x}"}, "R-1.yaml"},
		"bad seq":        {r(`facts["os.id"] == "a"`, "reviewed"), t1, "seq"},
		"yml test files": {r(`facts["os.id"] == "a"`, "reviewed"), map[string]string{"R-1.yml": testsDoc}, ".yaml extension"},
	} {
		rd, td := dirs(t, c.rules, c.tests)
		seq := uint64(1)
		if name == "bad seq" {
			seq = 0
		}
		if _, _, err := Build(BuildOptions{RulesDir: rd, TestsDir: td, Seq: seq, CreatedAt: created}); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want error containing %q", name, err, c.want)
		}
	}
	// a constant-false rule needs no exploitable case
	rd, td := dirs(t, r(`false`, "reviewed"), onlyNeg)
	if _, _, err := Build(BuildOptions{RulesDir: rd, TestsDir: td, Seq: 1, CreatedAt: created}); err != nil {
		t.Fatalf("constant false rule: %v", err)
	}
}

func TestBuildDeterministic(t *testing.T) {
	rd, td := simpleDirs(t, "a")
	o := BuildOptions{RulesDir: rd, TestsDir: td, Seq: 7, CreatedAt: created}
	a, _, err := Build(o)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond) // mtimes of nothing may leak into the archive
	b, _, err := Build(o)
	if err != nil {
		t.Fatal(err)
	}
	if SHA256(a) != SHA256(b) || !bytes.Equal(a, b) {
		t.Fatal("same input gave different bundles")
	}
	o.Seq = 8
	c, _, _ := Build(o)
	if SHA256(a) == SHA256(c) {
		t.Fatal("seq not part of the bundle")
	}
	// headers: sorted names, mtime 0, uid/gid 0
	zr, _ := gzip.NewReader(bytes.NewReader(a))
	tr := tar.NewReader(zr)
	var names []string
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		names = append(names, h.Name)
		if h.Uid != 0 || h.Gid != 0 || h.Uname != "" || h.Gname != "" || h.ModTime.Unix() != 0 {
			t.Errorf("%s: non-deterministic header %+v", h.Name, h)
		}
	}
	if strings.Join(names, ",") != "index.json,rules/R-1.yaml,tests/R-1.yaml" {
		t.Errorf("entries = %v", names)
	}
}

func TestPersistedBundleReverifiedAtStart(t *testing.T) {
	k := newKey(t)
	srv := newFeedServer(t)
	e := newEnv(t, k, srv.URL+"/feed/latest.json", srv.Client())
	tb, sig := bundle(t, k, 5, "a")
	srv.publish(t, 5, tb, sig)
	if err := e.feed.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}

	restart := func(keys ...ed25519.PublicKey) *env {
		n := newEnv(t, k, "", nil)
		n.dir = e.dir
		n.feed = New(Options{Keys: keys, Dir: e.dir, KV: n.kv, Engine: n.engine, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
		n.feed.LoadPersisted(context.Background())
		return n
	}
	n := restart(k.pub)
	if n.feed.Seq() != 5 || n.verdict("a") != model.VerdictExploitable || n.engine.Sources()["R-1"] != "feed:5" {
		t.Fatalf("persisted bundle not loaded: seq=%d", n.feed.Seq())
	}
	// the key was rotated out: the persisted bundle is no longer trusted
	if n := restart(newKey(t).pub); n.feed.Seq() != 0 || n.engine.Sources()["R-1"] != "builtin" {
		t.Fatalf("untrusted persisted bundle loaded: seq=%d", n.feed.Seq())
	}
	// two trusted keys (rotation window)
	if n := restart(newKey(t).pub, k.pub); n.feed.Seq() != 5 {
		t.Fatal("rotation with two keys failed")
	}
	// tampered file on disk
	path := filepath.Join(e.dir, TarballName(5))
	b, _ := os.ReadFile(path)
	b[len(b)/2] ^= 0xff
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if n := restart(k.pub); n.feed.Seq() != 0 {
		t.Fatal("tampered persisted bundle loaded")
	}
}

func TestImportAntiRollback(t *testing.T) {
	k := newKey(t)
	dir := filepath.Join(t.TempDir(), Dir)
	keys := []ed25519.PublicKey{k.pub}
	tb2, sig2 := bundle(t, k, 2, "a")
	tb1, sig1 := bundle(t, k, 1, "a")
	if _, err := Import(dir, keys, "", tb2, sig2, created); err != nil {
		t.Fatal(err)
	}
	if _, err := Import(dir, keys, "", tb1, sig1, created); err == nil || !strings.Contains(err.Error(), "rollback refused") {
		t.Fatalf("rollback import: %v", err)
	}
	if _, err := Import(dir, keys, "", tb2, sig2, created); err == nil || !strings.Contains(err.Error(), "already installed") {
		t.Fatalf("re-import: %v", err)
	}
	if _, err := Import(dir, []ed25519.PublicKey{newKey(t).pub}, "", tb2, sig2, created); err == nil {
		t.Fatal("untrusted import accepted")
	}
	tb3, sig3 := bundle(t, k, 3, "a")
	if _, err := Import(dir, keys, "", tb3, sig3, created); err != nil {
		t.Fatal(err)
	}
	if st := ReadState(dir); st.Seq != 3 {
		t.Fatalf("state = %+v", st)
	}
	// a running server picks the imported bundle up from disk
	e := newEnv(t, k, "", nil)
	e.feed = New(Options{Keys: keys, Dir: dir, Engine: e.engine, KV: e.kv, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		OnUpdated: func(context.Context) { e.updated++ }})
	e.feed.syncFromDisk(context.Background())
	if e.feed.Seq() != 3 || e.updated != 1 {
		t.Fatalf("sync from disk: seq=%d updated=%d", e.feed.Seq(), e.updated)
	}
}

func TestKeyHelpers(t *testing.T) {
	k := newKey(t)
	path := filepath.Join(t.TempDir(), "k")
	if err := WritePrivateKey(path, k.priv); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	if err := WritePrivateKey(path, k.priv); err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("overwrite: %v", err)
	}
	got, err := ReadPrivateKey(path)
	if err != nil || !bytes.Equal(got, k.priv) {
		t.Fatalf("round trip: %v", err)
	}
	pub, err := ParsePublicKey(EncodePublicKey(k.pub))
	if err != nil || !bytes.Equal(pub, k.pub) || len(KeyID(pub)) != 16 {
		t.Fatal("public key round trip")
	}
	if _, err := ParsePublicKey("AAAA"); err == nil {
		t.Fatal("short key accepted")
	}
	if err := VerifySig([]byte("x"), Sign(k.priv, []byte("x")), nil); err == nil {
		t.Fatal("verified with no trusted keys")
	}
	if !errors.Is(ErrNotInstalled, ErrNotInstalled) {
		t.Fatal()
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// memFeedClient serves latest.json and tarballs in memory over https://feed.test/feed/
// without opening a TCP socket, so tests run in strict offline sandboxes too.
type memFeed struct {
	mu      sync.Mutex
	pointer []byte
	files   map[string][]byte
}

func newMemFeed() (*memFeed, *http.Client) {
	mf := &memFeed{files: map[string][]byte{}}
	c := &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			mf.mu.Lock()
			defer mf.mu.Unlock()
			var body []byte
			status := http.StatusOK
			switch r.URL.Path {
			case "/feed/latest.json":
				body = append([]byte(nil), mf.pointer...)
			default:
				name := strings.TrimPrefix(r.URL.Path, "/feed/")
				if b, ok := mf.files[name]; ok {
					body = append([]byte(nil), b...)
				} else {
					status = http.StatusNotFound
				}
			}
			return &http.Response{
				StatusCode: status,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewReader(body)),
				Request:    r,
			}, nil
		}),
	}
	return mf, c
}

func TestSignedPointerFreshnessAndAntiDowngrade(t *testing.T) {
	k, other := newKey(t), newKey(t)
	mf, client := newMemFeed()
	now := created
	e := newEnv(t, k, "https://feed.test/feed/latest.json", client)
	e.feed.o.Now = func() time.Time { return now }

	setPointer := func(p Pointer, tb []byte) {
		t.Helper()
		raw, err := MarshalJSONFile(p)
		if err != nil {
			t.Fatal(err)
		}
		mf.mu.Lock()
		mf.pointer = raw
		if tb != nil {
			mf.files[TarballName(p.Seq)] = tb
		}
		mf.mu.Unlock()
	}

	tb1, sig1 := bundle(t, k, 1, "a")
	p1, err := MakeSignedPointer(k.priv, 1, TarballName(1), tb1, sig1, now, now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	setPointer(p1, tb1)
	if err := e.feed.Poll(context.Background()); err != nil {
		t.Fatalf("signed pointer 1 rejected: %v", err)
	}
	if !ReadState(e.dir).SignedPointerSeen {
		t.Fatal("SignedPointerSeen not persisted after valid signed pointer")
	}

	// Same-seq poll still checks pointer expiry (freeze attack detection): advance clock past ExpiresAt.
	now = created.Add(25 * time.Hour)
	if err := e.feed.Poll(context.Background()); err == nil || !strings.Contains(err.Error(), "pointer expired") {
		t.Fatalf("expired same-seq pointer accepted: %v", err)
	}

	// Reset clock inside validity window; verify tampered expires_at or foreign key is rejected.
	now = created.Add(time.Hour)
	tampered := p1
	tampered.ExpiresAt = created.Add(48 * time.Hour).Format(time.RFC3339)
	setPointer(tampered, nil)
	if err := e.feed.Poll(context.Background()); err == nil || !strings.Contains(err.Error(), "signature does not match") {
		t.Fatalf("tampered expires_at accepted: %v", err)
	}

	wrongKeyPtr, err := MakeSignedPointer(other.priv, 1, TarballName(1), tb1, sig1, now, now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	setPointer(wrongKeyPtr, nil)
	if err := e.feed.Poll(context.Background()); err == nil || !strings.Contains(err.Error(), "not a trusted key") {
		t.Fatalf("foreign pointer key accepted: %v", err)
	}

	// Anti-downgrade latch: stripping pointer_sig/signed_at/expires_at on a previously signed feed must fail.
	tb2, sig2 := bundle(t, k, 2, "b")
	setPointer(MakePointer(2, TarballName(2), tb2, sig2), tb2)
	if err := e.feed.Poll(context.Background()); err == nil || !strings.Contains(err.Error(), "downgrade") {
		t.Fatalf("downgrade to unsigned pointer accepted: %v", err)
	}
	if e.feed.Seq() != 1 {
		t.Fatalf("seq changed on downgrade: %d", e.feed.Seq())
	}

	// Signed seq 2 succeeds.
	p2, err := MakeSignedPointer(k.priv, 2, TarballName(2), tb2, sig2, now, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	setPointer(p2, tb2)
	if err := e.feed.Poll(context.Background()); err != nil {
		t.Fatalf("signed pointer 2 rejected: %v", err)
	}
	if e.feed.Seq() != 2 {
		t.Fatalf("seq = %d, want 2", e.feed.Seq())
	}

	// Tarball signature cannot be replayed as a pointer signature (domain separation).
	replay := MakePointer(2, TarballName(2), tb2, sig2)
	replay.SignedAt = now.Format(time.RFC3339)
	replay.PointerSig = &sig2
	if err := VerifyPointer(replay, []ed25519.PublicKey{k.pub}, now); err == nil {
		t.Fatal("tarball signature verified as pointer signature")
	}
}

func TestRequireSignedPointerRejectsInitialUnsigned(t *testing.T) {
	k := newKey(t)
	mf, client := newMemFeed()
	e := newEnv(t, k, "https://feed.test/feed/latest.json", client)
	e.feed.o.RequireSignedPointer = true

	tb, sig := bundle(t, k, 1, "a")
	raw, err := MarshalJSONFile(MakePointer(1, TarballName(1), tb, sig))
	if err != nil {
		t.Fatal(err)
	}
	mf.mu.Lock()
	mf.pointer = raw
	mf.files[TarballName(1)] = tb
	mf.mu.Unlock()

	if err := e.feed.Poll(context.Background()); err == nil || !strings.Contains(err.Error(), "require_signed_pointer") {
		t.Fatalf("unsigned pointer accepted when required: %v", err)
	}
	if e.feed.Seq() != 0 {
		t.Fatalf("bundle installed: seq=%d", e.feed.Seq())
	}
}
