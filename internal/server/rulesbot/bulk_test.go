package rulesbot

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DonSosiska/panoptes/internal/model"
)

type bulkRec struct {
	id, pkg, eco, published, vector string
	fixed                           bool
	withdrawn                       bool
}

func (r bulkRec) json() []byte {
	events := []any{map[string]string{"introduced": "0"}}
	if r.fixed {
		events = append(events, map[string]string{"fixed": "1.2-3"})
	}
	d := map[string]any{
		"id": r.id, "aliases": []string{strings.TrimPrefix(r.id, "DEBIAN-")}, "published": r.published, "modified": "2099-01-14T00:00:00Z",
		"affected": []any{map[string]any{
			"package": map[string]string{"name": r.pkg, "ecosystem": r.eco},
			"ranges":  []any{map[string]any{"type": "ECOSYSTEM", "events": events}},
		}},
	}
	if r.vector != "" {
		d["severity"] = []any{map[string]string{"type": "CVSS_V3", "score": r.vector}}
	}
	if r.withdrawn {
		d["withdrawn"] = "2099-01-01T00:00:00Z"
	}
	b, _ := json.Marshal(d)
	return b
}

func buildZip(t *testing.T, recs []bulkRec, extra map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, r := range recs {
		w, _ := zw.Create(r.id + ".json")
		_, _ = w.Write(r.json())
	}
	for n, b := range extra {
		w, _ := zw.Create(n)
		_, _ = w.Write(b)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type bulkServer struct {
	srv                            *httptest.Server
	mu                             sync.Mutex
	full, notModified, conditional int
	zip                            []byte
	etag                           string
}

func newBulkServer(t *testing.T, z []byte) *bulkServer {
	t.Helper()
	b := &bulkServer{zip: z, etag: `"v1"`}
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		defer b.mu.Unlock()
		if r.URL.Path != "/Debian/all.zip" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("If-None-Match") != "" {
			b.conditional++
		}
		if r.Header.Get("If-None-Match") == b.etag {
			b.notModified++
			w.WriteHeader(http.StatusNotModified)
			return
		}
		b.full++
		w.Header().Set("ETag", b.etag)
		_, _ = w.Write(b.zip)
	}))
	t.Cleanup(b.srv.Close)
	return b
}

func bulkOpts(b *bulkServer, cache, kev string, pkgs ...string) CandidateOptions {
	return CandidateOptions{
		BulkURL: b.srv.URL, CacheDir: cache, KEV: kev, EPSSURL: b.srv.URL + "/epss?cve=", Ecosystems: []string{"Debian:12"}, Packages: pkgs,
		Since: 30 * 24 * time.Hour, KEVMaxAge: 3 * 365 * 24 * time.Hour, Max: 50,
		Now:    func() time.Time { return time.Date(2099, 1, 15, 0, 0, 0, 0, time.UTC) },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func bulkFixture() []bulkRec {
	const d12 = "Debian:12"
	return []bulkRec{
		{id: "DEBIAN-CVE-2099-1001", pkg: "openssl", eco: d12, published: "2090-01-01T00:00:00Z", vector: vecHigh},                  // unfixed, old: relevant
		{id: "DEBIAN-CVE-2014-0160", pkg: "openssl", eco: d12, published: "2014-04-07T00:00:00Z", vector: vecCrit, fixed: true},     // Heartbleed: fixed, ancient
		{id: "DEBIAN-CVE-2099-1002", pkg: "openssl", eco: d12, published: "2099-01-05T00:00:00Z", vector: vecHigh, fixed: true},     // fixed, recent, High
		{id: "DEBIAN-CVE-2099-1003", pkg: "openssl", eco: d12, published: "2099-01-05T00:00:00Z", vector: vecMed, fixed: true},      // fixed, recent, Medium, not KEV
		{id: "DEBIAN-CVE-2099-1004", pkg: "openssl", eco: d12, published: "2097-06-01T00:00:00Z", vector: vecMed, fixed: true},      // KEV, fixed, ~1.5y old
		{id: "DEBIAN-CVE-2099-1005", pkg: "openssl", eco: d12, published: "2092-01-01T00:00:00Z", vector: vecCrit, fixed: true},     // KEV, fixed, 7y old
		{id: "DEBIAN-CVE-2099-1006", pkg: "openssl", eco: d12, published: "2085-01-01T00:00:00Z", vector: vecMed},                   // KEV, unfixed, ancient
		{id: "DEBIAN-CVE-2099-1007", pkg: "openssl", eco: "Debian:11", published: "2099-01-05T00:00:00Z", vector: vecCrit},          // other release
		{id: "DEBIAN-CVE-2099-1008", pkg: "unlisted", eco: d12, published: "2099-01-05T00:00:00Z", vector: vecCrit},                 // not in -packages
		{id: "DEBIAN-CVE-2099-1009", pkg: "openssl", eco: d12, published: "2099-01-05T00:00:00Z", vector: vecCrit, withdrawn: true}, // withdrawn
		{id: "DEBIAN-CVE-2099-1010", pkg: "openssl", eco: d12, published: "2099-01-05T00:00:00Z", vector: vecCrit},                  // covered by a rule
		{id: "DEBIAN-CVE-2099-1011", pkg: "openssl", eco: d12, published: "2090-01-01T00:00:00Z", vector: vecMed},                   // unfixed but Medium, not KEV
		{id: "DEBIAN-CVE-2099-1012", pkg: "openssl", eco: d12, published: "2098-01-01T00:00:00Z", vector: vecCrit, fixed: true},     // fixed, 1y old, not KEV
	}
}

func TestCandidatesBulk(t *testing.T) {
	big := bytes.Repeat([]byte("x"), MaxEntryBytes+1)
	z := buildZip(t, bulkFixture(), map[string][]byte{"DEBIAN-CVE-2099-9999.json": big, "README.txt": []byte("not json"), "bad.json": []byte("{")})
	b := newBulkServer(t, z)
	kev := writeKEV(t, "CVE-2099-1004", "CVE-2099-1005", "CVE-2099-1006", "CVE-2014-0160")
	o := bulkOpts(b, t.TempDir(), kev, "openssl")
	o.Rules = []model.Rule{{ID: "r", Vulns: []string{"CVE-2099-1010"}, Packages: []model.PackageSelector{{Source: "openssl", Type: "deb"}}}}
	cs, err := FindCandidates(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	// KEV first (1004, 1006: EPSS equal, CVSS 6.1 each, so by ID), then by CVSS: 1002 (7.8).
	if got := ids(cs); got != "CVE-2099-1004,CVE-2099-1006,CVE-2099-1001,CVE-2099-1002" && got != "CVE-2099-1004,CVE-2099-1006,CVE-2099-1002,CVE-2099-1001" {
		t.Fatalf("candidates: %s", got)
	}
	for _, c := range cs {
		if c.Source != "openssl" || c.Package != "openssl" || c.Type != "deb" || c.Ecosystem != "Debian:12" || len(c.BinaryPackages) != 1 || c.BinaryPackages[0] != "openssl" {
			t.Errorf("shape: %+v", c)
		}
		switch c.Vuln {
		case "CVE-2014-0160", "CVE-2099-1005":
			t.Errorf("old fixed vulnerability listed: %s", c.Vuln)
		}
	}
	if b.full != 1 {
		t.Fatalf("downloads = %d", b.full)
	}
}

func TestCandidatesBulkCacheReuse(t *testing.T) {
	b := newBulkServer(t, buildZip(t, bulkFixture(), nil))
	cache := t.TempDir()
	kev := writeKEV(t)
	o := bulkOpts(b, cache, kev, "openssl")
	first, err := FindCandidates(context.Background(), o)
	if err != nil || len(first) == 0 {
		t.Fatalf("%v %v", first, err)
	}
	second, err := FindCandidates(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if ids(first) != ids(second) {
		t.Fatalf("results differ: %s vs %s", ids(first), ids(second))
	}
	if b.full != 1 || b.notModified != 1 || b.conditional != 1 {
		t.Fatalf("full=%d 304=%d conditional=%d", b.full, b.notModified, b.conditional)
	}
	// a failing server falls back to the cached copy
	b.srv.Close()
	if third, err := FindCandidates(context.Background(), o); err != nil || ids(third) != ids(first) {
		t.Fatalf("offline with cache: %v %v", ids(third), err)
	}
	// ... but without a cache it is an error
	o.CacheDir = t.TempDir()
	if _, err := FindCandidates(context.Background(), o); err == nil {
		t.Fatal("expected an error without server and cache")
	}
}

func TestBulkDownloadCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("z"), 100))
	}))
	defer srv.Close()
	dest := filepath.Join(t.TempDir(), "x.zip")
	f := &fetcher{c: http.DefaultClient, max: 5}
	if _, err := f.download(context.Background(), srv.URL, dest, false, 50); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("oversized download accepted: %v", err)
	}
	if _, err := os.Stat(dest); err == nil {
		t.Fatal("partial file left behind")
	}
	if _, err := f.download(context.Background(), srv.URL, dest, false, 100); err != nil {
		t.Fatalf("download at the limit: %v", err)
	}
	f = &fetcher{c: http.DefaultClient, max: 0}
	if _, err := f.download(context.Background(), srv.URL, dest, false, 100); err != ErrRequestCap {
		t.Fatalf("request cap: %v", err)
	}
}

func TestScanZipEntryCap(t *testing.T) {
	big := append([]byte(`{"id":"X","pad":"`), bytes.Repeat([]byte("a"), MaxEntryBytes)...)
	big = append(big, []byte(`"}`)...)
	p := filepath.Join(t.TempDir(), "a.zip")
	z := buildZip(t, []bulkRec{{id: "OK-1", pkg: "p", eco: "Debian:12", published: recent}}, map[string][]byte{"BIG.json": big})
	if err := os.WriteFile(p, z, 0o644); err != nil {
		t.Fatal(err)
	}
	var seen []string
	n, err := scanZip(p, func(d *osvDetail) { seen = append(seen, d.ID) })
	if err != nil || n != 1 || len(seen) != 1 || seen[0] != "OK-1" {
		t.Fatalf("n=%d seen=%v err=%v", n, seen, err)
	}
	if _, err := scanZip(filepath.Join(t.TempDir(), "missing.zip"), nil); err == nil {
		t.Fatal("missing file accepted")
	}
}

func TestRelevancePolicy(t *testing.T) {
	now := time.Date(2099, 1, 15, 0, 0, 0, 0, time.UTC)
	p := policy{cutoff: now.AddDate(0, 0, -30), kevCutoff: now.AddDate(-3, 0, 0)}
	day := func(n int) time.Time { return now.AddDate(0, 0, -n) }
	for _, c := range []struct {
		name     string
		c        Candidate
		unfixed  bool
		pub      time.Time
		relevant bool
	}{
		{"unfixed high", Candidate{Severity: "High"}, true, day(4000), true},
		{"fixed recent high", Candidate{Severity: "Critical"}, false, day(10), true},
		{"fixed old high", Candidate{Severity: "Critical"}, false, day(100), false},
		{"recent medium", Candidate{Severity: "Medium"}, false, day(10), false},
		{"unfixed medium", Candidate{Severity: "Medium"}, true, day(10), false},
		{"kev medium recent-ish", Candidate{Severity: "Medium", KEV: true}, false, day(500), true},
		{"kev old fixed", Candidate{Severity: "Critical", KEV: true}, false, day(2000), false},
		{"kev old unfixed", Candidate{Severity: "Low", KEV: true}, true, day(9000), true},
	} {
		if got := p.relevant(c.c, c.unfixed, c.pub); got != c.relevant {
			t.Errorf("%s: got %v", c.name, got)
		}
	}
}

func TestCoveredBySourceSelector(t *testing.T) {
	c := Candidate{Vuln: "CVE-1", Package: "glibc", Source: "glibc", BinaryPackages: []string{"glibc"}, Type: "deb"}
	rs := func(sel model.PackageSelector) []model.Rule {
		return []model.Rule{{Vulns: []string{"CVE-1"}, Packages: []model.PackageSelector{sel}}}
	}
	if !covered(rs(model.PackageSelector{Source: "glibc", Type: "deb"}), c) {
		t.Error("source selector should cover")
	}
	if covered(rs(model.PackageSelector{Source: "glibc", Type: "apk"}), c) {
		t.Error("other type must not cover")
	}
	if covered(rs(model.PackageSelector{Source: "openssl"}), c) {
		t.Error("other source must not cover")
	}
	if !covered(rs(model.PackageSelector{Name: "glibc"}), c) {
		t.Error("name selector on the source name still covers")
	}
}

func TestCandidatesBulkTotalFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", 500) }))
	defer srv.Close()
	o := CandidateOptions{BulkURL: srv.URL, KEV: writeKEV(t), EPSSURL: srv.URL + "/?cve=", Packages: []string{"openssh"},
		Ecosystems: []string{"Debian:12"}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if _, err := FindCandidates(context.Background(), o); err == nil || !strings.Contains(err.Error(), "every OSV query failed") {
		t.Fatalf("got %v", err)
	}
}
