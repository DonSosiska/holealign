package rulesbot

import (
	"context"
	"encoding/json"
	"fmt"
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

func TestCVSS3Score(t *testing.T) {
	for vec, want := range map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.8,
		"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H": 7.8,
		"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H": 9.9,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0,
		"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N": 1.6,
		"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H": 5.5,
	} {
		got, err := CVSS3Score(vec)
		if err != nil || got != want {
			t.Errorf("%s: got %v (%v), want %v", vec, got, err, want)
		}
	}
	for _, bad := range []string{"", "CVSS:4.0/AV:N", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H"} {
		if _, err := CVSS3Score(bad); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
	if Rating(9.8) != "Critical" || Rating(7) != "High" || Rating(6.9) != "Medium" || Rating(0.1) != "Low" || Rating(0) != "None" {
		t.Error("rating")
	}
}

const (
	vecCrit = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" // 9.8
	vecHigh = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" // 7.8
	vecMed  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" // 6.1
	apiEco  = "Ubuntu:24.04:LTS"                             // not a bulk ecosystem: exercises the per-package API path
	recent  = "2099-01-10T00:00:00Z"
	old     = "2001-01-01T00:00:00Z"
)

type fakeAPIs struct {
	mu        sync.Mutex
	srv       *httptest.Server
	requests  int
	uaOK      bool
	epssCalls []string
}

type fakeVuln struct {
	id, modified, vector string
	pkg                  string
	binaries             []string
}

func newFakeAPIs(t *testing.T, vulns []fakeVuln, epss map[string]string) *fakeAPIs {
	t.Helper()
	f := &fakeAPIs{uaOK: true}
	byID := map[string]fakeVuln{}
	for _, v := range vulns {
		byID[v.id] = v
	}
	mux := http.NewServeMux()
	count := func(r *http.Request) {
		f.mu.Lock()
		f.requests++
		if r.Header.Get("User-Agent") != "panoptes-rules-bot" {
			f.uaOK = false
		}
		f.mu.Unlock()
	}
	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		count(r)
		var req struct {
			Queries []struct {
				Package   struct{ Name, Ecosystem string } `json:"package"`
				PageToken string                           `json:"page_token"`
			} `json:"queries"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		q := req.Queries[0]
		var list []map[string]string
		for _, v := range vulns {
			if v.pkg == q.Package.Name && q.Package.Ecosystem == apiEco {
				list = append(list, map[string]string{"id": v.id, "modified": v.modified})
			}
		}
		// two pages: the first holds all but the last vuln
		res := map[string]any{}
		if len(list) > 1 && q.PageToken == "" {
			res["vulns"], res["next_page_token"] = list[:len(list)-1], "p2"
		} else if len(list) > 1 {
			res["vulns"] = list[len(list)-1:]
		} else {
			res["vulns"] = list
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"results": []any{res}})
	})
	mux.HandleFunc("/v1/vulns/", func(w http.ResponseWriter, r *http.Request) {
		count(r)
		v, ok := byID[strings.TrimPrefix(r.URL.Path, "/v1/vulns/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		cve := strings.TrimPrefix(v.id, "DEBIAN-")
		aff := map[string]any{"package": map[string]string{"name": v.pkg, "ecosystem": apiEco}}
		if len(v.binaries) > 0 {
			var bs []any
			for _, b := range v.binaries {
				bs = append(bs, map[string]string{"binary_name": b})
			}
			aff["ecosystem_specific"] = map[string]any{"binaries": bs}
		}
		d := map[string]any{"id": v.id, "aliases": []string{cve}, "published": "2099-01-01T00:00:00Z", "affected": []any{aff}}
		if v.vector != "" {
			d["severity"] = []any{map[string]string{"type": "CVSS_V3", "score": v.vector}}
		}
		_ = json.NewEncoder(w).Encode(d)
	})
	mux.HandleFunc("/epss", func(w http.ResponseWriter, r *http.Request) {
		count(r)
		list := r.URL.Query().Get("cve")
		f.mu.Lock()
		f.epssCalls = append(f.epssCalls, list)
		f.mu.Unlock()
		var data []map[string]string
		for _, c := range strings.Split(list, ",") {
			if s, ok := epss[c]; ok {
				data = append(data, map[string]string{"cve": c, "epss": s})
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func writeKEV(t *testing.T, cves ...string) string {
	t.Helper()
	var vs []map[string]string
	for _, c := range cves {
		vs = append(vs, map[string]string{"cveID": c})
	}
	b, _ := json.Marshal(map[string]any{"vulnerabilities": vs})
	p := filepath.Join(t.TempDir(), "kev.json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func baseOpts(f *fakeAPIs, kev string, pkgs ...string) CandidateOptions {
	return CandidateOptions{
		OSVURL: f.srv.URL, KEV: kev, EPSSURL: f.srv.URL + "/epss?cve=", Ecosystems: []string{apiEco}, Packages: pkgs,
		Since: 30 * 24 * time.Hour, Max: 20, Now: func() time.Time { return time.Date(2099, 1, 15, 0, 0, 0, 0, time.UTC) },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func fixture() []fakeVuln {
	return []fakeVuln{
		{id: "DEBIAN-CVE-2099-0001", modified: recent, vector: vecCrit, pkg: "openssh"},
		{id: "DEBIAN-CVE-2099-0002", modified: recent, vector: vecMed, pkg: "openssh"},
		{id: "DEBIAN-CVE-2099-0003", modified: old, vector: vecMed, pkg: "openssh"}, // KEV, old, Medium
		{id: "DEBIAN-CVE-2099-0005", modified: recent, vector: vecHigh, pkg: "openssh"},
		{id: "DEBIAN-CVE-2099-0004", modified: old, vector: vecCrit, pkg: "openssh"}, // old, not KEV
		{id: "UBUNTU-CVE-2099-0006", modified: recent, vector: vecCrit, pkg: "nginx", binaries: []string{"nginx", "nginx-common"}},
	}
}

func ids(cs []Candidate) string {
	var s []string
	for _, c := range cs {
		s = append(s, c.Vuln)
	}
	return strings.Join(s, ",")
}

func TestCandidates(t *testing.T) {
	f := newFakeAPIs(t, fixture(), map[string]string{"CVE-2099-0001": "0.5", "CVE-2099-0006": "0.9", "CVE-2099-0003": "0.01"})
	o := baseOpts(f, writeKEV(t, "CVE-2099-0003"), "openssh", "nginx")
	o.Rules = []model.Rule{{ID: "r", Vulns: []string{"CVE-2099-0005"}, Packages: []model.PackageSelector{{Name: "openssh*", Type: "deb"}}}}
	cs, err := FindCandidates(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	// 0005 is covered, 0002 is Medium and not in KEV, 0004 is old and not in KEV.
	// Order: KEV first, then EPSS, then CVSS.
	if got := ids(cs); got != "CVE-2099-0003,CVE-2099-0006,CVE-2099-0001" {
		t.Fatalf("order: %s", got)
	}
	k := cs[0]
	if !k.KEV || k.Severity != "Medium" || k.Package != "openssh" || k.Type != "deb" || k.Ecosystem != apiEco ||
		len(k.BinaryPackages) != 1 || k.BinaryPackages[0] != "openssh" || k.EPSS != 0.01 || k.CVSS != 6.1 {
		t.Fatalf("kev candidate: %+v", k)
	}
	n := cs[1]
	if n.CVSS != 9.8 || n.Severity != "Critical" || n.EPSS != 0.9 || strings.Join(n.BinaryPackages, ",") != "nginx,nginx-common" ||
		strings.Join(n.Aliases, ",") != "UBUNTU-CVE-2099-0006" || n.Published == "" {
		t.Fatalf("nginx candidate: %+v", n)
	}
	if !f.uaOK {
		t.Error("missing User-Agent")
	}

	// -max caps the list
	o.Max = 2
	if cs, err = FindCandidates(context.Background(), o); err != nil || ids(cs) != "CVE-2099-0003,CVE-2099-0006" {
		t.Fatalf("max: %v %v", ids(cs), err)
	}
	// no rules: the covered CVE comes back
	o.Max, o.Rules = 20, nil
	if cs, err = FindCandidates(context.Background(), o); err != nil || !strings.Contains(ids(cs), "CVE-2099-0005") {
		t.Fatalf("uncovered: %v %v", ids(cs), err)
	}
}

func TestCandidatesCoveredByAliasAndBinary(t *testing.T) {
	c := Candidate{Vuln: "CVE-1", Aliases: []string{"GHSA-x"}, Package: "nginx", BinaryPackages: []string{"nginx-common"}, Type: "deb"}
	r := func(v string, sel model.PackageSelector) []model.Rule {
		return []model.Rule{{Vulns: []string{v}, Packages: []model.PackageSelector{sel}}}
	}
	if !covered(r("GHSA-x", model.PackageSelector{Name: "nginx*"}), c) {
		t.Error("alias + glob should cover")
	}
	if !covered(r("CVE-1", model.PackageSelector{Name: "nginx-common", Type: "deb"}), c) {
		t.Error("binary name should cover")
	}
	if covered(r("CVE-1", model.PackageSelector{Name: "nginx*", Type: "apk"}), c) {
		t.Error("other type must not cover")
	}
	if covered(r("CVE-2", model.PackageSelector{Name: "nginx*"}), c) {
		t.Error("other CVE must not cover")
	}
}

func TestCandidatesRequestCap(t *testing.T) {
	f := newFakeAPIs(t, fixture(), nil)
	o := baseOpts(f, writeKEV(t), "openssh", "nginx")
	o.MaxRequests = 4
	if _, err := FindCandidates(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.requests != 4 {
		t.Fatalf("requests = %d, want exactly the cap of 4", f.requests)
	}
}

func TestCandidatesTotalFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", 500) }))
	defer srv.Close()
	o := CandidateOptions{OSVURL: srv.URL, KEV: writeKEV(t), EPSSURL: srv.URL + "/?cve=", Packages: []string{"openssh"},
		Ecosystems: []string{apiEco}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if _, err := FindCandidates(context.Background(), o); err == nil || !strings.Contains(err.Error(), "every OSV query failed") {
		t.Fatalf("got %v", err)
	}
	o.Ecosystems = []string{"Gentoo:1"}
	if _, err := FindCandidates(context.Background(), o); err == nil || !strings.Contains(err.Error(), "unsupported OSV ecosystem") {
		t.Fatalf("got %v", err)
	}
}

func TestEPSSBatches(t *testing.T) {
	f := newFakeAPIs(t, nil, nil)
	var cs []Candidate
	for i := 0; i < 150; i++ {
		cs = append(cs, Candidate{Vuln: fmt.Sprintf("CVE-2099-%04d", i)})
	}
	enrichEPSS(context.Background(), &fetcher{c: http.DefaultClient, max: 10}, f.srv.URL+"/epss?cve=", cs, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if len(f.epssCalls) != 2 || strings.Count(f.epssCalls[0], ",") != 99 || strings.Count(f.epssCalls[1], ",") != 49 {
		t.Fatalf("batches: %d", len(f.epssCalls))
	}
}

func TestBodyLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", MaxBodyBytes+10)))
	}))
	defer srv.Close()
	if _, err := (&fetcher{c: http.DefaultClient, max: 1}).do(context.Background(), http.MethodGet, srv.URL, nil); err == nil {
		t.Fatal("oversized body accepted")
	}
}

func TestParsePackagesAndSince(t *testing.T) {
	got := ParsePackages([]byte("# libs\nopenssh\n  openssl # tls\n\nopenssh\n"))
	if strings.Join(got, ",") != "openssh,openssl" {
		t.Fatalf("%v", got)
	}
	if d, err := ParseSince("30d"); err != nil || d != 30*24*time.Hour {
		t.Fatal(d, err)
	}
	if _, err := ParseSince("x"); err == nil {
		t.Fatal("bad since accepted")
	}
}
