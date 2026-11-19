package match

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	v6 "github.com/anchore/grype/grype/db/v6"
	v6dist "github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/wagoodman/go-progress"

	"github.com/DonSosiska/holealign/internal/model"
)

func TestToFindingMapsKEVEPSSCVSS(t *testing.T) {
	v := vulnerability.Vulnerability{
		Reference:              vulnerability.Reference{ID: "CVE-2024-1"},
		Fix:                    vulnerability.Fix{State: vulnerability.FixStateFixed, Versions: []string{"1.2.3"}},
		RelatedVulnerabilities: []vulnerability.Reference{{ID: "GHSA-aaaa"}, {ID: "CVE-2024-1"}},
	}
	md := &vulnerability.Metadata{
		Severity:       "critical",
		Cvss:           []vulnerability.Cvss{{Metrics: vulnerability.CvssMetrics{BaseScore: 7.1}}, {Metrics: vulnerability.CvssMetrics{BaseScore: 9.8}}},
		KnownExploited: []vulnerability.KnownExploited{{CVE: "CVE-2024-1", DateAdded: ptr(time.Now())}},
		EPSS:           []vulnerability.EPSS{{EPSS: 0.42}},
	}
	f := toFinding(pkg.Package{Name: "openssl", Version: "3.0.1", Type: "deb", PURL: "pkg:deb/debian/openssl@3.0.1"}, v, md)
	if f.VulnID != "CVE-2024-1" || len(f.Aliases) != 1 || f.Aliases[0] != "GHSA-aaaa" {
		t.Fatalf("ids: %+v", f)
	}
	if f.Severity != "Critical" || f.CVSS != 9.8 || !f.KEV || f.EPSS != 0.42 {
		t.Fatalf("metadata: %+v", f)
	}
	if f.FixState != "fixed" || len(f.FixedVersions) != 1 || f.PackageType != "deb" || f.PURL == "" {
		t.Fatalf("package/fix: %+v", f)
	}
}

func TestMergeMetadataKeepsWorse(t *testing.T) {
	f := model.Finding{Severity: "Negligible"}
	mergeMetadata(&f, &vulnerability.Metadata{Severity: "High", Cvss: []vulnerability.Cvss{{Metrics: vulnerability.CvssMetrics{BaseScore: 8.1}}}})
	if f.Severity != "High" || f.CVSS != 8.1 {
		t.Fatalf("%+v", f)
	}
	mergeMetadata(&f, &vulnerability.Metadata{Severity: "Low"})
	if f.Severity != "High" {
		t.Fatal("severity must not be downgraded")
	}
	mergeMetadata(&f, nil)
}

func TestDedupe(t *testing.T) {
	in := []model.Finding{
		{PackageName: "a", PackageVer: "1", VulnID: "CVE-1", Aliases: []string{"X"}, CVSS: 5},
		{PackageName: "a", PackageVer: "1", VulnID: "CVE-1", Aliases: []string{"X", "Y"}, CVSS: 7, KEV: true},
		{PackageName: "a", PackageVer: "2", VulnID: "CVE-1"},
	}
	out := dedupe(in)
	if len(out) != 2 || len(out[0].Aliases) != 2 || out[0].CVSS != 7 || !out[0].KEV {
		t.Fatalf("%+v", out)
	}
}

func TestMatchWithoutDB(t *testing.T) {
	g := NewGrype(t.TempDir(), nil)
	if g.Ready() {
		t.Fatal("not ready without DB")
	}
	if _, err := g.Match(context.Background(), model.TargetHost, []byte(`{}`), model.OSInfo{}); !errors.Is(err, ErrNoDB) {
		t.Fatalf("want ErrNoDB, got %v", err)
	}
	// offline start: no DB on disk and no update -> error, not a panic
	if _, err := g.Reload(context.Background(), false); err == nil {
		t.Fatal("expected error when no DB is present")
	}
}

func TestPackageCap(t *testing.T) {
	if err := checkPackageCap(MaxPackages); err != nil {
		t.Fatal(err)
	}
	if err := checkPackageCap(MaxPackages + 1); !errors.Is(err, ErrTooManyPackages) {
		t.Fatalf("want ErrTooManyPackages, got %v", err)
	}
}

func ptr[T any](v T) *T { return &v }

func TestValidateDBCounts(t *testing.T) {
	if err := validateDBCounts(0, 0); err == nil {
		t.Fatal("empty DB must be rejected")
	}
	if err := validateDBCounts(2000, 0); err == nil {
		t.Fatal("empty update must be rejected")
	}
	if err := validateDBCounts(2000, 999); err == nil || !strings.Contains(err.Error(), "dropped") {
		t.Fatalf(">50%% drop must be rejected, got %v", err)
	}
	if err := validateDBCounts(2000, 1000); err != nil {
		t.Fatalf("exact 50%% should be allowed, got %v", err)
	}
	if err := validateDBCounts(0, 500); err != nil {
		t.Fatalf("initial non-empty DB should be allowed, got %v", err)
	}
	if err := validateDBCounts(500, 100); err != nil {
		t.Fatalf("below baseline drop should be allowed, got %v", err)
	}
}

// buildSyntheticGrypeDir creates a real Grype v6 DB directory with n vulnerability_handles
// (plus Grype's import.json checksum metadata via Hydrater + WriteImportMetadata) so it can
// be opened offline by grype.LoadVulnerabilityDB with ValidateChecksum=true.
func buildSyntheticGrypeDir(t *testing.T, dir string, n int) {
	t.Helper()
	w, err := v6.NewWriter(v6.Config{DBDirPath: dir})
	if err != nil {
		t.Fatalf("v6.NewWriter: %v", err)
	}
	if err := w.SetDBMetadata(); err != nil {
		t.Fatalf("SetDBMetadata: %v", err)
	}
	if err := w.AddProvider(v6.Provider{ID: "nvd", Version: "1"}); err != nil {
		t.Fatalf("AddProvider: %v", err)
	}
	if n > 0 {
		handles := make([]*v6.VulnerabilityHandle, 0, n)
		for i := 0; i < n; i++ {
			id := fmt.Sprintf("CVE-2026-%05d", i+1)
			handles = append(handles, &v6.VulnerabilityHandle{
				Name:       id,
				Status:     v6.VulnerabilityActive,
				ProviderID: "nvd",
				BlobValue:  &v6.VulnerabilityBlob{ID: id},
			})
		}
		if err := w.AddVulnerabilities(handles...); err != nil {
			t.Fatalf("AddVulnerabilities: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
}

func TestCountVulnerabilitiesOfflineReloadAndActiveGen(t *testing.T) {
	// 1. Verify countVulnerabilities against real Grype v6 schema (0 and 1200 rows).
	emptyDir := t.TempDir()
	buildSyntheticGrypeDir(t, emptyDir, 0)
	if n, err := countVulnerabilities(filepath.Join(emptyDir, v6.VulnerabilityDBFileName)); err != nil || n != 0 {
		t.Fatalf("empty db count = (%d, %v), want (0, nil)", n, err)
	}

	goodDir := t.TempDir()
	buildSyntheticGrypeDir(t, goodDir, 1200)
	if n, err := countVulnerabilities(filepath.Join(goodDir, v6.VulnerabilityDBFileName)); err != nil || n != 1200 {
		t.Fatalf("good db count = (%d, %v), want (1200, nil)", n, err)
	}

	// 2. Verify validGenName rejects path traversal and accepts gen-* names.
	for _, bad := range []string{"", ".", "..", "../gen-1", "gen-1/sub", "6", ".staging-1"} {
		if validGenName(bad) {
			t.Errorf("validGenName(%q) = true, want false", bad)
		}
	}
	if !validGenName("gen-12345") {
		t.Error("validGenName(gen-12345) = false")
	}

	// 3. Verify offline Reload(false) rejects an empty DB.
	emptyRoot := t.TempDir()
	emptyV6 := filepath.Join(emptyRoot, "6")
	if err := os.MkdirAll(emptyV6, 0o700); err != nil {
		t.Fatal(err)
	}
	buildSyntheticGrypeDir(t, emptyV6, 0)
	g := NewGrype(emptyRoot, nil)
	defer g.Close()
	if _, err := g.Reload(context.Background(), false); err == nil {
		t.Fatal("offline Reload accepted empty/unverified DB")
	}
}

// fakeDistClient implements v6dist.Client in-process against real synthetic Grype v6 DB files
// so the full staged curator update, hydration, checksum, anomaly guard, and disk swap execute
// deterministically without requiring loopback TCP.
type fakeDistClient struct {
	mu        sync.Mutex
	latest    *v6dist.LatestDocument
	dbFiles   map[string][]byte
	downloads int
}

func (f *fakeDistClient) Latest() (*v6dist.LatestDocument, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.latest == nil {
		return nil, errors.New("no latest document")
	}
	cp := *f.latest
	return &cp, nil
}

func (f *fakeDistClient) IsUpdateAvailable(current *v6.Description) (*v6dist.Archive, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.latest == nil {
		return nil, nil
	}
	if current != nil && !f.latest.Built.After(current.Built.Time) {
		return nil, nil
	}
	arch := f.latest.Archive
	return &arch, nil
}

func (f *fakeDistClient) ResolveArchiveURL(archive v6dist.Archive) (string, error) {
	return "fake://" + archive.Path, nil
}

func (f *fakeDistClient) Download(rawURL, dest string, p *progress.Manual) (string, error) {
	if p != nil {
		defer p.SetCompleted()
	}
	name := strings.TrimPrefix(rawURL, "fake://")
	f.mu.Lock()
	raw, ok := f.dbFiles[name]
	if ok {
		f.downloads++
	}
	f.mu.Unlock()
	if !ok {
		return "", fmt.Errorf("archive %q not found", name)
	}
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return "", err
	}
	tmp, err := os.MkdirTemp(dest, "grype-db-download")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(tmp, v6.VulnerabilityDBFileName), raw, 0o600); err != nil {
		_ = os.RemoveAll(tmp)
		return "", err
	}
	return tmp, nil
}

func TestStagedUpdateRejectsAnomalousDBAndPreservesActiveDB(t *testing.T) {
	fc := &fakeDistClient{dbFiles: map[string][]byte{}}

	publish := func(name string, built time.Time, count int) {
		t.Helper()
		dir := t.TempDir()
		buildSyntheticGrypeDir(t, dir, count)
		dbPath := filepath.Join(dir, v6.VulnerabilityDBFileName)
		// Stamp db_metadata.build_timestamp to match latest.json, just like a real Grype DB release.
		sdb, err := sql.Open("sqlite", "file:"+dbPath)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sdb.Exec(`UPDATE db_metadata SET build_timestamp = ?`, built.UTC().Format(time.RFC3339)); err != nil {
			_ = sdb.Close()
			t.Fatalf("update build_timestamp: %v", err)
		}
		if err := sdb.Close(); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(dbPath)
		if err != nil {
			t.Fatal(err)
		}
		arch, err := v6dist.NewArchive(dbPath, built, v6.ModelVersion, v6.Revision, v6.Addition)
		if err != nil {
			t.Fatal(err)
		}
		arch.Path = name
		doc := v6dist.NewLatestDocument(*arch)
		fc.mu.Lock()
		fc.latest = doc
		fc.dbFiles[name] = raw
		fc.mu.Unlock()
	}

	dbRoot := t.TempDir()
	g := NewGrypeWithOptions(Options{
		DBRoot:    dbRoot,
		LatestURL: "https://mirror.example/databases",
	})
	g.newDistClient = func(cfg v6dist.Config) (v6dist.Client, error) {
		if cfg.LatestURL != "https://mirror.example/databases" {
			t.Errorf("LatestURL = %q, want custom mirror URL", cfg.LatestURL)
		}
		return fc, nil
	}
	defer g.Close()

	// 1. Initial valid DB with 1200 records downloads into staging, hydrates, validates, and activates.
	t1 := time.Now().UTC().Truncate(time.Second).Add(time.Minute)
	publish("db1.db", t1, 1200)
	changed, err := g.Reload(context.Background(), true)
	if err != nil || !changed {
		t.Fatalf("initial reload: changed=%v err=%v", changed, err)
	}
	if !g.Ready() || g.Status().Vulnerabilities != 1200 {
		t.Fatalf("unexpected status after db1: ready=%v status=%+v", g.Ready(), g.Status())
	}
	if fc.downloads != 1 {
		t.Fatalf("downloads=%d, want 1", fc.downloads)
	}

	// 1b. Repeat poll with same latest.json is a no-op (no re-download).
	changed, err = g.Reload(context.Background(), true)
	if err != nil || changed || fc.downloads != 1 {
		t.Fatalf("repeat reload: changed=%v err=%v downloads=%d", changed, err, fc.downloads)
	}

	// 2. Empty upstream DB (0 records) is refused; active DB in memory AND on disk stays 1200.
	t2 := t1.Add(time.Hour)
	publish("db_empty.db", t2, 0)
	changed, err = g.Reload(context.Background(), true)
	if err == nil || !strings.Contains(err.Error(), "0 vulnerability records") {
		t.Fatalf("empty DB must be rejected, got changed=%v err=%v", changed, err)
	}
	if g.Status().Vulnerabilities != 1200 {
		t.Fatalf("in-memory DB changed after rejected empty update: %+v", g.Status())
	}
	if diskCount, err := countVulnerabilities(g.Status().Path); err != nil || diskCount != 1200 {
		t.Fatalf("on-disk DB corrupted after rejected empty update: count=%d err=%v", diskCount, err)
	}

	// 3. Catastrophic >50% drop (1200 -> 100) is refused; active DB stays 1200.
	t3 := t2.Add(time.Hour)
	publish("db_drop.db", t3, 100)
	changed, err = g.Reload(context.Background(), true)
	if err == nil || !strings.Contains(err.Error(), "dropped from 1200 to 100") {
		t.Fatalf(">50%% drop must be rejected, got changed=%v err=%v", changed, err)
	}
	if g.Status().Vulnerabilities != 1200 {
		t.Fatalf("in-memory DB changed after rejected drop: %+v", g.Status())
	}
	if diskCount, err := countVulnerabilities(g.Status().Path); err != nil || diskCount != 1200 {
		t.Fatalf("on-disk DB corrupted after rejected drop: count=%d err=%v", diskCount, err)
	}

	// 4. Legitimate newer DB (1300 records) is accepted and replaces active DB.
	t4 := t3.Add(time.Hour)
	publish("db_good.db", t4, 1300)
	changed, err = g.Reload(context.Background(), true)
	if err != nil || !changed {
		t.Fatalf("valid update rejected: changed=%v err=%v", changed, err)
	}
	if g.Status().Vulnerabilities != 1300 {
		t.Fatalf("status after db_good: %+v", g.Status())
	}
	if diskCount, err := countVulnerabilities(g.Status().Path); err != nil || diskCount != 1300 {
		t.Fatalf("on-disk DB not updated: count=%d err=%v", diskCount, err)
	}
	// Ensure no leftover staging/backup directories remain and only one generation dir exists.
	ents, _ := os.ReadDir(dbRoot)
	genCount := 0
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".staging-") || strings.HasPrefix(e.Name(), ".prev-") {
			t.Errorf("leftover temp dir %q", e.Name())
		}
		if strings.HasPrefix(e.Name(), "gen-") {
			genCount++
		}
	}
	if genCount != 1 {
		t.Fatalf("gen dirs = %d, want 1", genCount)
	}

	// 5. Simulate server restart: a fresh Grype instance loads generation 2 offline from disk.
	g2 := NewGrype(dbRoot, nil)
	defer g2.Close()
	changed, err = g2.Reload(context.Background(), false)
	if err != nil || !changed || g2.Status().Vulnerabilities != 1300 {
		t.Fatalf("restart offline reload: changed=%v err=%v status=%+v", changed, err, g2.Status())
	}
}
