package match

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"

	"panoptes/internal/model"
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
