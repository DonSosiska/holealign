//go:build integration

package match

import (
	"context"
	"os"
	"testing"
	"time"

	"panoptes/internal/model"
)

// A minimal CycloneDX SBOM as Syft would write it: Debian 12 with a vulnerable openssh-server.
const sbomOpenSSH = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {"type": "operating-system", "bom-ref": "os", "name": "debian", "version": "12",
     "description": "Debian GNU/Linux 12 (bookworm)",
     "properties": [{"name": "syft:distro:id", "value": "debian"}, {"name": "syft:distro:versionID", "value": "12"}]},
    {"type": "library", "bom-ref": "pkg1", "name": "openssh-server", "version": "1:9.2p1-2+deb12u2",
     "purl": "pkg:deb/debian/openssh-server@1:9.2p1-2+deb12u2?arch=amd64&distro=debian-12",
     "properties": [{"name": "syft:package:type", "value": "deb"},
                    {"name": "syft:package:metadataType", "value": "dpkg-db-entry"},
                    {"name": "syft:metadata:package", "value": "openssh-server"},
                    {"name": "syft:metadata:source", "value": "openssh"},
                    {"name": "syft:metadata:version", "value": "1:9.2p1-2+deb12u2"}]}
  ]
}`

// Run with: go test -tags integration ./internal/server/match -run Integration -v
// PANOPTES_TEST_GRYPE_DB may point at a persistent cache dir to avoid re-downloading (~100+ MB).
func TestIntegrationOpenSSHRegreSSHion(t *testing.T) {
	dir := os.Getenv("PANOPTES_TEST_GRYPE_DB")
	if dir == "" {
		dir = t.TempDir()
	}
	g := NewGrype(dir, nil)
	defer g.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if _, err := g.Reload(ctx, true); err != nil {
		t.Skipf("grype DB not available (offline?): %v", err)
	}
	fs, err := g.Match(ctx, model.TargetHost, []byte(sbomOpenSSH), model.OSInfo{ID: "debian", VersionID: "12"})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d findings; db built %s", len(fs), g.Status().Built)
	var hit *model.Finding
	for i, f := range fs {
		t.Logf("  %s %s sev=%s cvss=%.1f epss=%.4f kev=%v fix=%v/%v aliases=%v", f.PackageName, f.VulnID, f.Severity, f.CVSS, f.EPSS, f.KEV, f.FixState, f.FixedVersions, f.Aliases)
		if f.VulnID == "CVE-2024-6387" || contains(f.Aliases, "CVE-2024-6387") {
			hit = &fs[i]
		}
	}
	if hit == nil {
		t.Fatal("CVE-2024-6387 (regreSSHion) not found for openssh-server 1:9.2p1-2+deb12u2 on debian 12")
	}
	if hit.PackageType != "deb" || hit.PackageName != "openssh-server" || hit.Severity == "Unknown" {
		t.Fatalf("unexpected finding fields: %+v", *hit)
	}
	if hit.CVSS <= 0 {
		t.Errorf("expected a CVSS score, got %v", hit.CVSS)
	}
	if hit.EPSS <= 0 {
		t.Errorf("expected an EPSS score from the DB, got %v", hit.EPSS)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
