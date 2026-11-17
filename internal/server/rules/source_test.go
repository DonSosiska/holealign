package rules

import (
	"context"
	"strings"
	"testing"

	"github.com/DonSosiska/panoptes/internal/model"
	"github.com/DonSosiska/panoptes/internal/server/core"
)

func TestSourceOfPURL(t *testing.T) {
	for _, c := range []struct{ purl, name, want string }{
		{"pkg:deb/debian/libc6@2.36-9?arch=amd64&upstream=glibc%402.36-9", "libc6", "glibc"},
		{"pkg:deb/debian/libc6@2.36-9?upstream=glibc", "libc6", "glibc"},
		{"pkg:apk/alpine/libssl3@3.1.4?upstream=openssl", "libssl3", "openssl"},
		{"pkg:rpm/redhat/openssl-libs@3.0.7-27.el9?arch=x86_64&upstream=openssl-3.0.7-27.el9.src.rpm", "openssl-libs", "openssl"},
		{"pkg:deb/debian/curl@7.88", "curl", "curl"},
		{"", "curl", "curl"},
	} {
		if got := SourceOf(c.purl, c.name); got != c.want {
			t.Errorf("SourceOf(%q) = %q, want %q", c.purl, got, c.want)
		}
	}
}

func srcRule(sel model.PackageSelector) model.Rule {
	r := validRule()
	r.Packages = []model.PackageSelector{sel}
	return r
}

func evalSrc(e *Engine, vuln, name, typ, purl string) core.Evaluation {
	return e.Evaluate(context.Background(), core.HostContext{Host: model.Host{Hostname: "h"}, Facts: model.Facts{}},
		model.Finding{VulnID: vuln, PackageName: name, PackageType: typ, PURL: purl, Target: "host", TargetKind: model.TargetHost})
}

func TestSourceSelectorMatching(t *testing.T) {
	r := srcRule(model.PackageSelector{Source: "glibc", Type: "deb"})
	r.Vulns = []string{"CVE-2099-1"}
	e := New([]model.Rule{r}, nil)
	if evalSrc(e, "CVE-2099-1", "libc6", "deb", "pkg:deb/debian/libc6@2.36?upstream=glibc%402.36").Rule == nil {
		t.Error("libc6 with upstream=glibc must match source glibc")
	}
	if evalSrc(e, "CVE-2099-1", "libc-bin", "deb", "pkg:deb/debian/libc-bin@2.36?upstream=glibc").Rule == nil {
		t.Error("libc-bin must match")
	}
	if evalSrc(e, "CVE-2099-1", "glibc", "deb", "").Rule == nil {
		t.Error("no upstream qualifier: the package name is the source")
	}
	if evalSrc(e, "CVE-2099-1", "libc6", "deb", "pkg:deb/debian/libc6@2.36?upstream=other").Rule != nil {
		t.Error("other source must not match")
	}
	if evalSrc(e, "CVE-2099-1", "libc6", "apk", "pkg:apk/x/libc6@1?upstream=glibc").Rule != nil {
		t.Error("type must be respected")
	}
	// name selectors are unchanged
	n := srcRule(model.PackageSelector{Name: "libc*"})
	n.Vulns = r.Vulns
	en := New([]model.Rule{n}, nil)
	if evalSrc(en, "CVE-2099-1", "libc6", "deb", "").Rule == nil {
		t.Error("name selector must still match")
	}
	if evalSrc(en, "CVE-2099-1", "libc6", "deb", "pkg:deb/debian/libc6@1?upstream=zzz").Rule == nil {
		t.Error("name selector ignores the source")
	}
}

func TestSourceInExpression(t *testing.T) {
	r := srcRule(model.PackageSelector{Source: "openssh", Type: "deb"})
	r.Vulns = []string{"CVE-2099-2"}
	r.ExploitableIf = `pkg["source"] == "openssh" && pkg["name"].startsWith("openssh-server")`
	r.Facts = nil
	cases := []TestCase{
		{Name: "server", Want: model.VerdictExploitable, Finding: TestFinding{Vuln: "CVE-2099-2", Package: "openssh-server", Source: "openssh", Type: "deb"}},
		{Name: "client", Want: model.VerdictNotExploitable, Finding: TestFinding{Vuln: "CVE-2099-2", Package: "openssh-client", Source: "openssh", Type: "deb"}},
	}
	if err := Validate(r); err != nil {
		t.Fatal(err)
	}
	if f := RunTests([]model.Rule{r}, []RuleTests{{RuleID: r.ID, Cases: cases}}); len(f) != 0 {
		t.Fatalf("%v", f)
	}
	// without a source the finding cannot match the source selector
	cases[0].Finding.Source = ""
	cases[0].Finding.Package = "ssh-server-x"
	if f := RunTests([]model.Rule{r}, []RuleTests{{RuleID: r.ID, Cases: cases[:1]}}); len(f) != 1 {
		t.Fatalf("want 1 failure, got %v", f)
	}
}

func TestValidateSourceSelector(t *testing.T) {
	for name, tc := range map[string]struct {
		sel  model.PackageSelector
		want string
	}{
		"ok":       {model.PackageSelector{Source: "glibc", Type: "deb"}, ""},
		"both":     {model.PackageSelector{Name: "a", Source: "b"}, "either name or source"},
		"neither":  {model.PackageSelector{Type: "deb"}, "name or source is required"},
		"src glob": {model.PackageSelector{Source: "gl*"}, "exact package name"},
	} {
		err := Validate(srcRule(tc.sel))
		if tc.want == "" {
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
		} else if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want %q", name, err, tc.want)
		}
	}
}
