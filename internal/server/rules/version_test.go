package rules

import (
	"context"
	"testing"

	"github.com/DonSosiska/panoptes/internal/model"
	"github.com/DonSosiska/panoptes/internal/server/core"
)

func TestVersionCompareType(t *testing.T) {
	// want: sign of compare(a, b)
	tests := []struct {
		typ, a, b string
		want      int
	}{
		// dpkg: tilde sorts before everything, even the end of the string
		{"deb", "2.4.52~rc1", "2.4.52", -1},
		{"deb", "1.0-1~bpo12+1", "1.0-1", -1},
		{"deb", "1.0~~", "1.0~", -1},
		{"deb", "1.0~", "1.0", -1},
		{"deb", "1.0", "1.0a", -1},
		{"deb", "1.0~rc1", "1.0~rc2", -1},
		// anything but a tilde sorts after the end of the string
		{"deb", "1.0.0+dfsg", "1.0.0", 1},
		{"deb", "1.0-1+deb12u1", "1.0-1", 1},
		{"deb", "1.0-1+deb12u1", "1.0-1+deb12u2", -1},
		// epoch dominates
		{"deb", "1:1.0", "2.0", 1},
		{"deb", "1:9.2p1-2", "1:9.2p1-2", 0},
		// numeric parts compare numerically, letters before non-letters
		{"deb", "6.1.10", "6.10.0", -1},
		{"deb", "1.0.0a", "1.0.0+", -1},
		{"deb", "1.001", "1.1", 0},
		{"deb", "9.2p1-2+deb12u3", "9.2p1-2+deb12u2", 1},
		// rpm
		{"rpm", "1.0~rc1", "1.0", -1},
		{"rpm", "1.0^git1", "1.0", 1},
		{"rpm", "1.0^git1", "1.0.1", -1},
		{"rpm", "1.2.3-4.el9", "1.2.3-10.el9", -1},
		{"rpm", "2:1.0", "1:9.0", 1},
		{"rpm", "1.0a", "1.0", 1},
		// apk
		{"apk", "1.2.3-r1", "1.2.3-r10", -1},
		{"apk", "1.2.3_rc1", "1.2.3", -1},
		{"apk", "1.2.3_p1", "1.2.3", 1},
		{"apk", "9.7_p1-r0", "9.8_p1-r0", -1},
		// other ecosystems and unparsable versions: loose comparison
		{"npm", "1.2.10", "1.2.9", 1},
		{"", "6.1.10", "6.10.0", -1},
		{"python", "2.0", "2.0.0", 0},
		{"deb", "not a version!", "1.0", versionCompare("not a version!", "1.0")},
	}
	for _, tc := range tests {
		got := versionCompareType(tc.a, tc.b, tc.typ)
		if sign(got) != sign(tc.want) {
			t.Errorf("%s: compare(%q, %q) = %d, want sign %d", tc.typ, tc.a, tc.b, got, tc.want)
		}
		if back := versionCompareType(tc.b, tc.a, tc.typ); sign(back) != -sign(tc.want) {
			t.Errorf("%s: compare(%q, %q) = %d, want sign %d (antisymmetry)", tc.typ, tc.b, tc.a, back, -tc.want)
		}
	}
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

// The CEL functions keep their two-argument signature and pick the ordering from pkg.type.
func TestVersionFunctionsUsePackageType(t *testing.T) {
	run := func(typ, expr string) model.Verdict {
		t.Helper()
		r := model.Rule{ID: "v1", Vulns: []string{"CVE-2030-1"}, Title: "t", Explanation: "e", Source: "builtin", Status: model.RuleReviewed,
			Packages: []model.PackageSelector{{Name: "foo"}}, ExploitableIf: expr}
		e := New([]model.Rule{r}, nil)
		if p := e.Problems(); len(p) > 0 {
			t.Fatal(p[0].String())
		}
		ev := e.Evaluate(context.Background(), core.HostContext{Host: model.Host{Hostname: "h"}},
			model.Finding{VulnID: "CVE-2030-1", PackageName: "foo", PackageType: typ, PackageVer: "2.4.52~rc1", TargetKind: model.TargetHost})
		return ev.Verdict
	}
	if got := run("deb", `version_lt(pkg.version, "2.4.52")`); got != model.VerdictExploitable {
		t.Errorf("deb: 2.4.52~rc1 < 2.4.52 should hold, got %s", got)
	}
	if got := run("deb", `version_ge(pkg.version, "2.4.52")`); got != model.VerdictNotExploitable {
		t.Errorf("deb: 2.4.52~rc1 >= 2.4.52 should not hold, got %s", got)
	}
	if got := run("deb", `version_lt("1.0-1~bpo12+1", "1.0-1")`); got != model.VerdictExploitable {
		t.Errorf("deb bpo: got %s", got)
	}
	if got := run("deb", `version_lt("6.1.10", "6.10.0")`); got != model.VerdictExploitable {
		t.Errorf("numeric: got %s", got)
	}
}
