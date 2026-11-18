package llm

import (
	"context"
	"strings"
	"testing"

	"github.com/DonSosiska/holealign/internal/model"
)

func debFinding(pkg string) model.Finding {
	f := finding()
	f.PackageName = pkg
	f.PURL = "pkg:deb/debian/" + pkg + "@1%3A9.2p1-2?arch=arm64&distro=debian-12&upstream=openssh%401%3A9.2p1-2"
	return f
}

func TestSourceOf(t *testing.T) {
	cases := []struct{ purl, pkg, want string }{
		{"pkg:deb/debian/openssh-client@1%3A9.2p1-2?arch=arm64&distro=debian-12&upstream=openssh", "openssh-client", "openssh"},
		{"pkg:deb/debian/libssl3@3.0?upstream=openssl@3.0.11", "libssl3", "openssl"},
		{"pkg:deb/debian/nginx@1?arch=amd64", "nginx", "nginx"},
		{"", "nginx-common", "nginx-common"},
	}
	for _, c := range cases {
		if got := SourceOf(model.Finding{PackageName: c.pkg, PURL: c.purl}); got != c.want {
			t.Fatalf("%q: got %q want %q", c.purl, got, c.want)
		}
	}
}

func TestSiblingsSharedRule(t *testing.T) {
	e := newEnv(t, 50, goodJSON)
	e.dr.d.Siblings = func(_ context.Context, v, src string) []model.Finding {
		if v != "CVE-2030-0001" || src != "openssh" {
			t.Errorf("siblings args %q %q", v, src)
		}
		return []model.Finding{debFinding("openssh-client"), debFinding("openssh-server"), debFinding("openssh-sftp-server")}
	}
	for _, p := range []string{"openssh-client", "openssh-server", "openssh-sftp-server"} {
		e.dr.Enqueue(context.Background(), debFinding(p))
	}
	if len(e.dr.queue) != 1 {
		t.Fatalf("queue %d", len(e.dr.queue))
	}
	e.run(debFinding("openssh-server"))
	user := e.prov.calls[0]
	for _, p := range []string{"openssh-client (deb)", "openssh-server (deb)", "openssh-sftp-server (deb)"} {
		if !strings.Contains(user, p) {
			t.Fatalf("prompt lacks %s:\n%s", p, user)
		}
	}
	r, err := e.st.GetRule(context.Background(), "CVE-2030-0001-openssh")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"openssh-client", "openssh-server", "openssh-sftp-server"} {
		if !selectorMatches(r.Packages, p, "deb") {
			t.Fatalf("rule lacks package %s: %+v", p, r.Packages)
		}
	}
	e.run(debFinding("openssh-client")) // covered now: no further LLM call
	if e.prov.n() != 1 {
		t.Fatalf("calls %d", e.prov.n())
	}
}

func TestExistingRuleCoversByVulnAndPackage(t *testing.T) {
	e := newEnv(t, 50, goodJSON)
	err := e.st.UpsertRule(context.Background(), model.Rule{ID: "hand", Vulns: []string{"CVE-2030-0001"},
		Packages: []model.PackageSelector{{Name: "foo*", Type: "deb"}}, Status: model.RuleReviewed, ExploitableIf: "true"}, e.now)
	if err != nil {
		t.Fatal(err)
	}
	e.run(finding())
	if e.prov.n() != 0 {
		t.Fatal("covered finding must not be drafted")
	}
	f := finding()
	f.PackageType = "rpm" // type mismatch -> not covered
	e.run(f)
	if e.prov.n() != 1 {
		t.Fatalf("calls %d", e.prov.n())
	}
}
