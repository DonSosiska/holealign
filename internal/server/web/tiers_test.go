package web

import (
	"context"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DonSosiska/panoptes/internal/model"
)

func (e *env) seedAll(h model.Host, fs ...model.Finding) {
	e.t.Helper()
	for i := range fs {
		fs[i].HostID, fs[i].Target, fs[i].TargetKind, fs[i].PackageType = h.ID, "host", model.TargetHost, "deb"
		if fs[i].PackageVer == "" {
			fs[i].PackageVer = "1.0"
		}
	}
	if _, err := e.st.ApplyHostFindings(context.Background(), h.ID, append(e.existing(h), fs...), time.Now()); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) body(c any, path string) string {
	e.t.Helper()
	w := e.do("GET", path, nil, e.session("admin"))
	if w.Code != 200 {
		e.t.Fatalf("%s: %d", path, w.Code)
	}
	return w.Body.String()
}

func card(t *testing.T, body, label string) int {
	t.Helper()
	m := regexp.MustCompile(`<div class="big">(\d+)</div><div>` + regexp.QuoteMeta(label) + `</div>`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no card %q", label)
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

func seedDemoShape(e *env) model.Host {
	h := e.seedHost("alpha", "prod")
	U := model.VerdictConditionsUnknown
	var fs []model.Finding
	// 3 sibling packages, one CVE, high+fixed: attention
	for _, p := range []string{"openssh-client", "openssh-server", "openssh-sftp-server"} {
		fs = append(fs, model.Finding{PackageName: p, VulnID: "CVE-2024-6387", Severity: "Critical", CVSS: 8.1, FixState: "fixed",
			FixedVersions: []string{"9.2p1-2+deb12u3"}, Verdict: U})
	}
	// background: high but not fixed (two sibling packages)
	fs = append(fs,
		model.Finding{PackageName: "libc6", VulnID: "CVE-2019-1", Severity: "High", FixState: "not-fixed", Verdict: U},
		model.Finding{PackageName: "libc-bin", VulnID: "CVE-2019-1", Severity: "High", FixState: "not-fixed", Verdict: U},
		model.Finding{PackageName: "foo", VulnID: "CVE-2019-2", Severity: "Low", FixState: "wont-fix", Verdict: U},
		// KEV, not fixed: attention
		model.Finding{PackageName: "bar", VulnID: "CVE-2019-3", Severity: "Low", FixState: "not-fixed", KEV: true, Verdict: U},
		model.Finding{PackageName: "baz", VulnID: "CVE-2019-4", Severity: "Low", FixState: "fixed", Verdict: model.VerdictNotExploitable},
		model.Finding{PackageName: "expl", VulnID: "CVE-2019-5", Severity: "Low", Verdict: model.VerdictExploitable})
	e.seedAll(h, fs...)
	return h
}

func TestGroupedFindingsPage(t *testing.T) {
	e := newEnv(t, true)
	seedDemoShape(e)
	b := e.body(nil, "/findings")
	if n := strings.Count(b, `href="/vulns/CVE-2024-6387"`); n != 1 {
		t.Fatalf("expected one grouped row, got %d", n)
	}
	for _, p := range []string{"openssh-client", "openssh-server", "openssh-sftp-server", "3 packages", "9.2p1-2"} {
		if !strings.Contains(b, p) {
			t.Errorf("missing %q", p)
		}
	}
	// default tier: attention only
	for _, id := range []string{"CVE-2019-1", "CVE-2019-2", "CVE-2019-4"} {
		if strings.Contains(b, id) {
			t.Errorf("background %s shown by default", id)
		}
	}
	for _, id := range []string{"CVE-2019-3", "CVE-2019-5"} {
		if !strings.Contains(b, id) {
			t.Errorf("attention %s missing", id)
		}
	}
	if !strings.Contains(b, "needs attention") || !strings.Contains(b, "show all") || !strings.Contains(b, "3 CVEs") {
		t.Errorf("switch/count missing: %s", b)
	}
	// per-package view: three rows for the ssh CVE
	b = e.body(nil, "/findings?view=package")
	if n := strings.Count(b, `>CVE-2024-6387</a>`); n != 3 {
		t.Fatalf("per-package rows = %d", n)
	}
	if strings.Contains(b, "CVE-2019-1") {
		t.Error("per-package view ignored the tier default")
	}
}

func TestTierDefaultAndExplicitFilters(t *testing.T) {
	e := newEnv(t, true)
	h := seedDemoShape(e)
	has := func(path, id string) bool { return strings.Contains(e.body(nil, path), id) }
	if has("/findings", "CVE-2019-1") {
		t.Error("default shows background")
	}
	for _, p := range []string{
		"/findings?tier=all", "/findings?tier=background", "/findings?q=CVE-2019-1", "/findings?verdict=conditions_unknown",
		"/findings?host=" + h.ID, "/findings?resolved=1",
	} {
		if !has(p, "CVE-2019-1") {
			t.Errorf("%s hides CVE-2019-1", p)
		}
	}
	if has("/findings?tier=background", `href="/vulns/CVE-2024-6387"`) {
		t.Error("background shows attention")
	}
	if has("/findings?label=prod", "CVE-2019-1") || has("/findings?kev=0", "CVE-2019-1") {
		t.Error("label/kev filters must keep the attention default")
	}
	// backward compatible e2e query
	b := e.body(nil, "/findings?q="+url.QueryEscape("CVE-2024-6387")+"&resolved=1")
	if !strings.Contains(b, "alpha") || !strings.Contains(b, "CVE-2024-6387") {
		t.Error("e2e query lost the finding")
	}
	// host page: attention default, show-all link
	if b := e.body(nil, "/hosts/"+h.ID); strings.Contains(b, "CVE-2019-1") || !strings.Contains(b, "CVE-2024-6387") {
		t.Error("host page tier default wrong")
	}
	if !has("/hosts/"+h.ID+"?tier=all", "CVE-2019-1") || !has("/hosts/"+h.ID+"?all=1", "CVE-2019-1") {
		t.Error("host page show-all wrong")
	}
}

func TestDashboardAndHostsCounts(t *testing.T) {
	e := newEnv(t, true)
	h := seedDemoShape(e)
	h2 := e.seedHost("beta")
	e.seedAll(h2, model.Finding{PackageName: "libc6", VulnID: "CVE-2019-1", Severity: "High", FixState: "not-fixed", Verdict: model.VerdictConditionsUnknown})
	b := e.body(nil, "/")
	if card(t, b, "Exploitable") != 1 || card(t, b, "Needs attention") != 2 || card(t, b, "Background") != 3 ||
		card(t, b, "Not exploitable") != 1 || card(t, b, "Hosts") != 2 {
		t.Fatalf("dashboard counts wrong: %s", b)
	}
	if !strings.Contains(b, "Counts are per CVE per host") || !strings.Contains(b, "EPSS below 10%") {
		t.Error("explainer missing")
	}
	if strings.Contains(b, "CVE-2019-1") {
		t.Error("background in dashboard top list")
	}
	// KEV first among unknowns, exploitable on top
	if i, j := strings.Index(b, "CVE-2019-5"), strings.Index(b, "CVE-2019-3"); i < 0 || j < 0 || i > j {
		t.Error("top list order wrong")
	}
	hb := e.body(nil, "/hosts")
	m := regexp.MustCompile(`href="/hosts/` + h.ID + `">alpha</a>.*?</tr>`).FindString(strings.ReplaceAll(hb, "\n", " "))
	if !strings.Contains(m, ">1</span>") || !strings.Contains(m, ">2</span>") || !strings.Contains(m, `class="num muted">2<`) {
		t.Errorf("hosts row: %s", m)
	}
	if !strings.Contains(hb, "Attention") || !strings.Contains(hb, "Background") {
		t.Error("hosts columns missing")
	}
}

func TestVulnPageGroupsByHost(t *testing.T) {
	e := newEnv(t, true)
	seedDemoShape(e)
	h2 := e.seedHost("beta")
	e.seedAll(h2, model.Finding{PackageName: "openssh-client", VulnID: "CVE-2024-6387", Severity: "High", Verdict: model.VerdictConditionsUnknown})
	b := e.body(nil, "/vulns/CVE-2024-6387")
	if !strings.Contains(b, "2 hosts") || !strings.Contains(b, "4 affected package instances") || !strings.Contains(b, "openssh-sftp-server") {
		t.Errorf("vuln page: %s", b)
	}
}

func TestParseFilterTier(t *testing.T) {
	cases := map[string]string{
		"": "attention", "tier=all": "", "tier=background": "background", "label=x&kev=1": "attention",
		"q=CVE-1": "", "verdict=exploitable": "", "resolved=1": "", "host=h": "", "tier=attention&q=CVE-1": "attention", "tier=junk": "attention",
	}
	for qs, want := range cases {
		q, _ := url.ParseQuery(qs)
		if f, _ := parseFilter(q); f.Tier != want {
			t.Errorf("%q: tier %q want %q", qs, f.Tier, want)
		}
	}
}
