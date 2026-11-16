package rules

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"panoptes/internal/model"
	"panoptes/internal/server/core"
)

const shippedRules = "../../../rules"

func loadShipped(t *testing.T) []model.Rule {
	t.Helper()
	rs, err := LoadDir(shippedRules)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(rs) < 8 {
		t.Fatalf("expected >= 8 shipped rules, got %d", len(rs))
	}
	for _, r := range rs {
		if err := Validate(r); err != nil {
			t.Errorf("shipped rule invalid: %v", err)
		}
	}
	return rs
}

func shippedEngine(t *testing.T) *Engine {
	t.Helper()
	e := New(loadShipped(t), nil)
	if p := e.Problems(); len(p) > 0 {
		t.Fatalf("problems: %v", p)
	}
	return e
}

// jsonFacts round-trips through JSON so numbers become float64 like on the wire.
func jsonFacts(t *testing.T, f map[string]any) model.Facts {
	t.Helper()
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	var out model.Facts
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func eval(t *testing.T, e *Engine, vuln, pkg, typ string, facts map[string]any) core.Evaluation {
	t.Helper()
	hc := core.HostContext{
		Host:  model.Host{Hostname: "h1", Labels: []string{"prod"}, OS: model.OSInfo{ID: "debian", VersionID: "12", Arch: "amd64", Kernel: "6.1.0"}},
		Facts: jsonFacts(t, facts),
	}
	f := model.Finding{VulnID: vuln, PackageName: pkg, PackageType: typ, PackageVer: "1.0", Target: "host", TargetKind: model.TargetHost}
	return e.Evaluate(context.Background(), hc, f)
}

func want(t *testing.T, ev core.Evaluation, v model.Verdict, reasonSub ...string) {
	t.Helper()
	if ev.Verdict != v {
		t.Fatalf("verdict = %s (%s), want %s", ev.Verdict, ev.Reason, v)
	}
	for _, s := range reasonSub {
		if !strings.Contains(ev.Reason, s) {
			t.Errorf("reason %q lacks %q", ev.Reason, s)
		}
	}
}

func TestShippedRulesLoad(t *testing.T) { shippedEngine(t) }

func TestCVE20246387(t *testing.T) {
	e := shippedEngine(t)
	cfg := func(lgt string) map[string]any {
		return map[string]any{"sshd.config": map[string]any{"logingracetime": lgt}}
	}
	mk := func(libc string, c map[string]any) map[string]any {
		c["os.libc"] = libc
		return c
	}
	ev := eval(t, e, "CVE-2024-6387", "openssh-server", "deb", mk("glibc", cfg("120")))
	want(t, ev, model.VerdictExploitable, "os.libc=glibc", "sshd.config.logingracetime=120")
	if ev.Rule == nil || ev.Rule.ID != "CVE-2024-6387" || ev.RuleStatus != model.RuleReviewed {
		t.Errorf("rule info: %+v", ev)
	}
	want(t, eval(t, e, "CVE-2024-6387", "openssh-server", "deb", mk("glibc", cfg("0"))), model.VerdictNotExploitable)
	want(t, eval(t, e, "CVE-2024-6387", "openssh-server", "apk", mk("musl", cfg("120"))), model.VerdictNotExploitable)
	// sshd.config missing
	ev = eval(t, e, "CVE-2024-6387", "openssh-server", "deb", map[string]any{"os.libc": "glibc"})
	want(t, ev, model.VerdictConditionsUnknown, "sshd.config")
	// key missing from config -> default 120
	want(t, eval(t, e, "CVE-2024-6387", "openssh-server", "deb", mk("glibc", map[string]any{"sshd.config": map[string]any{}})), model.VerdictExploitable, "<unset>")
	// different package: no rule
	ev = eval(t, e, "CVE-2024-6387", "openssh-client", "deb", mk("glibc", cfg("120")))
	want(t, ev, model.VerdictConditionsUnknown, "no rule")
	if ev.Rule != nil {
		t.Error("Rule must be nil without a match")
	}
	// wrong type (python) -> no rule
	want(t, eval(t, e, "CVE-2024-6387", "openssh-server", "python", mk("glibc", cfg("120"))), model.VerdictConditionsUnknown, "no rule")
	// alias matching
	hc := core.HostContext{Facts: jsonFacts(t, mk("glibc", cfg("120")))}
	ev = e.Evaluate(context.Background(), hc, model.Finding{VulnID: "GHSA-xxxx", Aliases: []string{"CVE-2024-6387"}, PackageName: "openssh-server", PackageType: "rpm"})
	want(t, ev, model.VerdictExploitable)
}

func TestCVE202348795(t *testing.T) {
	e := shippedEngine(t)
	debian12 := "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com"
	f := func(c, m string) map[string]any {
		return map[string]any{"sshd.config": map[string]any{"ciphers": c, "macs": m}}
	}
	want(t, eval(t, e, "CVE-2023-48795", "openssh-server", "deb", f(debian12, "hmac-sha2-256")), model.VerdictExploitable, "sshd.config.ciphers=chacha20")
	want(t, eval(t, e, "CVE-2023-48795", "openssh-server", "deb", f("aes256-ctr,aes256-gcm@openssh.com", "hmac-sha2-256-etm@openssh.com")), model.VerdictNotExploitable)
	want(t, eval(t, e, "CVE-2023-48795", "openssh-server", "deb", f("aes128-cbc", "hmac-sha2-256-etm@openssh.com")), model.VerdictExploitable)
	want(t, eval(t, e, "CVE-2023-48795", "openssh-server", "deb", f("aes128-cbc", "hmac-sha2-256")), model.VerdictNotExploitable)
	// keys absent entirely
	want(t, eval(t, e, "CVE-2023-48795", "openssh-server", "deb", map[string]any{"sshd.config": map[string]any{}}), model.VerdictNotExploitable)
}

func TestCVE202344487(t *testing.T) {
	e := shippedEngine(t)
	want(t, eval(t, e, "CVE-2023-44487", "nginx", "deb", map[string]any{"nginx.http2": true}), model.VerdictExploitable, "nginx.http2=true")
	want(t, eval(t, e, "CVE-2023-44487", "nginx-common", "deb", map[string]any{"nginx.http2": false}), model.VerdictNotExploitable)
	// apache package uses the apache rule: nginx facts are irrelevant
	ev := eval(t, e, "CVE-2023-44487", "apache2", "deb", map[string]any{"nginx.http2": true, "apache.http2": false})
	want(t, ev, model.VerdictNotExploitable)
	if ev.Rule.ID != "CVE-2023-44487-apache" {
		t.Errorf("rule = %s", ev.Rule.ID)
	}
	ev = eval(t, e, "CVE-2023-44487", "apache2-bin", "deb", map[string]any{"apache.http2": true})
	want(t, ev, model.VerdictExploitable)
	want(t, eval(t, e, "CVE-2023-44487", "httpd", "rpm", map[string]any{"apache.http2": true}), model.VerdictExploitable)
	// apache2 as rpm does not match (deb only)
	want(t, eval(t, e, "CVE-2023-44487", "apache2", "rpm", map[string]any{"apache.http2": true}), model.VerdictConditionsUnknown, "no rule")
	// nginx fact missing
	want(t, eval(t, e, "CVE-2023-44487", "nginx", "deb", map[string]any{}), model.VerdictConditionsUnknown, "nginx.http2")
}

func TestCVE20241086(t *testing.T) {
	e := shippedEngine(t)
	k := func(m map[string]any) map[string]any { return map[string]any{"kernel.sysctl": m} }
	want(t, eval(t, e, "CVE-2024-1086", "linux-image-6.1.0-18-amd64", "deb", k(map[string]any{})), model.VerdictExploitable)
	want(t, eval(t, e, "CVE-2024-1086", "linux-image-6.1.0-18-amd64", "deb", k(map[string]any{"kernel.unprivileged_userns_clone": "0"})), model.VerdictNotExploitable, "kernel.unprivileged_userns_clone=0")
	want(t, eval(t, e, "CVE-2024-1086", "kernel-core", "rpm", k(map[string]any{"user.max_user_namespaces": "0"})), model.VerdictNotExploitable)
	want(t, eval(t, e, "CVE-2024-1086", "linux-lts", "apk", k(map[string]any{"user.max_user_namespaces": "63000", "kernel.apparmor_restrict_unprivileged_userns": "1"})), model.VerdictNotExploitable)
	want(t, eval(t, e, "CVE-2024-1086", "linux-image-x", "deb", map[string]any{}), model.VerdictConditionsUnknown, "kernel.sysctl")
}

func TestCVE202421626(t *testing.T) {
	e := shippedEngine(t)
	want(t, eval(t, e, "CVE-2024-21626", "runc", "deb", map[string]any{"services.active": []any{"ssh", "docker"}}), model.VerdictExploitable)
	want(t, eval(t, e, "CVE-2024-21626", "runc", "deb", map[string]any{"services.active": []any{"ssh", "cron"}}), model.VerdictNotExploitable)
	want(t, eval(t, e, "CVE-2024-21626", "containerd.io", "deb", map[string]any{"services.active": []any{}}), model.VerdictNotExploitable)
}

func TestCVE20243094(t *testing.T) {
	e := shippedEngine(t)
	f := map[string]any{"os.libc": "glibc", "services.active": []any{"ssh"}}
	want(t, eval(t, e, "CVE-2024-3094", "liblzma5", "deb", f), model.VerdictExploitable)
	f["os.libc"] = "musl"
	want(t, eval(t, e, "CVE-2024-3094", "xz-utils", "deb", f), model.VerdictNotExploitable)
}

func TestCVE20244577(t *testing.T) {
	e := shippedEngine(t)
	ev := eval(t, e, "CVE-2024-4577", "php8.2-cgi", "deb", map[string]any{"os.id": "debian"})
	want(t, ev, model.VerdictNotExploitable, "os.id=debian")
	want(t, eval(t, e, "CVE-2024-4577", "php8.2-cgi", "deb", map[string]any{}), model.VerdictConditionsUnknown, "os.id")
}

func TestFactRequestsUnionAndFileMatch(t *testing.T) {
	r := validRule()
	r.ID = "X-1"
	r.Facts = []string{"file.match:proxy"}
	r.FactRequests = []model.FactRequest{{Name: "file.match:proxy", Collector: "file.match", Params: map[string]string{"path": "/etc/apache2/*.conf", "pattern": "ProxyPass"}}}
	r.ExploitableIf = `size(facts["file.match:proxy"]) > 0`
	r2 := r
	r2.ID = "X-2"
	r2.Vulns = []string{"CVE-2000-0002"}
	e := New(append(loadShipped(t), r, r2), nil)
	if p := e.Problems(); len(p) != 0 {
		t.Fatal(p)
	}
	frs := e.FactRequests()
	if len(frs) != 1 || frs[0].Name != "file.match:proxy" {
		t.Fatalf("fact requests: %+v", frs)
	}
	ev := eval(t, e, "CVE-2000-0001", "pkg", "deb", map[string]any{"file.match:proxy": []any{"/etc/apache2/a.conf:ProxyPass /"}})
	want(t, ev, model.VerdictExploitable, "file.match:proxy=")
	want(t, eval(t, e, "CVE-2000-0001", "pkg", "deb", map[string]any{}), model.VerdictConditionsUnknown, "file.match:proxy")
}

func TestIntPortsFromJSON(t *testing.T) {
	r := validRule()
	r.Facts = []string{"sockets.ports"}
	r.ExploitableIf = `22 in facts["sockets.ports"]`
	e := New([]model.Rule{r}, nil)
	if p := e.Problems(); len(p) != 0 {
		t.Fatal(p)
	}
	want(t, eval(t, e, "CVE-2000-0001", "pkg", "deb", map[string]any{"sockets.ports": []any{22, 80}}), model.VerdictExploitable)
	want(t, eval(t, e, "CVE-2000-0001", "pkg", "deb", map[string]any{"sockets.ports": []any{80}}), model.VerdictNotExploitable)
}

func TestNotAffectedIfAndPkgHostVars(t *testing.T) {
	r := validRule()
	r.Facts = []string{"os.id"}
	r.NotAffectedIf = `version_ge(pkg.version, "2.0") && host.arch == "amd64" && "prod" in host.labels`
	r.ExploitableIf = `true`
	e := New([]model.Rule{r}, nil)
	hc := core.HostContext{Host: model.Host{Labels: []string{"prod"}, OS: model.OSInfo{Arch: "amd64"}}, Facts: model.Facts{"os.id": "debian"}}
	ev := e.Evaluate(context.Background(), hc, model.Finding{VulnID: "CVE-2000-0001", PackageName: "pkg", PackageVer: "2.1"})
	want(t, ev, model.VerdictNotExploitable, "not_affected_if")
	ev = e.Evaluate(context.Background(), hc, model.Finding{VulnID: "CVE-2000-0001", PackageName: "pkg", PackageVer: "1.9"})
	want(t, ev, model.VerdictExploitable)
}

func TestExpressionError(t *testing.T) {
	r := validRule()
	r.Facts = []string{"kernel.sysctl"}
	r.ExploitableIf = `facts["kernel.sysctl"]["nope"] == "1"` // missing key -> runtime error
	e := New([]model.Rule{r}, nil)
	ev := eval(t, e, "CVE-2000-0001", "pkg", "deb", map[string]any{"kernel.sysctl": map[string]any{}})
	want(t, ev, model.VerdictConditionsUnknown, "error")
}

func TestPathologicalCostAndTimeout(t *testing.T) {
	list := "[" + strings.TrimSuffix(strings.Repeat("1,", 40), ",") + "]"
	r := validRule()
	r.Facts = []string{"os.id"}
	r.ExploitableIf = list + `.exists(a, ` + list + `.exists(b, ` + list + `.exists(c, ` + list + `.exists(d, a+b+c+d > 1000))))`
	e := New([]model.Rule{r}, nil)
	if p := e.Problems(); len(p) != 0 {
		t.Fatal(p)
	}
	ev := eval(t, e, "CVE-2000-0001", "pkg", "deb", map[string]any{"os.id": "x"})
	want(t, ev, model.VerdictConditionsUnknown, "error")

	// timeout path: an already-expired context must abort evaluation
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r2 := validRule()
	r2.Facts = []string{"os.id"}
	r2.ExploitableIf = `[1,2,3,4,5,6,7,8,9,10].all(a, [1,2,3,4,5,6,7,8,9,10].all(b, [1,2,3,4,5,6,7,8,9,10].all(c, a+b+c > 0)))`
	e2 := New([]model.Rule{r2}, nil)
	ev = e2.Evaluate(ctx, core.HostContext{Facts: model.Facts{"os.id": "x"}}, model.Finding{VulnID: "CVE-2000-0001", PackageName: "pkg"})
	want(t, ev, model.VerdictConditionsUnknown, "error")
}

// --- DB source, override, rejected ---

type fakeDB struct {
	mu    sync.Mutex
	rules []model.Rule
	err   error
}

func (f *fakeDB) ListRules(context.Context) ([]model.Rule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rules, f.err
}

func TestDBOverrideAndRejected(t *testing.T) {
	files := loadShipped(t)
	db := &fakeDB{}
	e := New(files, db)
	nginx := map[string]any{"nginx.http2": true}
	want(t, eval(t, e, "CVE-2023-44487", "nginx", "deb", nginx), model.VerdictExploitable)

	// DB rule with same ID overrides the file rule.
	var o model.Rule
	for _, r := range files {
		if r.ID == "CVE-2023-44487-nginx" {
			o = r
		}
	}
	o.ExploitableIf = `false`
	o.Status = model.RuleDraft
	o.Source = "user"
	db.rules = []model.Rule{o}
	if err := e.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	ev := eval(t, e, "CVE-2023-44487", "nginx", "deb", nginx)
	want(t, ev, model.VerdictNotExploitable)
	if ev.RuleStatus != model.RuleDraft {
		t.Errorf("status = %s", ev.RuleStatus)
	}

	// A DB rule with a different ID for the same CVE/package beats the file rule too.
	o2 := o
	o2.ID = "AAA-other"
	o2.ExploitableIf = `true`
	o.Status = model.RuleRejected
	db.rules = []model.Rule{o2}
	_ = e.Reload(context.Background())
	ev = eval(t, e, "CVE-2023-44487", "nginx", "deb", map[string]any{"nginx.http2": false})
	want(t, ev, model.VerdictExploitable)
	if ev.Rule.ID != "AAA-other" {
		t.Errorf("rule = %s", ev.Rule.ID)
	}

	// Rejected DB rule suppresses the file rule with the same ID.
	o.Status = model.RuleRejected
	db.rules = []model.Rule{o}
	_ = e.Reload(context.Background())
	want(t, eval(t, e, "CVE-2023-44487", "nginx", "deb", nginx), model.VerdictConditionsUnknown, "no rule")
	if got := e.Lookup("CVE-2023-44487"); len(got) != 2 {
		t.Errorf("Lookup returned %d rules, want 2 (apache + rejected nginx)", len(got))
	}
	if len(e.Rules()) != len(files) {
		t.Errorf("Rules() = %d", len(e.Rules()))
	}

	// Invalid DB rule is skipped, reported, and the file rule stays.
	bad := o
	bad.Status = model.RuleDraft
	bad.ExploitableIf = `this is not cel (`
	db.rules = []model.Rule{bad}
	_ = e.Reload(context.Background())
	if p := e.Problems(); len(p) != 1 || p[0].Source != "db" || p[0].RuleID != "CVE-2023-44487-nginx" {
		t.Fatalf("problems: %v", p)
	}
	want(t, eval(t, e, "CVE-2023-44487", "nginx", "deb", nginx), model.VerdictExploitable)

	// DB read error is returned and file rules still work.
	db.err = errors.New("boom")
	db.rules = nil
	if err := e.Reload(context.Background()); err == nil {
		t.Error("expected reload error")
	}
	want(t, eval(t, e, "CVE-2023-44487", "nginx", "deb", nginx), model.VerdictExploitable)
}

func TestRejectedFileRuleIgnored(t *testing.T) {
	r := validRule()
	r.Status = model.RuleRejected
	e := New([]model.Rule{r}, nil)
	want(t, eval(t, e, "CVE-2000-0001", "pkg", "deb", map[string]any{"os.id": "x"}), model.VerdictConditionsUnknown, "no rule")
	if len(e.FactRequests()) != 0 {
		t.Error("rejected rule must not contribute fact requests")
	}
}

func TestConcurrentEvaluate(t *testing.T) {
	e := shippedEngine(t)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				ev := eval(t, e, "CVE-2023-44487", "nginx", "deb", map[string]any{"nginx.http2": true})
				if ev.Verdict != model.VerdictExploitable {
					t.Error(ev)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// --- Validate ---

func validRule() model.Rule {
	return model.Rule{
		ID: "TEST-1", Vulns: []string{"CVE-2000-0001"}, Title: "t",
		Packages: []model.PackageSelector{{Name: "pkg*"}},
		Facts:    []string{"os.id"}, ExploitableIf: `facts["os.id"] == "x"`,
		Explanation: "e", Status: model.RuleReviewed, Source: "user",
	}
}

func TestValidate(t *testing.T) {
	if err := Validate(validRule()); err != nil {
		t.Fatalf("valid rule rejected: %v", err)
	}
	cases := []struct {
		name string
		mut  func(*model.Rule)
		sub  string
	}{
		{"empty id", func(r *model.Rule) { r.ID = "" }, "id is required"},
		{"no vulns", func(r *model.Rule) { r.Vulns = nil }, "vulns"},
		{"no packages", func(r *model.Rule) { r.Packages = nil }, "package selector"},
		{"bad glob", func(r *model.Rule) { r.Packages = []model.PackageSelector{{Name: "[abc"}} }, "invalid glob"},
		{"unknown fact", func(r *model.Rule) { r.Facts = []string{"os.nope"} }, `unknown fact "os.nope"`},
		{"bad cel", func(r *model.Rule) { r.ExploitableIf = `facts["os.id" ==` }, "exploitable_if"},
		{"non-bool", func(r *model.Rule) { r.ExploitableIf = `"a" + "b"` }, "must return bool"},
		{"bad not_affected_if", func(r *model.Rule) { r.NotAffectedIf = `1 + 1` }, "not_affected_if"},
		{"undeclared file.match", func(r *model.Rule) {
			r.Facts = []string{"file.match:x"}
			r.ExploitableIf = `true`
		}, "not declared in fact_requests"},
		{"wrong collector", func(r *model.Rule) {
			r.Facts = []string{"file.match:x"}
			r.FactRequests = []model.FactRequest{{Name: "file.match:x", Collector: "exec", Params: map[string]string{"path": "/etc/a", "pattern": "a"}}}
		}, "collector"},
		{"missing params", func(r *model.Rule) {
			r.Facts = []string{"file.match:x"}
			r.FactRequests = []model.FactRequest{{Name: "file.match:x", Collector: "file.match", Params: map[string]string{"path": "/etc/a"}}}
		}, "params.pattern"},
		{"bad regexp", func(r *model.Rule) {
			r.FactRequests = []model.FactRequest{{Name: "file.match:x", Collector: "file.match", Params: map[string]string{"path": "/etc/a", "pattern": "("}}}
		}, "RE2"},
		{"undeclared fact in expr", func(r *model.Rule) { r.ExploitableIf = `facts["os.libc"] == "glibc"` }, "not listed in facts"},
		{"bad status", func(r *model.Rule) { r.Status = "maybe" }, "status"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := validRule()
			c.mut(&r)
			err := Validate(r)
			if err == nil || !strings.Contains(err.Error(), c.sub) {
				t.Fatalf("err = %v, want containing %q", err, c.sub)
			}
		})
	}
	// multiple problems are all reported
	r := validRule()
	r.ID, r.Vulns, r.Facts = "", nil, []string{"bogus"}
	var ve *ValidationError
	if err := Validate(r); !errors.As(err, &ve) || len(ve.Problems) < 3 {
		t.Fatalf("want >=3 problems, got %v", err)
	}
}

func TestLoadDirStrictAndParse(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := writeFile(dir, name, body); err != nil {
			t.Fatal(err)
		}
	}
	write("ok.yaml", "id: A\nvulns: [CVE-1]\n")
	write("bad.yaml", "id: B\nunknown_key: 1\n")
	rs, err := LoadDir(dir)
	if err == nil || !strings.Contains(err.Error(), "bad.yaml") {
		t.Fatalf("err = %v", err)
	}
	if len(rs) != 1 || rs[0].ID != "A" {
		t.Fatalf("rules = %+v", rs)
	}
	if _, err := LoadDir(dir + "/missing"); err == nil {
		t.Error("expected error for missing dir")
	}
}

// --- version functions ---

func TestVersionCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"6.1.10", "6.10.0", -1},
		{"1.0", "1.0.0", 0},
		{"1.2", "1.10", -1},
		{"9.2p1", "9.2", 1},
		{"1:9.2p1-2", "9.8p1", 1}, // epoch wins
		{"1:9.2p1-2", "2:1.0", -1},
		{"1:9.2", "1:9.2", 0},
		{"5.6.1", "5.6.2", -1},
		{"5.6.1-2+deb12u1", "5.6.1-2", 1},
		{"007", "7", 0},
		{"1.0a", "1.0b", -1},
		{"", "0", 0},
	}
	for _, c := range cases {
		if got := versionCompare(c.a, c.b); got != c.want {
			t.Errorf("versionCompare(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := versionCompare(c.b, c.a); got != -c.want {
			t.Errorf("versionCompare(%q,%q) = %d, want %d", c.b, c.a, got, -c.want)
		}
	}
}

func TestCELFunctions(t *testing.T) {
	r := validRule()
	r.Facts = []string{"kernel.modules"}
	r.ExploitableIf = `version_lt("6.1.10", "6.10.0") && version_ge("1:2.0", "3.0") && has_module(facts["kernel.modules"], "nf_tables") && !has_module(facts["kernel.modules"], "x")`
	e := New([]model.Rule{r}, nil)
	if p := e.Problems(); len(p) != 0 {
		t.Fatal(p)
	}
	want(t, eval(t, e, "CVE-2000-0001", "pkg", "deb", map[string]any{"kernel.modules": []any{"nf_tables", "ext4"}}), model.VerdictExploitable)
	want(t, eval(t, e, "CVE-2000-0001", "pkg", "deb", map[string]any{"kernel.modules": []any{"ext4"}}), model.VerdictNotExploitable)
}
