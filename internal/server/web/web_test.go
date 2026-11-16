package web

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"panoptes/internal/model"
	"panoptes/internal/server/config"
	"panoptes/internal/server/store"
)

type fakeRules struct {
	mu          sync.Mutex
	rules       []model.Rule
	validateErr error
	validated   []model.Rule
	reloads     int
}

func (f *fakeRules) Rules() []model.Rule {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]model.Rule(nil), f.rules...)
}
func (f *fakeRules) Validate(r model.Rule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.validated = append(f.validated, r)
	return f.validateErr
}
func (f *fakeRules) Reload(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reloads++
	return nil
}

type fakeTrig struct {
	mu sync.Mutex
	n  int
}

func (f *fakeTrig) TriggerAll() { f.mu.Lock(); f.n++; f.mu.Unlock() }
func (f *fakeTrig) count() int  { f.mu.Lock(); defer f.mu.Unlock(); return f.n }

type env struct {
	t     *testing.T
	st    *store.SQLite
	rules *fakeRules
	trig  *fakeTrig
	srv   *Server
	mux   *http.ServeMux
}

const draftYAML = `id: CVE-2024-1
vulns: [CVE-2024-1]
title: Test rule
packages:
  - {name: foo}
facts: [os.id]
exploitable_if: 'facts["os.id"] == "debian"'
explanation: because
status: draft
source: "llm:test"
`

func newEnv(t *testing.T, withRules bool) *env {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	e := &env{t: t, st: st, rules: &fakeRules{}, trig: &fakeTrig{}}
	e.rules.rules = []model.Rule{{
		ID: "CVE-2024-1", Vulns: []string{"CVE-2024-1"}, Title: "Test rule", Packages: []model.PackageSelector{{Name: "foo"}},
		Facts: []string{"os.id"}, ExploitableIf: `facts["os.id"] == "debian"`, Explanation: "because", Status: model.RuleDraft, Source: "llm:test",
	}}
	cfg := config.Default()
	cfg.PublicURL = "http://panoptes.test"
	d := Deps{Store: st, Pipeline: e.trig, Config: &cfg, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if withRules {
		d.Rules = e.rules
	}
	e.srv, err = New(d)
	if err != nil {
		t.Fatal(err)
	}
	e.mux = http.NewServeMux()
	e.srv.Mount(e.mux)
	return e
}

func (e *env) addUser(name, pw string) {
	e.t.Helper()
	h, _ := store.HashPassword(pw)
	if err := e.st.CreateUser(context.Background(), name, h); err != nil {
		e.t.Fatal(err)
	}
}

// session creates a session directly in the store and returns its cookie.
func (e *env) session(user string) *http.Cookie {
	e.t.Helper()
	if _, err := e.st.GetUser(context.Background(), user); err != nil {
		e.addUser(user, "pw-long-enough")
	}
	tok, hash, _ := store.NewSecret("ps_")
	now := time.Now()
	if err := e.st.CreateSession(context.Background(), store.Session{TokenHash: hash, Username: user, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		e.t.Fatal(err)
	}
	return &http.Cookie{Name: cookieName, Value: tok}
}

func (e *env) do(method, path string, form url.Values, c *http.Cookie, hdr ...string) *httptest.ResponseRecorder {
	e.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	r := httptest.NewRequest(method, path, body)
	r.RemoteAddr = "192.0.2.1:1234"
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if c != nil {
		r.AddCookie(c)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, r)
	return w
}

func (e *env) csrf(c *http.Cookie) string { return e.srv.csrfFor(c.Value) }

func (e *env) post(path string, form url.Values, c *http.Cookie) *httptest.ResponseRecorder {
	if form == nil {
		form = url.Values{}
	}
	form.Set("csrf", e.csrf(c))
	if form.Get("current_password") == "" {
		form.Set("current_password", "pw-long-enough")
	}
	return e.do("POST", path, form, c)
}

// postNoAuth posts without adding the acting user's current password.
func (e *env) postNoAuth(path string, form url.Values, c *http.Cookie) *httptest.ResponseRecorder {
	form.Set("csrf", e.csrf(c))
	return e.do("POST", path, form, c)
}

func (e *env) seedHost(hostname string, labels ...string) model.Host {
	e.t.Helper()
	ctx := context.Background()
	_, hash, _ := store.NewSecret("pa_")
	h, err := e.st.EnrollHost(ctx, store.EnrollParams{MachineID: "m-" + hostname, Hostname: hostname, Labels: labels, KeyHash: hash})
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.st.ApplyCheckin(ctx, h.ID, model.CheckinRequest{Hostname: hostname, Labels: labels, AgentVersion: "1.0",
		OS: model.OSInfo{ID: "debian", PrettyName: "Debian 12"}, Facts: model.Facts{"os.id": "debian"}, FactsComplete: true}, time.Now()); err != nil {
		e.t.Fatal(err)
	}
	return h
}

func (e *env) seedFinding(h model.Host, vuln string, v model.Verdict, kev bool) model.Finding {
	e.t.Helper()
	f := model.Finding{HostID: h.ID, Target: "host", TargetKind: model.TargetHost, PackageName: "foo", PackageVer: "1.0", PackageType: "deb",
		VulnID: vuln, Severity: "High", CVSS: 7.5, KEV: kev, Verdict: v, VerdictReason: "os.id=debian", RuleID: "CVE-2024-1",
		FixedVersions: []string{"1.1"}, FixState: "fixed"}
	res, err := e.st.ApplyHostFindings(context.Background(), h.ID, append(e.existing(h), f), time.Now())
	if err != nil {
		e.t.Fatal(err)
	}
	for _, c := range res.Current {
		if c.VulnID == vuln {
			return c
		}
	}
	e.t.Fatal("finding not stored")
	return f
}

func (e *env) existing(h model.Host) []model.Finding {
	fs, _ := e.st.HostFindings(context.Background(), h.ID)
	var out []model.Finding
	for _, f := range fs {
		if f.Verdict != model.VerdictResolved {
			out = append(out, f)
		}
	}
	return out
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([0-9a-f]+)"`)

func TestUnauthenticatedRedirects(t *testing.T) {
	e := newEnv(t, true)
	for _, p := range []string{"/", "/hosts", "/hosts/x", "/findings", "/findings/1", "/vulns/CVE-1", "/rules", "/rules/x", "/settings"} {
		w := e.do("GET", p, nil, nil)
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
			t.Errorf("%s: got %d %q", p, w.Code, w.Header().Get("Location"))
		}
	}
	w := e.do("POST", "/rules/x/approve", url.Values{}, nil)
	if w.Code != http.StatusSeeOther {
		t.Errorf("unauth POST: %d", w.Code)
	}
}

func TestLoginFlow(t *testing.T) {
	e := newEnv(t, true)
	e.addUser("admin", "correct-horse")

	// get form + csrf cookie
	w := e.do("GET", "/login", nil, nil)
	if w.Code != 200 {
		t.Fatalf("login form %d", w.Code)
	}
	m := csrfRe.FindStringSubmatch(w.Body.String())
	if m == nil {
		t.Fatal("no csrf on login form")
	}
	var lc *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == loginCSRFName {
			lc = c
		}
	}
	if lc == nil {
		t.Fatal("no login csrf cookie")
	}
	login := func(user, pw, tok string) *httptest.ResponseRecorder {
		return e.do("POST", "/login", url.Values{"username": {user}, "password": {pw}, "csrf": {tok}}, lc)
	}

	// missing/incorrect CSRF -> 403
	if w := login("admin", "correct-horse", "bogus"); w.Code != 403 {
		t.Errorf("bad csrf: %d", w.Code)
	}
	// wrong password -> 401, no session cookie
	w = login("admin", "wrong", m[1])
	if w.Code != 401 {
		t.Errorf("wrong pw: %d", w.Code)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieName && c.Value != "" {
			t.Error("session cookie set on failure")
		}
	}
	// unknown user -> 401
	if w := login("nobody", "whatever1", m[1]); w.Code != 401 {
		t.Errorf("unknown user: %d", w.Code)
	}
	// success
	w = login("admin", "correct-horse", m[1])
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
		t.Fatalf("login: %d %q", w.Code, w.Header().Get("Location"))
	}
	var sc *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieName && c.Value != "" {
			sc = c
		}
	}
	if sc == nil || !sc.HttpOnly || sc.SameSite != http.SameSiteLaxMode || sc.Secure {
		t.Fatalf("bad session cookie %+v", sc)
	}
	// only the hash is stored
	if _, err := e.st.GetSession(context.Background(), store.HashSecret(sc.Value), time.Now()); err != nil {
		t.Fatalf("session not stored by hash: %v", err)
	}
	if _, err := e.st.GetSession(context.Background(), sc.Value, time.Now()); err == nil {
		t.Fatal("plain token stored")
	}
	if w := e.do("GET", "/", nil, sc); w.Code != 200 {
		t.Fatalf("dashboard after login: %d", w.Code)
	}
	// logout invalidates
	if w := e.post("/logout", nil, sc); w.Code != http.StatusSeeOther {
		t.Fatalf("logout %d", w.Code)
	}
	if w := e.do("GET", "/", nil, sc); w.Code != http.StatusSeeOther {
		t.Fatalf("session still valid after logout: %d", w.Code)
	}
}

func TestLoginRateLimitAndSecureCookie(t *testing.T) {
	e := newEnv(t, true)
	e.addUser("admin", "correct-horse")
	lc := &http.Cookie{Name: loginCSRFName, Value: "tok"}
	try := func(pw string) int {
		return e.do("POST", "/login", url.Values{"username": {"admin"}, "password": {pw}, "csrf": {"tok"}}, lc).Code
	}
	for i := 0; i < maxFailures; i++ {
		if c := try("bad"); c != 401 {
			t.Fatalf("attempt %d: %d", i, c)
		}
	}
	if c := try("bad"); c != 429 {
		t.Fatalf("expected 429, got %d", c)
	}
	if c := try("correct-horse"); c != 429 {
		t.Fatalf("correct password must still be blocked while limited, got %d", c)
	}

	// https public URL -> Secure cookie
	cfg := config.Default()
	cfg.PublicURL = "https://panoptes.example.com"
	s, _ := New(Deps{Store: e.st, Config: &cfg})
	if c := s.cookie("x", "v", time.Now().Add(time.Hour)); !c.Secure {
		t.Error("cookie not Secure for https public_url")
	}
}

func TestLimiterWindow(t *testing.T) {
	now := time.Now()
	l := newLimiter(func() time.Time { return now })
	for i := 0; i < maxFailures; i++ {
		l.fail("k")
	}
	if !l.blocked("k") {
		t.Fatal("should be blocked")
	}
	now = now.Add(failWindow + time.Second)
	if l.blocked("k") {
		t.Fatal("should expire")
	}
}

func TestCSRFAndOriginRejected(t *testing.T) {
	e := newEnv(t, true)
	e.addUser("admin", "pw-long-enough")
	c := e.session("admin")
	// no token
	if w := e.do("POST", "/settings/matrix", url.Values{"routes": {"prod = !a:b"}}, c); w.Code != 403 {
		t.Errorf("missing csrf: %d", w.Code)
	}
	// wrong token
	if w := e.do("POST", "/settings/matrix", url.Values{"routes": {"prod = !a:b"}, "csrf": {"nope"}}, c); w.Code != 403 {
		t.Errorf("wrong csrf: %d", w.Code)
	}
	// token of another session
	c2 := e.session("admin")
	if w := e.do("POST", "/settings/matrix", url.Values{"routes": {"prod = !a:b"}, "csrf": {e.csrf(c2)}}, c); w.Code != 403 {
		t.Errorf("foreign csrf: %d", w.Code)
	}
	// cross-origin with valid token
	f := url.Values{"routes": {"prod = !a:b"}, "csrf": {e.csrf(c)}}
	if w := e.do("POST", "/settings/matrix", f, c, "Origin", "http://evil.example"); w.Code != 403 {
		t.Errorf("cross origin: %d", w.Code)
	}
	if w := e.do("POST", "/settings/matrix", f, c, "Sec-Fetch-Site", "cross-site"); w.Code != 403 {
		t.Errorf("cross-site fetch: %d", w.Code)
	}
	if _, err := e.st.GetSetting(context.Background(), matrixSettingKey); err == nil {
		t.Error("setting saved despite rejected requests")
	}
	// same origin passes
	if w := e.do("POST", "/settings/matrix", f, c, "Origin", "http://example.com", "Sec-Fetch-Site", "same-origin"); w.Code != 303 {
		t.Errorf("same origin: %d", w.Code)
	}
}

func TestParseFilter(t *testing.T) {
	q, _ := url.ParseQuery("verdict=exploitable&label=prod&kev=1&q=CVE-2024-6387&host=h1&resolved=1&page=3")
	f, page := parseFilter(q)
	if f.Verdict != model.VerdictExploitable || f.Label != "prod" || f.KEV == nil || !*f.KEV || f.VulnID != "CVE-2024-6387" ||
		f.HostID != "h1" || !f.IncludeResolved || page != 3 || f.Offset != 2*pageSize || f.Limit != pageSize {
		t.Fatalf("bad mapping: %+v page=%d", f, page)
	}
	q, _ = url.ParseQuery("verdict=bogus&kev=0&page=-4")
	f, page = parseFilter(q)
	if f.Verdict != "" || f.KEV == nil || *f.KEV || page != 1 || f.Offset != 0 {
		t.Fatalf("bad defaults: %+v page=%d", f, page)
	}
}

func TestFindingsFilterEndToEnd(t *testing.T) {
	e := newEnv(t, true)
	c := e.session("admin")
	h1 := e.seedHost("alpha", "prod")
	h2 := e.seedHost("beta", "dev")
	e.seedFinding(h1, "CVE-2024-0001", model.VerdictExploitable, true)
	e.seedFinding(h1, "CVE-2024-0002", model.VerdictConditionsUnknown, false)
	e.seedFinding(h2, "CVE-2024-0003", model.VerdictExploitable, false)

	body := func(qs string) string {
		w := e.do("GET", "/findings"+qs, nil, c)
		if w.Code != 200 {
			t.Fatalf("%s: %d", qs, w.Code)
		}
		return w.Body.String()
	}
	b := body("?verdict=exploitable")
	if !strings.Contains(b, "CVE-2024-0001") || !strings.Contains(b, "CVE-2024-0003") || strings.Contains(b, "CVE-2024-0002") {
		t.Error("verdict filter wrong")
	}
	b = body("?label=prod")
	if !strings.Contains(b, "CVE-2024-0001") || strings.Contains(b, "CVE-2024-0003") {
		t.Error("label filter wrong")
	}
	b = body("?kev=1")
	if !strings.Contains(b, "CVE-2024-0001") || strings.Contains(b, "CVE-2024-0002") || strings.Contains(b, "CVE-2024-0003") {
		t.Error("kev filter wrong")
	}
	b = body("?q=CVE-2024-0002")
	if !strings.Contains(b, "CVE-2024-0002") || strings.Contains(b, "CVE-2024-0001") {
		t.Error("vuln filter wrong")
	}
	b = body("?host=" + h2.ID)
	if !strings.Contains(b, "CVE-2024-0003") || strings.Contains(b, "CVE-2024-0001") {
		t.Error("host filter wrong")
	}
}

func TestPagesRender(t *testing.T) {
	e := newEnv(t, true)
	c := e.session("admin")
	h := e.seedHost("alpha", "prod")
	f := e.seedFinding(h, "CVE-2024-1", model.VerdictExploitable, true)
	for _, p := range []string{"/", "/hosts", "/hosts/" + h.ID, "/hosts/" + h.ID + "?all=1", "/findings", "/findings/" + itoa(f.ID),
		"/vulns/CVE-2024-1", "/rules", "/rules?status=draft", "/rules/CVE-2024-1", "/settings"} {
		w := e.do("GET", p, nil, c)
		if w.Code != 200 {
			t.Errorf("%s: %d %s", p, w.Code, w.Body.String())
		}
	}
	// finding detail content
	b := e.do("GET", "/findings/"+itoa(f.ID), nil, c).Body.String()
	for _, want := range []string{"os.id=debian", "apt-get install --only-upgrade foo", "nvd.nist.gov/vuln/detail/CVE-2024-1", "osv.dev/vulnerability/CVE-2024-1", "Test rule"} {
		if !strings.Contains(b, want) {
			t.Errorf("finding page misses %q", want)
		}
	}
	// 404s
	for _, p := range []string{"/hosts/nope", "/findings/99999", "/findings/abc", "/vulns/CVE-9999-9", "/rules/nope", "/nothing-here"} {
		if w := e.do("GET", p, nil, c); w.Code != 404 {
			t.Errorf("%s: want 404 got %d", p, w.Code)
		}
	}
	// the API namespace is not rendered as HTML
	if w := e.do("GET", "/api/unknown", nil, c); w.Code != 404 || strings.Contains(w.Body.String(), "<html") {
		t.Errorf("api 404: %d", w.Code)
	}
	// static assets
	if w := e.do("GET", "/static/style.css", nil, nil); w.Code != 200 || !strings.Contains(w.Body.String(), "prefers-color-scheme") {
		t.Errorf("static css: %d", w.Code)
	}
}

func itoa(i int64) string { return strconv.FormatInt(i, 10) }

func TestRuleEditFlow(t *testing.T) {
	e := newEnv(t, true)
	c := e.session("admin")
	edited := strings.Replace(draftYAML, "title: Test rule", "title: Edited title", 1)
	w := e.post("/rules/CVE-2024-1/edit", url.Values{"yaml": {edited}}, c)
	if w.Code != 303 {
		t.Fatalf("edit: %d %s", w.Code, w.Body.String())
	}
	if len(e.rules.validated) != 1 || e.rules.validated[0].Title != "Edited title" {
		t.Fatalf("Validate not called with edited rule: %+v", e.rules.validated)
	}
	got, err := e.st.GetRule(context.Background(), "CVE-2024-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Title != "Edited title" || got.Source != "user" {
		t.Fatalf("stored: %+v", got)
	}
	if e.rules.reloads != 1 || e.trig.count() != 1 {
		t.Fatalf("reloads=%d triggers=%d", e.rules.reloads, e.trig.count())
	}
}

func TestRuleEditErrors(t *testing.T) {
	e := newEnv(t, true)
	c := e.session("admin")

	// validation error -> 422, shown inline, nothing stored, no reload/trigger
	e.rules.validateErr = errors.New("cel: undeclared reference to 'nope'")
	w := e.post("/rules/CVE-2024-1/edit", url.Values{"yaml": {draftYAML}}, c)
	if w.Code != 422 || !strings.Contains(w.Body.String(), "undeclared reference") {
		t.Fatalf("validation error: %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Test rule") { // submitted YAML retained
		t.Error("yaml not retained")
	}
	if _, err := e.st.GetRule(context.Background(), "CVE-2024-1"); !errors.Is(err, store.ErrNotFound) {
		t.Error("rule stored despite validation failure")
	}
	if e.rules.reloads != 0 || e.trig.count() != 0 {
		t.Error("reload/trigger after failed validation")
	}
	e.rules.validateErr = nil

	// strict YAML: unknown field
	w = e.post("/rules/CVE-2024-1/edit", url.Values{"yaml": {draftYAML + "bogus_field: 1\n"}}, c)
	if w.Code != 422 || !strings.Contains(w.Body.String(), "bogus_field") {
		t.Fatalf("unknown field: %d", w.Code)
	}
	// invalid YAML
	if w := e.post("/rules/CVE-2024-1/edit", url.Values{"yaml": {"id: [unclosed"}}, c); w.Code != 422 {
		t.Fatalf("bad yaml: %d", w.Code)
	}
	// id change refused
	other := strings.Replace(draftYAML, "id: CVE-2024-1", "id: CVE-2024-2", 1)
	if w := e.post("/rules/CVE-2024-1/edit", url.Values{"yaml": {other}}, c); w.Code != 422 {
		t.Fatalf("id change: %d", w.Code)
	}
	// bad status
	bad := strings.Replace(draftYAML, "status: draft", "status: weird", 1)
	if w := e.post("/rules/CVE-2024-1/edit", url.Values{"yaml": {bad}}, c); w.Code != 422 {
		t.Fatalf("bad status: %d", w.Code)
	}
	if len(e.rules.validated) != 1 { // only the first request got as far as Validate
		t.Errorf("validate calls: %d", len(e.rules.validated))
	}
}

func TestApproveReject(t *testing.T) {
	e := newEnv(t, true)
	c := e.session("admin")
	if w := e.post("/rules/CVE-2024-1/approve", nil, c); w.Code != 303 {
		t.Fatalf("approve: %d %s", w.Code, w.Body.String())
	}
	got, err := e.st.GetRule(context.Background(), "CVE-2024-1")
	if err != nil || got.Status != model.RuleReviewed {
		t.Fatalf("after approve: %+v %v", got, err)
	}
	if got.Source != "llm:test" {
		t.Errorf("source provenance lost: %q", got.Source)
	}
	if e.rules.reloads != 1 || e.trig.count() != 1 || len(e.rules.validated) != 1 {
		t.Fatalf("reloads=%d triggers=%d validated=%d", e.rules.reloads, e.trig.count(), len(e.rules.validated))
	}
	if w := e.post("/rules/CVE-2024-1/reject", nil, c); w.Code != 303 {
		t.Fatalf("reject: %d", w.Code)
	}
	got, _ = e.st.GetRule(context.Background(), "CVE-2024-1")
	if got.Status != model.RuleRejected {
		t.Fatalf("after reject: %+v", got)
	}
	if e.rules.reloads != 2 || e.trig.count() != 2 {
		t.Fatalf("reloads=%d triggers=%d", e.rules.reloads, e.trig.count())
	}
	if w := e.post("/rules/NOPE/approve", nil, c); w.Code != 404 {
		t.Fatalf("approve unknown: %d", w.Code)
	}
}

func TestNilRulesService(t *testing.T) {
	e := newEnv(t, false)
	c := e.session("admin")
	r := model.Rule{ID: "R1", Title: "db rule", Status: model.RuleDraft, Source: "llm:x", Vulns: []string{"CVE-1"}}
	if err := e.st.UpsertRule(context.Background(), r, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/", "/rules", "/rules/R1"} {
		if w := e.do("GET", p, nil, c); w.Code != 200 {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
	if !strings.Contains(e.do("GET", "/rules", nil, c).Body.String(), "db rule") {
		t.Error("db rules not listed without engine")
	}
	if w := e.post("/rules/R1/approve", nil, c); w.Code != 303 {
		t.Fatalf("approve without engine: %d", w.Code)
	}
	got, _ := e.st.GetRule(context.Background(), "R1")
	if got.Status != model.RuleReviewed {
		t.Fatalf("status %v", got.Status)
	}
}

func TestRulesListAndDraftBadge(t *testing.T) {
	e := newEnv(t, true)
	c := e.session("admin")
	b := e.do("GET", "/rules", nil, c).Body.String()
	if !strings.Contains(b, `<span class="count">1</span>`) {
		t.Error("draft count missing in nav")
	}
	if b := e.do("GET", "/rules?status=reviewed", nil, c).Body.String(); strings.Contains(b, `href="/rules/CVE-2024-1"`) {
		t.Error("status filter not applied")
	}
}

func TestMatrixRoutes(t *testing.T) {
	e := newEnv(t, true)
	c := e.session("admin")
	for _, bad := range []string{"prod = room:server", "prod = !noserver", "prod", "= !a:b", "prod = ", "prod = !a:b\nprod = !c:d"} {
		w := e.post("/settings/matrix", url.Values{"routes": {bad}}, c)
		if w.Code != 422 {
			t.Errorf("%q: want 422 got %d", bad, w.Code)
		}
	}
	if _, err := e.st.GetSetting(context.Background(), matrixSettingKey); err == nil {
		t.Fatal("invalid routes persisted")
	}
	w := e.post("/settings/matrix", url.Values{"routes": {"prod = !x:y, !z:y\n# comment\n\ndev = !d:y"}}, c)
	if w.Code != 303 {
		t.Fatalf("save: %d", w.Code)
	}
	raw, err := e.st.GetSetting(context.Background(), matrixSettingKey)
	if err != nil {
		t.Fatal(err)
	}
	var got []struct {
		Label string   `json:"label"`
		Rooms []string `json:"rooms"`
	}
	if err := json.Unmarshal(raw, &got); err != nil || len(got) != 2 || got[0].Label != "prod" || len(got[0].Rooms) != 2 || got[1].Rooms[0] != "!d:y" {
		t.Fatalf("stored %s (%v)", raw, err)
	}
	if !strings.Contains(e.do("GET", "/settings", nil, c).Body.String(), "prod = !x:y, !z:y") {
		t.Error("saved routes not shown")
	}
}

func TestEnrollTokenShownOnce(t *testing.T) {
	e := newEnv(t, true)
	c := e.session("admin")
	w := e.post("/settings/tokens", url.Values{"name": {"fleet-a"}}, c)
	if w.Code != 200 {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	m := regexp.MustCompile(`pt_[0-9a-f]{64}`).FindString(w.Body.String())
	if m == "" {
		t.Fatal("token not shown")
	}
	if !strings.Contains(w.Body.String(), "enroll_token:") || !strings.Contains(w.Body.String(), "server_url: http://panoptes.test") {
		t.Error("agent.yaml snippet missing")
	}
	// stored hashed: the hash is accepted by UseEnrollToken, the plain secret is not
	ok, err := e.st.UseEnrollToken(context.Background(), store.HashSecret(m))
	if err != nil || !ok {
		t.Fatalf("hash not stored: %v %v", ok, err)
	}
	if ok, _ := e.st.UseEnrollToken(context.Background(), m); ok {
		t.Fatal("plain token stored")
	}
	// never shown again
	b := e.do("GET", "/settings", nil, c).Body.String()
	if strings.Contains(b, m) || !strings.Contains(b, "fleet-a") {
		t.Error("token visible on later view (or listing broken)")
	}
	// duplicate name
	if w := e.post("/settings/tokens", url.Values{"name": {"fleet-a"}}, c); w.Code != 409 {
		t.Errorf("duplicate: %d", w.Code)
	}
	// invalid name
	if w := e.post("/settings/tokens", url.Values{"name": {"bad name <x>"}}, c); w.Code != 422 {
		t.Errorf("invalid name: %d", w.Code)
	}
	// revoke
	if w := e.post("/settings/tokens/fleet-a/revoke", nil, c); w.Code != 303 {
		t.Fatalf("revoke: %d", w.Code)
	}
	toks, _ := e.st.ListEnrollTokens(context.Background())
	if len(toks) != 1 || !toks[0].Revoked {
		t.Fatalf("tokens: %+v", toks)
	}
}

func TestUsers(t *testing.T) {
	e := newEnv(t, true)
	e.addUser("admin", "pw-long-enough")
	c := e.session("admin")
	if w := e.post("/settings/users", url.Values{"username": {"bob"}, "password": {"short"}}, c); w.Code != 422 {
		t.Errorf("short pw: %d", w.Code)
	}
	if w := e.post("/settings/users", url.Values{"username": {"bob"}, "password": {"long-enough-1"}}, c); w.Code != 303 {
		t.Fatalf("add: %d", w.Code)
	}
	u, err := e.st.GetUser(context.Background(), "bob")
	if err != nil || !store.CheckPassword(u.PasswordHash, "long-enough-1") {
		t.Fatalf("user not stored hashed: %+v %v", u, err)
	}
	if w := e.post("/settings/users", url.Values{"username": {"bob"}, "password": {"long-enough-1"}}, c); w.Code != 409 {
		t.Errorf("duplicate: %d", w.Code)
	}
	if w := e.post("/settings/users/bob/password", url.Values{"password": {"abc"}}, c); w.Code != 422 {
		t.Errorf("short change: %d", w.Code)
	}
	if w := e.post("/settings/users/bob/password", url.Values{"password": {"new-password-9"}}, c); w.Code != 303 {
		t.Fatalf("change: %d", w.Code)
	}
	u, _ = e.st.GetUser(context.Background(), "bob")
	if !store.CheckPassword(u.PasswordHash, "new-password-9") {
		t.Error("password not changed")
	}
	if w := e.post("/settings/users/admin/delete", nil, c); w.Code != 422 {
		t.Errorf("self delete: %d", w.Code)
	}
	if _, err := e.st.GetUser(context.Background(), "admin"); err != nil {
		t.Error("self was deleted")
	}
	if w := e.post("/settings/users/bob/delete", nil, c); w.Code != 303 {
		t.Fatalf("delete: %d", w.Code)
	}
	if _, err := e.st.GetUser(context.Background(), "bob"); !errors.Is(err, store.ErrNotFound) {
		t.Error("bob not deleted")
	}
}

func TestXSSEscaped(t *testing.T) {
	e := newEnv(t, true)
	c := e.session("admin")
	evil := `<script>alert(1)</script>`
	h := e.seedHost(evil, `"><img src=x onerror=alert(2)>`)
	f := e.seedFinding(h, "CVE-2024-9", model.VerdictExploitable, false)
	for _, p := range []string{"/", "/hosts", "/hosts/" + h.ID, "/findings", "/findings/" + itoa(f.ID), "/vulns/CVE-2024-9", "/findings?label=" + url.QueryEscape(evil)} {
		w := e.do("GET", p, nil, c)
		b := w.Body.String()
		if strings.Contains(b, evil) || strings.Contains(b, "<img src=x") {
			t.Errorf("%s: unescaped markup in output", p)
		}
		if strings.Contains(p, "hosts") && !strings.Contains(b, "&lt;script&gt;alert(1)&lt;/script&gt;") && p != "/" {
			t.Errorf("%s: escaped hostname missing", p)
		}
	}
	// reflected query values are escaped too
	b := e.do("GET", "/findings?q="+url.QueryEscape(`"><script>x</script>`), nil, c).Body.String()
	if strings.Contains(b, "<script>x</script>") {
		t.Error("reflected q not escaped")
	}
}

func TestSecurityHeaders(t *testing.T) {
	e := newEnv(t, true)
	w := e.do("GET", "/login", nil, nil)
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "default-src 'self'") || w.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("missing security headers")
	}
	if strings.Contains(w.Body.String(), "http://") || strings.Contains(w.Body.String(), "https://") {
		t.Error("login page references external resources")
	}
}
