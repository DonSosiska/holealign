package web

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DonSosiska/panoptes/internal/model"
	"github.com/DonSosiska/panoptes/internal/server/config"
	"github.com/DonSosiska/panoptes/internal/server/store"
)

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuf) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

// logEnv returns an env whose server logs (text) into the returned buffer.
func logEnv(t *testing.T, publicURL string) (*env, *lockedBuf) {
	t.Helper()
	e := newEnv(t, true)
	buf := &lockedBuf{}
	cfg := config.Default()
	cfg.PublicURL = publicURL
	srv, err := New(Deps{Store: e.st, Rules: e.rules, Pipeline: e.trig, Config: &cfg,
		Logger: slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))})
	if err != nil {
		t.Fatal(err)
	}
	e.srv = srv
	e.mux = http.NewServeMux()
	srv.Mount(e.mux)
	return e, buf
}

func TestLimiterNotResetByJunkKeys(t *testing.T) {
	now := time.Now()
	l := newLimiter(func() time.Time { return now })
	for i := 0; i < maxFailures; i++ {
		l.fail("target")
	}
	for i := 0; i < 10001; i++ {
		l.fail("junk" + strconv.Itoa(i))
	}
	if !l.blocked("target") {
		t.Fatal("target lockout wiped by junk keys")
	}
	// tiny capacity: blocked entries survive eviction while unblocked ones go
	l = newLimiterCfg(func() time.Time { return now }, 3, time.Minute, 0, 10)
	for i := 0; i < 3; i++ {
		l.fail("target")
	}
	for i := 0; i < 500; i++ {
		l.fail("j" + strconv.Itoa(i))
	}
	if !l.blocked("target") || len(l.items) > 10 {
		t.Fatalf("blocked=%v size=%d", l.blocked("target"), len(l.items))
	}
}

func TestLimiterEvictsExpiredFirst(t *testing.T) {
	now := time.Now()
	l := newLimiterCfg(func() time.Time { return now }, 5, time.Minute, 0, 5)
	for i := 0; i < 5; i++ {
		l.fail("old" + strconv.Itoa(i))
	}
	now = now.Add(2 * time.Minute)
	l.fail("new")
	if len(l.items) != 1 {
		t.Fatalf("expired entries should be swept, have %d", len(l.items))
	}
}

func TestPerIPLimit(t *testing.T) {
	e, _ := logEnv(t, "http://panoptes.test")
	now := time.Now()
	e.srv.now = func() time.Time { return now }
	e.srv.lim = newLimiterCfg(e.srv.now, maxFailures, failWindow, 0, limiterCap)
	e.srv.limIP = newLimiterCfg(e.srv.now, maxIPFailures, ipFailWindow, 0, limiterCap)

	// per-IP: many different usernames from one IP hit the IP cap
	for i := 0; i < maxIPFailures; i++ {
		e.srv.loginFailed("198.51.100.1", "user"+strconv.Itoa(i), false)
	}
	if e.srv.limIP.acquire("198.51.100.1") {
		t.Fatal("per-IP limit not enforced")
	}
	if !e.srv.limIP.acquire("198.51.100.2") {
		t.Fatal("other IP must not be blocked")
	}
}

func TestAuditLog(t *testing.T) {
	e, logs := logEnv(t, "http://panoptes.test")
	e.addUser("admin", "pw-long-enough")
	e.addUser("bob", "bob-long-password")
	c := e.session("admin")

	lc := &http.Cookie{Name: loginCSRFName, Value: "tok"}
	if w := e.do("POST", "/login", url.Values{"username": {"bob"}, "password": {"bob-long-password"}, "csrf": {"tok"}}, lc); w.Code != 303 {
		t.Fatalf("login %d", w.Code)
	}
	e.post("/rules/CVE-2024-1/approve", nil, c)
	y := strings.Replace(draftYAML, "status: draft", "status: reviewed", 1)
	y = strings.Replace(y, `== "debian"`, `== "ubuntu"`, 1)
	if w := e.post("/rules/CVE-2024-1/edit", url.Values{"yaml": {y}}, c); w.Code != 303 {
		t.Fatalf("edit %d %s", w.Code, w.Body.String())
	}
	e.post("/rules/CVE-2024-1/reject", nil, c)
	e.post("/settings/matrix", url.Values{"routes": {"a = !r:s\nb = !q:s"}}, c)
	e.post("/settings/tokens", url.Values{"name": {"fleet-a"}}, c)
	e.post("/settings/tokens/fleet-a/revoke", nil, c)
	e.post("/settings/users", url.Values{"username": {"carol"}, "password": {"carol-long-password"}}, c)
	e.post("/settings/users/carol/password", url.Values{"password": {"carol-other-password"}}, c)
	e.post("/settings/users/carol/delete", nil, c)
	e.post("/logout", nil, c)

	out := logs.String()
	for _, want := range []string{
		`action=login target=bob`, `action=rule_approve target=CVE-2024-1`, `action=rule_edit`, `action=rule_reject`,
		`action=matrix_routes_change`, `old_routes=0 new_routes=2`, `action=token_create target=fleet-a`,
		`action=token_revoke target=fleet-a`, `action=user_add target=carol`, `action=user_password_change target=carol`,
		`action=user_delete target=carol`, `action=logout`, `actor=admin`, `ip=192.0.2.1`,
		`old_status=draft new_status=reviewed`, `new_exploitable_if_sha256=` + sha256hex(`facts["os.id"] == "ubuntu"`),
		`old_exploitable_if_sha256=` + sha256hex(`facts["os.id"] == "debian"`),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("audit log missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "pt_") || strings.Contains(out, "carol-long-password") {
		t.Error("secret leaked into the log")
	}
}

func TestReauthRequired(t *testing.T) {
	e := newEnv(t, true)
	e.addUser("admin", "pw-long-enough")
	e.addUser("bob", "bob-long-password")
	ctx := context.Background()
	cases := []struct {
		path string
		form url.Values
	}{
		{"/settings/users", url.Values{"username": {"dave"}, "password": {"dave-long-password"}}},
		{"/settings/users/bob/password", url.Values{"password": {"changed-password-1"}}},
		{"/settings/users/bob/delete", url.Values{}},
		{"/settings/tokens", url.Values{"name": {"t1"}}},
	}
	for _, tc := range cases {
		for _, cur := range []string{"", "wrong-password"} {
			f := url.Values{}
			for k, v := range tc.form {
				f[k] = v
			}
			if cur != "" {
				f.Set("current_password", cur)
			}
			if w := e.postNoAuth(tc.path, f, e.session("admin")); w.Code != 403 {
				t.Errorf("%s cur=%q: %d", tc.path, cur, w.Code)
			}
		}
	}
	if _, err := e.st.GetUser(ctx, "dave"); err == nil {
		t.Error("user added without re-auth")
	}
	if u, _ := e.st.GetUser(ctx, "bob"); !store.CheckPassword(u.PasswordHash, "bob-long-password") {
		t.Error("password changed without re-auth")
	}
	if toks, _ := e.st.ListEnrollTokens(ctx); len(toks) != 0 {
		t.Error("token created without re-auth")
	}
	if _, err := e.st.GetUser(ctx, "bob"); err != nil {
		t.Error("bob deleted without re-auth")
	}
}

func TestPasswordMinLength(t *testing.T) {
	e := newEnv(t, true)
	e.addUser("admin", "pw-long-enough")
	c := e.session("admin")
	if w := e.post("/settings/users", url.Values{"username": {"bob"}, "password": {"elevenchars"}}, c); w.Code != 422 {
		t.Errorf("11 chars accepted: %d", w.Code)
	}
	if w := e.post("/settings/users", url.Values{"username": {"bob"}, "password": {"twelve-chars"}}, c); w.Code != 303 {
		t.Errorf("12 chars rejected: %d", w.Code)
	}
	if w := e.post("/settings/users/bob/password", url.Values{"password": {"elevenchars"}}, c); w.Code != 422 {
		t.Errorf("11 chars accepted on change: %d", w.Code)
	}
}

func TestHostCookiesAndHSTS(t *testing.T) {
	e, _ := logEnv(t, "https://panoptes.example.com")
	e.addUser("admin", "correct-horse-battery")
	w := e.do("GET", "/login", nil, nil)
	if w.Header().Get("Strict-Transport-Security") != "max-age=31536000" {
		t.Errorf("HSTS: %q", w.Header().Get("Strict-Transport-Security"))
	}
	var lc *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "__Host-panoptes_login" {
			lc = c
		}
	}
	if lc == nil || !lc.Secure || lc.Path != "/" || lc.Domain != "" {
		t.Fatalf("login cookie %+v", lc)
	}
	w = e.do("POST", "/login", url.Values{"username": {"admin"}, "password": {"correct-horse-battery"}, "csrf": {lc.Value}}, lc)
	if w.Code != 303 {
		t.Fatalf("login %d", w.Code)
	}
	var sc *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "__Host-panoptes_session" && c.Value != "" {
			sc = c
		}
	}
	if sc == nil || !sc.Secure || !sc.HttpOnly || sc.Path != "/" || sc.Domain != "" {
		t.Fatalf("session cookie %+v", sc)
	}
	if w := e.do("GET", "/", nil, sc); w.Code != 200 {
		t.Errorf("session cookie not accepted: %d", w.Code)
	}
	// plain http: no HSTS, plain names
	h := newEnv(t, true)
	if h.do("GET", "/login", nil, nil).Header().Get("Strict-Transport-Security") != "" {
		t.Error("HSTS over http")
	}
}

func TestHTTPNonLoopbackWarns(t *testing.T) {
	_, logs := logEnv(t, "http://panoptes.example.com")
	if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), "plain http") {
		t.Errorf("no warning: %s", logs.String())
	}
	for _, u := range []string{"http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080"} {
		_, l := logEnv(t, u)
		if strings.Contains(l.String(), "plain http") {
			t.Errorf("%s should not warn", u)
		}
	}
}

func TestNextExpiry(t *testing.T) {
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	exp := created.Add(sessionIdle)
	// within 5 minutes of the last refresh: untouched
	if _, ok := nextExpiry(created, exp, created.Add(4*time.Minute)); ok {
		t.Error("refreshed too early")
	}
	// older than 5 minutes: now+1h
	now := created.Add(10 * time.Minute)
	got, ok := nextExpiry(created, exp, now)
	if !ok || !got.Equal(now.Add(sessionIdle)) {
		t.Errorf("got %v %v", got, ok)
	}
	// capped by the absolute 12h lifetime
	exp = created.Add(11*time.Hour + 30*time.Minute)
	now = created.Add(11*time.Hour + 20*time.Minute)
	got, ok = nextExpiry(created, exp, now)
	if !ok || !got.Equal(created.Add(sessionTTL)) {
		t.Errorf("cap: %v %v", got, ok)
	}
	// already at the cap: no change
	exp = created.Add(sessionTTL)
	if _, ok := nextExpiry(created, exp, created.Add(11*time.Hour+50*time.Minute)); ok {
		t.Error("extended past absolute lifetime")
	}
}

func TestIdleExtensionEndToEnd(t *testing.T) {
	e := newEnv(t, true)
	e.addUser("admin", "pw-long-enough")
	now := time.Now()
	e.srv.now = func() time.Time { return now }
	tok, hash, _ := store.NewSecret("ps_")
	_ = e.st.CreateSession(context.Background(), store.Session{TokenHash: hash, Username: "admin", CreatedAt: now, ExpiresAt: now.Add(sessionIdle)})
	c := &http.Cookie{Name: cookieName, Value: tok}
	now = now.Add(30 * time.Minute)
	if w := e.do("GET", "/", nil, c); w.Code != 200 {
		t.Fatalf("%d", w.Code)
	}
	// without the refresh the session would die at +1h; now it must live past that
	now = now.Add(45 * time.Minute)
	if w := e.do("GET", "/", nil, c); w.Code != 200 {
		t.Fatalf("session not extended: %d", w.Code)
	}
	now = now.Add(sessionIdle + time.Minute)
	if w := e.do("GET", "/", nil, c); w.Code != 303 {
		t.Fatalf("idle session still valid: %d", w.Code)
	}
}

func TestReferenceLinks(t *testing.T) {
	e := newEnv(t, true)
	c := e.session("admin")
	h := e.seedHost("web1")
	f := e.seedFinding(h, "CVE-2024-1", model.VerdictExploitable, false)
	e.rules.mu.Lock()
	e.rules.rules[0].References = []string{
		"https://nvd.nist.gov/vuln/detail/CVE-2024-1", "https://evil.example.com/x", "javascript:alert(1)",
		"http://nvd.nist.gov/insecure", "https://nvd.nist.gov.evil.com/x", "https://user@github.com/a",
	}
	e.rules.mu.Unlock()
	b := e.do("GET", "/findings/"+itoa(f.ID), nil, c).Body.String()
	if !strings.Contains(b, `<a href="https://nvd.nist.gov/vuln/detail/CVE-2024-1"`) {
		t.Error("allowlisted reference not linked")
	}
	for _, bad := range []string{`href="https://evil.example.com`, `href="javascript`, `href="http://nvd`, `href="https://nvd.nist.gov.evil`, `href="https://user@`} {
		if strings.Contains(b, bad) {
			t.Errorf("link rendered for %s", bad)
		}
	}
	if !strings.Contains(b, "https://evil.example.com/x") {
		t.Error("non-allowlisted reference should still show as text")
	}
}

func TestStaticNoListing(t *testing.T) {
	e, _ := logEnv(t, "https://panoptes.example.com")
	for _, p := range []string{"/static/", "/static", "/static/."} {
		w := e.do("GET", p, nil, nil)
		if w.Code == 200 || strings.Contains(w.Body.String(), "style.css") {
			t.Errorf("%s: %d listing exposed", p, w.Code)
		}
	}
	w := e.do("GET", "/static/style.css", nil, nil)
	if w.Code != 200 {
		t.Fatalf("css %d", w.Code)
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "default-src 'self'") ||
		w.Header().Get("X-Frame-Options") != "DENY" || w.Header().Get("Strict-Transport-Security") == "" ||
		w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("static headers: %v", w.Header())
	}
	if w := e.do("GET", "/static/nope.css", nil, nil); w.Code != 404 {
		t.Errorf("missing: %d", w.Code)
	}
}
