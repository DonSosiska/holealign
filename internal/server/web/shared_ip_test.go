package web

import (
	"bytes"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
)

func TestKnownDeviceBypassesSharedIPLimiters(t *testing.T) {
	e, _ := loginEnv(t)
	w := e.login("192.0.2.10", "admin", "correct-horse-battery")
	var dev *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == deviceCookie {
			dev = c
		}
	}
	if dev == nil {
		t.Fatal("no device cookie")
	}
	// every client behind one proxy address: wrong passwords for admin exhaust the limiters
	const shared = "127.0.0.1"
	for i := 0; i < maxFailures+1; i++ {
		e.login(shared, "admin", "wrong-password")
	}
	if w := e.login(shared, "admin", "correct-horse-battery"); w.Code != 429 {
		t.Fatalf("without the device cookie the shared IP stays limited: %d", w.Code)
	}
	if w := e.login(shared, "admin", "wrong-password", dev); w.Code != 401 {
		t.Fatalf("wrong password with device cookie: %d", w.Code)
	}
	if w := e.login(shared, "admin", "correct-horse-battery", dev); w.Code != 303 {
		t.Fatalf("known device locked out by shared-IP failures: %d", w.Code)
	}
	// the bypass must not clear the limiter for everybody else
	if w := e.login(shared, "admin", "correct-horse-battery"); w.Code != 429 {
		t.Fatalf("limiter cleared by a device login: %d", w.Code)
	}
}

func TestForwardedHeaderFromUntrustedPeerWarnsOnce(t *testing.T) {
	e := newEnv(t, true)
	var buf bytes.Buffer
	e.srv.log = slog.New(slog.NewTextHandler(&buf, nil))
	e.srv.ipOf = remoteIP
	for i := 0; i < 3; i++ {
		r := newReq("GET", "/login", nil, e.srv.pubURL.Host)
		r.Header.Set("X-Forwarded-For", "203.0.113.5")
		e.srv.warnForwardedOnce(r)
	}
	if n := strings.Count(buf.String(), "level=WARN"); n != 1 {
		t.Fatalf("want one warning, got %d: %s", n, buf.String())
	}
	buf.Reset()
	e.srv.ipOf = func(*http.Request) string { return "203.0.113.5" } // trusted proxy honoured
	e.srv.fwdWarn = sync.Once{}
	r := newReq("GET", "/login", nil, e.srv.pubURL.Host)
	r.Header.Set("X-Forwarded-For", "203.0.113.5")
	e.srv.warnForwardedOnce(r)
	if buf.Len() != 0 {
		t.Fatalf("warned although the header was honoured: %s", buf.String())
	}
}

func TestDraftRulePageShowsExpressions(t *testing.T) {
	e := newEnv(t, true)
	c := e.session("admin")
	e.rules.mu.Lock()
	r := &e.rules.rules[0]
	r.ExploitableIf = `facts["x"] == "<script>alert(1)</script>"`
	r.NotAffectedIf = "facts[\"y\"] == true || " + strings.Repeat("z", 500)
	e.rules.mu.Unlock()
	full := e.do("GET", "/rules/CVE-2024-1", nil, c).Body.String()
	b := full[:strings.Index(full, "<h2>Edit</h2>")]
	for _, want := range []string{"exploitable_if", "not_affected_if", "can mark hosts not affected", "LLM-written and unverified",
		"&lt;script&gt;", "<summary>show all</summary>"} {
		if !strings.Contains(b, want) {
			t.Errorf("approve panel missing %q", want)
		}
	}
	if strings.Contains(b, "<script>alert") {
		t.Error("expression not escaped")
	}
	if strings.Index(b, "can mark hosts not affected") > strings.Index(b, `action="/rules/CVE-2024-1/approve"`) {
		t.Error("expressions are not above the Approve button")
	}
	e.rules.mu.Lock()
	e.rules.rules[0].NotAffectedIf = ""
	e.rules.mu.Unlock()
	full = e.do("GET", "/rules/CVE-2024-1", nil, c).Body.String()
	if strings.Contains(full[:strings.Index(full, "<h2>Edit</h2>")], "can mark hosts not affected") {
		t.Error("not_affected_if warning shown without the condition")
	}
}
