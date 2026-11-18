package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/DonSosiska/holealign/internal/model"
)

const (
	testSlackToken = "xoxb" + "-1234567890-secretsecretsecret"
	testTGToken    = "123456789:AAH-secret_token_value_0123456789"
	slackChan      = "C0123456789"
	tgChat         = "-1001234567890"
)

// fakeAPI records the requests of a Slack or Telegram test server.
type fakeAPI struct {
	t      *testing.T
	srv    *httptest.Server
	mu     sync.Mutex
	paths  []string
	auths  []string
	bodies []map[string]any
	script func(call int, w http.ResponseWriter)
}

func newFakeAPI(t *testing.T, script func(call int, w http.ResponseWriter)) *fakeAPI {
	t.Helper()
	f := &fakeAPI{t: t, script: script}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("body is not JSON: %v", err)
		}
		f.mu.Lock()
		call := len(f.bodies)
		f.paths = append(f.paths, r.Method+" "+r.URL.EscapedPath())
		f.auths = append(f.auths, r.Header.Get("Authorization"))
		f.bodies = append(f.bodies, body)
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if f.script != nil {
			f.script(call, w)
			return
		}
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPI) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.bodies)
}

func (f *fakeAPI) text(i int) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, _ := f.bodies[i]["text"].(string)
	return s
}

func testSlack(t *testing.T, f *fakeAPI) *Slack {
	t.Helper()
	s, err := NewSlackChannel(testSlackToken, f.srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	s.base = f.srv.URL
	return s
}

func testTelegram(t *testing.T, f *fakeAPI) *Telegram {
	t.Helper()
	c, err := NewTelegramChannel(testTGToken, f.srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	c.base = f.srv.URL
	return c
}

func newNotifier(t *testing.T, cfg Config, rs RouteSource, chans ...Channel) *Notifier {
	t.Helper()
	n, err := New(cfg, rs, chans...)
	if err != nil {
		t.Fatal(err)
	}
	n.backoff = time.Millisecond
	return n
}

func hostile() model.Event {
	ev := testEvent(model.EventExploitable, "CVE-2024-1", "web01")
	ev.Host.Hostname = "<!channel> <!here> @everyone @here <@U12345> <#C123|x> <https://evil.example|click> " +
		"*bold* _it_ ~s~ `code` <a href=\"https://evil.example\">x</a> <b>b</b> &amp; [md](https://evil.example) </code>"
	ev.Finding.VerdictReason = "<!channel> @channel </b><script>alert(1)</script> *x* `y`"
	ev.Finding.PackageName = "pkg<i>"
	ev.FixCmd = "apt-get install -y a`b` <!channel> && echo '@everyone'"
	ev.WebURL = "https://holealign.example/findings/1?a=1&b=<2>"
	return ev
}

// --- destinations -------------------------------------------------------------------------------

func TestParseAndValidateDestinations(t *testing.T) {
	good := map[string][2]string{
		"!room:example.org":         {"matrix", "!room:example.org"},
		"#alias:example.org":        {"matrix", "#alias:example.org"},
		"matrix:!room:example.org":  {"matrix", "!room:example.org"},
		"slack:C0123456789":         {"slack", "C0123456789"},
		"slack:G0123456789":         {"slack", "G0123456789"},
		"slack:D0123456789":         {"slack", "D0123456789"},
		"telegram:-1001234567890":   {"telegram", "-1001234567890"},
		"telegram:12345":            {"telegram", "12345"},
		"telegram:-100123456/42":    {"telegram", "-100123456/42"},
		" slack:C0123456789 ":       {"slack", "C0123456789"},
		"unknown:!room:example.org": {"matrix", "unknown:!room:example.org"}, // classified Matrix, then rejected below
	}
	for in, want := range good {
		sc, tg := ParseDestination(in)
		if sc != want[0] || tg != want[1] {
			t.Errorf("ParseDestination(%q) = %q %q, want %q %q", in, sc, tg, want[0], want[1])
		}
	}
	v12 := "!2yijIgSMxGZwffdVoU4ny4n00S4Atg9YwXs8Cw4lwi0" // room version 12: no server part
	for _, in := range []string{"!room:example.org", "#alias:example.org", "matrix:!room:example.org", v12, "matrix:" + v12, "slack:C0123456789",
		"telegram:-1001234567890", "telegram:-100123456/42"} {
		if err := ValidateDestination(in); err != nil {
			t.Errorf("ValidateDestination(%q): %v", in, err)
		}
	}
	for _, in := range []string{"", " ", "room:server", "!nocolon", "! a:b", v12[:42], v12 + "x", "#" + v12[1:], "!2yijIgSMxGZwffdVoU4ny4n00S4Atg9YwXs8Cw4lwi+", "slack:", "slack:general", "slack:#general", "slack:c0123456789",
		"slack:C012", "slack:C0123456789/extra", "slack:T0123456789", "telegram:", "telegram:@chan", "telegram:abc",
		"telegram:0", "telegram:-100/0", "telegram:-100/-1", "telegram:-100/", "telegram:1/2/3", "signal:123",
		"unknown:!room:example.org", "https://hooks.slack.com/services/T/B/x", "slack:C01234 56789", "!r:s" + strings.Repeat("a", 300)} {
		if err := ValidateDestination(in); err == nil {
			t.Errorf("ValidateDestination(%q) accepted", in)
		}
	}
	if err := ValidateDestination("signal:123"); err == nil || !strings.Contains(err.Error(), "unknown scheme") {
		t.Errorf("unknown scheme error = %v", err)
	}
	if c, err := CanonicalDestination("matrix:!a:b"); err != nil || c != "!a:b" {
		t.Errorf("canonical = %q %v", c, err)
	}
}

// --- Slack --------------------------------------------------------------------------------------

func TestSlackRequestShape(t *testing.T) {
	f := newFakeAPI(t, nil)
	n := newNotifier(t, Config{Default: []string{"slack:" + slackChan}}, nil, testSlack(t, f))
	if err := n.Notify(context.Background(), []model.Event{testEvent(model.EventExploitable, "CVE-2024-1", "web01")}); err != nil {
		t.Fatal(err)
	}
	if f.count() != 1 {
		t.Fatalf("requests = %d", f.count())
	}
	if f.paths[0] != "POST /chat.postMessage" || f.auths[0] != "Bearer "+testSlackToken {
		t.Errorf("request: %s auth %q", f.paths[0], f.auths[0])
	}
	b := f.bodies[0]
	if b["channel"] != slackChan || b["unfurl_links"] != false || b["unfurl_media"] != false || b["link_names"] != false {
		t.Errorf("body = %v", b)
	}
	if txt := f.text(0); !strings.Contains(txt, "*EXPLOITABLE: CVE-2024-1 on web01*") || !strings.Contains(txt, "Package: openssl 3.0.1") {
		t.Errorf("text = %q", txt)
	}
}

func TestSlackHostileStringsAreInert(t *testing.T) {
	f := newFakeAPI(t, nil)
	n := newNotifier(t, Config{Default: []string{"slack:" + slackChan}}, nil, testSlack(t, f))
	if err := n.Notify(context.Background(), []model.Event{hostile()}); err != nil {
		t.Fatal(err)
	}
	txt := f.text(0)
	// mentions in inline code spans are inert in Slack (and keep fix commands copy-pasteable)
	noCode := regexp.MustCompile("`[^`]*`").ReplaceAllString(txt, "")
	for _, bad := range []string{"<!channel>", "<!here>", "<@U12345>", "<#C123", "<https://evil.example|click>", "<a href", "<script>", "@everyone", "@here", "@channel"} {
		if strings.Contains(noCode, bad) || (bad[0] == '<' && strings.Contains(txt, bad)) {
			t.Errorf("text contains %q:\n%s", bad, txt)
		}
	}
	// every "<" in the message starts one of our own constructs: <url|label> links
	for _, m := range regexp.MustCompile(`<[^>]*>`).FindAllString(txt, -1) {
		if !strings.HasPrefix(m, "<https://holealign.example/") {
			t.Errorf("unexpected angle-bracket construct %q", m)
		}
	}
	if !strings.Contains(txt, "&lt;!channel&gt;") || !strings.Contains(txt, "@\u200beveryone") {
		t.Errorf("escaping missing:\n%s", txt)
	}
	// the link URL cannot break out of <url|label>
	if !strings.Contains(txt, "<https://holealign.example/findings/1?a=1&amp;b=%3C2%3E|") {
		t.Errorf("link not safe:\n%s", txt)
	}
	// the code span cannot be closed from the inside
	if !strings.Contains(txt, "Fix: `apt-get install -y aˋbˋ &lt;!channel&gt; && echo '@everyone'`") &&
		!strings.Contains(txt, "&amp;&amp; echo") {
		t.Errorf("fix command not escaped:\n%s", txt)
	}
}

func TestSlackHugeHostIsBounded(t *testing.T) {
	f := newFakeAPI(t, nil)
	n := newNotifier(t, Config{Default: []string{"slack:" + slackChan}}, nil, testSlack(t, f))
	ev := testEvent(model.EventExploitable, "CVE-1", strings.Repeat("h<&>", 2500)) // 10 KB
	if err := n.Notify(context.Background(), []model.Event{ev}); err != nil {
		t.Fatal(err)
	}
	if got := utf8.RuneCountInString(f.text(0)); got > 4000 {
		t.Errorf("text has %d runes for a 10 KB host name", got)
	}
}

func TestSlackTextLimit(t *testing.T) {
	var lines []Line
	for i := 0; i < 5000; i++ {
		lines = append(lines, Line{txt(strings.Repeat("<&>", 100))})
	}
	out := formatSlack(Message{Lines: lines})
	if n := utf8.RuneCountInString(out); n > slackMaxText {
		t.Errorf("formatted %d runes > %d", n, slackMaxText)
	}
	if !strings.HasSuffix(out, truncatedNote) {
		t.Error("no truncation note")
	}
	// a section/line is never cut inside an entity
	if strings.Contains(strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(out, "&lt;", ""), "&gt;", ""), "&amp;", ""), "&") {
		t.Error("broken entity")
	}
}

func TestSlackErrorMapping(t *testing.T) {
	cases := []struct {
		resp      string
		status    int
		permanent bool
		attempts  int
	}{
		{`{"ok":false,"error":"channel_not_found"}`, 404, true, 1},
		{`{"ok":false,"error":"not_in_channel"}`, 403, true, 1},
		{`{"ok":false,"error":"invalid_auth"}`, 401, true, 1},
		{`{"ok":false,"error":"account_inactive"}`, 401, true, 1},
		{`{"ok":false,"error":"token_revoked"}`, 401, true, 1},
		{`{"ok":false,"error":"some_new_error"}`, 400, true, 1},
		{`{"ok":false,"error":"ratelimited"}`, 429, false, maxAttempts},
		{`{"ok":false,"error":"internal_error"}`, 503, false, maxAttempts},
	}
	for _, c := range cases {
		f := newFakeAPI(t, func(_ int, w http.ResponseWriter) { _, _ = io.WriteString(w, c.resp) })
		pl := &problemLog{}
		n := newNotifier(t, Config{Default: []string{"slack:" + slackChan}, OnDeliveryProblem: pl.add}, nil, testSlack(t, f))
		err := n.Notify(context.Background(), []model.Event{testEvent(model.EventExploitable, "CVE-1", "h")})
		var de *DeliveryError
		if !errors.As(err, &de) || len(de.Failed) != 1 {
			t.Errorf("%s: err = %v (exploitable must be retried later)", c.resp, err)
		}
		if f.count() != c.attempts {
			t.Errorf("%s: attempts = %d, want %d", c.resp, f.count(), c.attempts)
		}
		ps := pl.all()
		if len(ps) != 1 || ps[0].status != c.status || ps[0].permanent != c.permanent || ps[0].room != "slack:"+slackChan {
			t.Errorf("%s: problems = %+v", c.resp, ps)
		}
	}
}

func TestSlackPermanentNonCriticalNotRetried(t *testing.T) {
	f := newFakeAPI(t, func(_ int, w http.ResponseWriter) {
		_, _ = io.WriteString(w, `{"ok":false,"error":"channel_not_found"}`)
	})
	n := newNotifier(t, Config{Default: []string{"slack:" + slackChan}}, nil, testSlack(t, f))
	err := n.Notify(context.Background(), []model.Event{testEvent(model.EventResolved, "CVE-1", "h")})
	var de *DeliveryError
	if !errors.As(err, &de) || len(de.Failed) != 0 {
		t.Fatalf("err = %v, want a DeliveryError without events to retry", err)
	}
}

func TestSlack429RetryAfterHeader(t *testing.T) {
	f := newFakeAPI(t, func(call int, w http.ResponseWriter) {
		if call == 0 {
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"ok":false,"error":"ratelimited"}`)
			return
		}
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	s := testSlack(t, f)
	err := s.Send(context.Background(), slackChan, buildGroup([]model.Event{testEvent(model.EventExploitable, "CVE-1", "h")}))
	var se *SendError
	if !errors.As(err, &se) || se.Status != 429 || se.Permanent || se.RetryAfter != 7*time.Second {
		t.Fatalf("err = %#v", err)
	}
	// through the notifier the retry succeeds (the wait itself is capped, so use a short cap-free path)
	f2 := newFakeAPI(t, func(call int, w http.ResponseWriter) {
		if call == 0 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	n := newNotifier(t, Config{Default: []string{"slack:" + slackChan}}, nil, testSlack(t, f2))
	if err := n.Notify(context.Background(), []model.Event{testEvent(model.EventExploitable, "CVE-1", "h")}); err != nil {
		t.Fatal(err)
	}
	if f2.count() != 2 {
		t.Errorf("attempts = %d, want 2", f2.count())
	}
}

func TestSlackTokenNeverInErrors(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close() // connection refused
	s, _ := NewSlackChannel(testSlackToken, nil)
	s.base = url
	err := s.Send(context.Background(), slackChan, Message{Lines: []Line{{txt("x")}}})
	if err == nil || strings.Contains(err.Error(), testSlackToken) {
		t.Fatalf("err = %v", err)
	}
	var se *SendError
	if !errors.As(err, &se) || se.Status != 0 || se.Permanent {
		t.Errorf("network error must be a retryable status-0 error: %#v", err)
	}
	for _, bad := range []string{"", "xoxp-123456789012", "xapp-1-secret", "https://hooks.slack.com/services/T/B/x"} {
		if _, err := NewSlackChannel(bad, nil); err == nil {
			t.Errorf("token %q accepted", bad)
		}
	}
}

// --- Telegram -----------------------------------------------------------------------------------

func TestTelegramRequestShape(t *testing.T) {
	f := newFakeAPI(t, nil)
	n := newNotifier(t, Config{Default: []string{"telegram:" + tgChat + "/17"}}, nil, testTelegram(t, f))
	if err := n.Notify(context.Background(), []model.Event{testEvent(model.EventExploitable, "CVE-2024-1", "web01")}); err != nil {
		t.Fatal(err)
	}
	if f.count() != 1 {
		t.Fatalf("requests = %d", f.count())
	}
	if f.paths[0] != "POST /bot"+testTGToken+"/sendMessage" {
		t.Errorf("path = %q", f.paths[0])
	}
	b := f.bodies[0]
	if b["chat_id"] != float64(-1001234567890) || b["message_thread_id"] != float64(17) || b["parse_mode"] != "HTML" {
		t.Errorf("body = %v", b)
	}
	if lp, _ := b["link_preview_options"].(map[string]any); lp["is_disabled"] != true {
		t.Errorf("link previews not disabled: %v", b)
	}
	if _, ok := b["disable_notification"]; ok {
		t.Error("alerts must notify")
	}
	if txt := f.text(0); !strings.Contains(txt, "🔴 <b>EXPLOITABLE: CVE-2024-1 on web01</b>") {
		t.Errorf("text = %q", txt)
	}
	// informational events are silent
	if err := n.Notify(context.Background(), []model.Event{testEvent(model.EventResolved, "CVE-2024-1", "web01")}); err != nil {
		t.Fatal(err)
	}
	if f.bodies[1]["disable_notification"] != true {
		t.Errorf("resolved should be silent: %v", f.bodies[1])
	}
	// no topic: no thread id
	n2 := newNotifier(t, Config{Default: []string{"telegram:" + tgChat}}, nil, testTelegram(t, f))
	_ = n2.Notify(context.Background(), []model.Event{testEvent(model.EventExploitable, "CVE-9", "web01")})
	if _, ok := f.bodies[2]["message_thread_id"]; ok {
		t.Errorf("thread id sent without topic: %v", f.bodies[2])
	}
}

var tgTag = regexp.MustCompile(`</?([A-Za-z0-9]+)[^>]*>`)
var tgEntity = regexp.MustCompile(`&[A-Za-z0-9#]*;?`)

// checkTelegramHTML verifies that text only uses b, code and a tags, balanced, with valid entities.
func checkTelegramHTML(t *testing.T, text string) {
	t.Helper()
	var stack []string
	for _, m := range tgTag.FindAllStringSubmatch(text, -1) {
		name := m[1]
		if name != "b" && name != "code" && name != "a" {
			t.Errorf("forbidden tag %q in %q", m[0], text)
			continue
		}
		if strings.HasPrefix(m[0], "</") {
			if len(stack) == 0 || stack[len(stack)-1] != name {
				t.Errorf("unbalanced %s in %q", m[0], text)
				return
			}
			stack = stack[:len(stack)-1]
		} else {
			stack = append(stack, name)
		}
	}
	if len(stack) != 0 {
		t.Errorf("unclosed tags %v in %q", stack, text)
	}
	for _, e := range tgEntity.FindAllString(text, -1) {
		if e != "&amp;" && e != "&lt;" && e != "&gt;" && e != "&quot;" {
			t.Errorf("bad entity %q in %q", e, text)
		}
	}
	// outside our own tags no "<" or ">" may remain
	stripped := tgTag.ReplaceAllString(text, "")
	if strings.ContainsAny(stripped, "<>") {
		t.Errorf("raw angle bracket in %q", text)
	}
}

func TestTelegramHostileStringsAreInert(t *testing.T) {
	f := newFakeAPI(t, nil)
	n := newNotifier(t, Config{Default: []string{"telegram:" + tgChat}}, nil, testTelegram(t, f))
	if err := n.Notify(context.Background(), []model.Event{hostile()}); err != nil {
		t.Fatal(err)
	}
	body := f.text(0)
	checkTelegramHTML(t, body)
	noCode := regexp.MustCompile("(?s)<code>.*?</code>").ReplaceAllString(body, "") // inert in Telegram
	for _, bad := range []string{"<script>", "<a href=\"https://evil", "<i>", "@everyone", "@here", "@channel"} {
		if strings.Contains(noCode, bad) || (bad[0] == '<' && strings.Contains(body, bad)) {
			t.Errorf("text contains %q:\n%s", bad, body)
		}
	}
	if !strings.Contains(body, "@\u200beveryone") || !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("escaping missing:\n%s", body)
	}
	if !strings.Contains(body, `<a href="https://holealign.example/findings/1?a=1&amp;b=&lt;2&gt;">`) {
		t.Errorf("link attribute not escaped:\n%s", body)
	}
}

func TestTelegramLengthLimitNeverBreaksEntities(t *testing.T) {
	f := newFakeAPI(t, nil)
	n := newNotifier(t, Config{Default: []string{"telegram:" + tgChat}}, nil, testTelegram(t, f))
	// 10 KB host name and a pile of packages: far beyond 4096 characters of entities
	ev := testEvent(model.EventExploitable, "CVE-1", strings.Repeat("h<&>", 2500))
	var evs []model.Event
	for i := 0; i < 50; i++ {
		e := ev
		e.Finding.PackageName = fmt.Sprintf("pkg-%d<&>%s", i, strings.Repeat("x", 200))
		e.Finding.VerdictReason = strings.Repeat("r<&>", 100) + fmt.Sprint(i)
		evs = append(evs, e)
	}
	if err := n.Notify(context.Background(), evs); err != nil {
		t.Fatal(err)
	}
	body := f.text(0)
	checkTelegramHTML(t, body)
	visible := utf8.RuneCountInString(html2text(body))
	if visible > 4096 {
		t.Errorf("visible text has %d characters", visible)
	}
	// tiny budget: a single line longer than the limit is cut before markup is built
	long := Message{Lines: []Line{{txt("x"), bold(strings.Repeat("<&>", 5000)), code("c")}}}
	out := formatTelegram(long)
	checkTelegramHTML(t, out)
	if utf8.RuneCountInString(html2text(out)) > 4096 {
		t.Error("long line not cut")
	}
}

func html2text(s string) string {
	s = tgTag.ReplaceAllString(s, "")
	return strings.NewReplacer("&lt;", "<", "&gt;", ">", "&amp;", "&", "&quot;", `"`).Replace(s)
}

func TestTelegramErrors(t *testing.T) {
	cases := []struct {
		name      string
		code      int
		body      string
		status    int
		permanent bool
		attempts  int
	}{
		{"chat not found", 400, `{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}`, 400, true, 1},
		{"bot kicked", 403, `{"ok":false,"error_code":403,"description":"Forbidden: bot was kicked from the group chat"}`, 403, true, 1},
		{"bot blocked", 403, `{"ok":false,"error_code":403,"description":"Forbidden: bot was blocked by the user"}`, 403, true, 1},
		{"bad token", 401, `{"ok":false,"error_code":401,"description":"Unauthorized"}`, 401, true, 1},
		{"429 no wait", 429, `{"ok":false,"error_code":429,"description":"Too Many Requests","parameters":{"retry_after":0}}`, 429, false, maxAttempts},
		{"502", 502, `bad gateway`, 502, false, maxAttempts},
	}
	for _, c := range cases {
		f := newFakeAPI(t, func(_ int, w http.ResponseWriter) { w.WriteHeader(c.code); _, _ = io.WriteString(w, c.body) })
		pl := &problemLog{}
		n := newNotifier(t, Config{Default: []string{"telegram:" + tgChat}, OnDeliveryProblem: pl.add}, nil, testTelegram(t, f))
		err := n.Notify(context.Background(), []model.Event{testEvent(model.EventExploitable, "CVE-1", "h")})
		var de *DeliveryError
		if !errors.As(err, &de) || len(de.Failed) != 1 {
			t.Errorf("%s: err = %v", c.name, err)
		}
		if f.count() != c.attempts {
			t.Errorf("%s: attempts = %d, want %d", c.name, f.count(), c.attempts)
		}
		ps := pl.all()
		if len(ps) != 1 || ps[0].status != c.status || ps[0].permanent != c.permanent || ps[0].room != "telegram:"+tgChat {
			t.Errorf("%s: problems = %+v", c.name, ps)
		}
		if err != nil && strings.Contains(err.Error(), testTGToken) {
			t.Errorf("%s: token in error %v", c.name, err)
		}
	}
}

func TestTelegram429RetryAfterParameter(t *testing.T) {
	f := newFakeAPI(t, func(_ int, w http.ResponseWriter) {
		w.WriteHeader(429)
		_, _ = io.WriteString(w, `{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 9","parameters":{"retry_after":9}}`)
	})
	err := testTelegram(t, f).Send(context.Background(), tgChat, Message{Lines: []Line{{txt("x")}}})
	var se *SendError
	if !errors.As(err, &se) || se.Status != 429 || se.RetryAfter != 9*time.Second || se.Permanent {
		t.Fatalf("err = %#v", err)
	}
	// then success after a retry through the notifier
	f2 := newFakeAPI(t, func(call int, w http.ResponseWriter) {
		if call == 0 {
			w.WriteHeader(429)
			_, _ = io.WriteString(w, `{"ok":false,"error_code":429,"parameters":{"retry_after":0}}`)
			return
		}
		_, _ = io.WriteString(w, `{"ok":true,"result":{}}`)
	})
	n := newNotifier(t, Config{Default: []string{"telegram:" + tgChat}}, nil, testTelegram(t, f2))
	if err := n.Notify(context.Background(), []model.Event{testEvent(model.EventExploitable, "CVE-1", "h")}); err != nil || f2.count() != 2 {
		t.Fatalf("err %v attempts %d", err, f2.count())
	}
}

func TestTelegramTokenRedaction(t *testing.T) {
	// network error: net/http puts the full URL (with the token) into *url.Error
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	c, err := NewTelegramChannel(testTGToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.base = url
	err = c.Send(context.Background(), tgChat, Message{Lines: []Line{{txt("x")}}})
	if err == nil || strings.Contains(err.Error(), testTGToken) || strings.Contains(err.Error(), "/bot") {
		t.Fatalf("network error leaks the URL: %v", err)
	}
	// a server that echoes the token in its description
	f := newFakeAPI(t, func(_ int, w http.ResponseWriter) {
		w.WriteHeader(400)
		_, _ = io.WriteString(w, `{"ok":false,"error_code":400,"description":"bad request /bot`+testTGToken+`/sendMessage"}`)
	})
	err = testTelegram(t, f).Send(context.Background(), tgChat, Message{Lines: []Line{{txt("x")}}})
	if err == nil || strings.Contains(err.Error(), testTGToken) {
		t.Fatalf("description leaks the token: %v", err)
	}
	for _, bad := range []string{"", "token", "123:abc", "https://api.telegram.org/bot1:x"} {
		if _, err := NewTelegramChannel(bad, nil); err == nil {
			t.Errorf("token %q accepted", bad)
		}
	}
}

// --- routing across channels --------------------------------------------------------------------

type multiEnv struct {
	hs *fakeHS
	sl *fakeAPI
	tg *fakeAPI
	n  *Notifier
}

func newMulti(t *testing.T, cfg Config, rs RouteSource) *multiEnv {
	t.Helper()
	e := &multiEnv{hs: newFakeHS(t, nil), sl: newFakeAPI(t, nil), tg: newFakeAPI(t, nil)}
	mx, err := NewMatrixChannel(e.hs.srv.URL, "t", e.hs.srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	e.n = newNotifier(t, cfg, rs, mx, testSlack(t, e.sl), testTelegram(t, e.tg))
	return e
}

func TestRoutingLabelsToMixedDestinations(t *testing.T) {
	e := newMulti(t, Config{
		Default: []string{"!def:x"},
		Ops:     []string{"slack:" + slackChan, "telegram:" + tgChat},
		Routes: []Route{
			{Label: "prod", To: []string{"!prod:x", "slack:C0000000001", "matrix:!prod:x"}},
			{Label: "web", To: []string{"telegram:-100777/3"}},
		},
	}, staticRoutes{routes: []Route{{Label: "web", To: []string{"slack:C0000000002"}}}})
	evs := []model.Event{
		testEvent(model.EventExploitable, "CVE-1", "a", "prod"),
		testEvent(model.EventExploitable, "CVE-2", "b", "web"),
		testEvent(model.EventExploitable, "CVE-3", "c"), // no label: default
		testEvent(model.EventExploitable, "CVE-4", "d", "prod", "web"),
	}
	if err := e.n.Notify(context.Background(), evs); err != nil {
		t.Fatal(err)
	}
	// matrix: prod room gets CVE-1 and CVE-4 (listed twice, deduplicated by canonical form); default gets CVE-3
	if c := e.hs.roomCounts(); c["!prod:x"] != 2 || c["!def:x"] != 1 || len(c) != 2 {
		t.Errorf("matrix rooms = %v", c)
	}
	// slack: C...1 prod (CVE-1, CVE-4), C...2 web from DB (CVE-2, CVE-4); the ops channel gets nothing
	got := map[string]int{}
	for _, b := range e.sl.bodies {
		got[b["channel"].(string)]++
	}
	if got["C0000000001"] != 2 || got["C0000000002"] != 2 || got[slackChan] != 0 || len(got) != 2 {
		t.Errorf("slack channels = %v", got)
	}
	// telegram: only the web route (CVE-2, CVE-4) with its topic
	if e.tg.count() != 2 || e.tg.bodies[0]["message_thread_id"] != float64(3) || e.tg.bodies[0]["chat_id"] != float64(-100777) {
		t.Errorf("telegram = %v", e.tg.bodies)
	}
}

func TestOpsDestinationsReceiveServerLevelEvents(t *testing.T) {
	e := newMulti(t, Config{
		Default: []string{"!def:x"},
		Ops:     []string{"slack:" + slackChan, "telegram:" + tgChat, "!ops:x"},
	}, nil)
	feed := model.Event{Kind: model.EventFeedStale, Detail: "feed stale: last refresh 3 days ago"}
	agg := model.Event{Kind: model.EventAgentSilent, Detail: "20 agents silent\nweb01\nweb02"}
	if err := e.n.Notify(context.Background(), []model.Event{feed, agg}); err != nil {
		t.Fatal(err)
	}
	if c := e.hs.roomCounts(); c["!ops:x"] != 2 || c["!def:x"] != 0 {
		t.Errorf("matrix = %v", c)
	}
	if e.sl.count() != 2 || e.tg.count() != 2 {
		t.Fatalf("slack %d telegram %d", e.sl.count(), e.tg.count())
	}
	if !strings.Contains(e.sl.text(0), "*FEED STALE:*") || !strings.Contains(e.tg.text(1), "<b>AGENT SILENT:</b>") ||
		!strings.Contains(e.tg.text(1), "\nweb01\nweb02") {
		t.Errorf("health rendering:\nslack %q\ntelegram %q", e.sl.text(0), e.tg.text(1))
	}
	// without ops destinations server-level events go to the default destinations
	e2 := newMulti(t, Config{Default: []string{"slack:" + slackChan}}, nil)
	if err := e2.n.Notify(context.Background(), []model.Event{feed}); err != nil || e2.sl.count() != 1 {
		t.Fatalf("err %v count %d", err, e2.sl.count())
	}
}

func TestBurstModeAppliesPerDestinationOnEveryChannel(t *testing.T) {
	e := newMulti(t, Config{Default: []string{"slack:" + slackChan, "telegram:" + tgChat}}, nil)
	var evs []model.Event
	for i := 0; i < burstThreshold+5; i++ {
		evs = append(evs, testEvent(model.EventExploitable, fmt.Sprintf("CVE-%d", i), "h"))
	}
	if err := e.n.Notify(context.Background(), evs); err != nil {
		t.Fatal(err)
	}
	if e.sl.count() != burstKeep+1 || e.tg.count() != burstKeep+1 {
		t.Fatalf("slack %d telegram %d, want %d each", e.sl.count(), e.tg.count(), burstKeep+1)
	}
	if !strings.HasPrefix(e.sl.text(burstKeep), "…and 10 more findings") || !strings.HasPrefix(e.tg.text(burstKeep), "…and 10 more findings") {
		t.Errorf("summary: %q / %q", e.sl.text(burstKeep), e.tg.text(burstKeep))
	}
}

func TestPartialDeliveryMemoryAcrossChannels(t *testing.T) {
	hsOK := newFakeHS(t, nil)
	sl := newFakeAPI(t, func(_ int, w http.ResponseWriter) { _, _ = io.WriteString(w, `{"ok":false,"error":"internal_error"}`) })
	mx, _ := NewMatrixChannel(hsOK.srv.URL, "t", hsOK.srv.Client())
	n := newNotifier(t, Config{Default: []string{"!r:x", "slack:" + slackChan}}, nil, mx, testSlack(t, sl))
	ev := testEvent(model.EventExploitable, "CVE-1", "h")
	err := n.Notify(context.Background(), []model.Event{ev})
	var de *DeliveryError
	if !errors.As(err, &de) || len(de.Failed) != 1 {
		t.Fatalf("err = %v", err)
	}
	if len(hsOK.requests()) != 1 {
		t.Fatalf("matrix requests = %d", len(hsOK.requests()))
	}
	slBefore := sl.count()
	_ = n.Notify(context.Background(), []model.Event{ev}) // retry of the failed event
	if len(hsOK.requests()) != 1 {
		t.Errorf("retry re-posted to Matrix: %d requests", len(hsOK.requests()))
	}
	if sl.count() <= slBefore {
		t.Error("retry did not try Slack again")
	}
}

func TestUnconfiguredChannelAtRuntimeIsAPermanentProblem(t *testing.T) {
	hs := newFakeHS(t, nil)
	mx, _ := NewMatrixChannel(hs.srv.URL, "t", hs.srv.Client())
	pl := &problemLog{}
	// a DB-stored route names Slack, but the server runs without a Slack token
	n := newNotifier(t, Config{Default: []string{"!r:x"}, OnDeliveryProblem: pl.add}, staticRoutes{routes: []Route{{Label: "prod", To: []string{"slack:" + slackChan}}}}, mx)
	err := n.Notify(context.Background(), []model.Event{testEvent(model.EventExploitable, "CVE-1", "h", "prod")})
	var de *DeliveryError
	if !errors.As(err, &de) || len(de.Failed) != 1 || !strings.Contains(err.Error(), "slack channel is not configured") {
		t.Fatalf("err = %v", err)
	}
	if ps := pl.all(); len(ps) != 1 || !ps[0].permanent || ps[0].room != "slack:"+slackChan {
		t.Errorf("problems = %+v", ps)
	}
}

func TestInvalidStoredDestinationsAreSkipped(t *testing.T) {
	hs := newFakeHS(t, nil)
	n := newTestMatrix(t, hs, Config{Default: []string{"!def:x"}},
		staticRoutes{routes: []Route{{Label: "prod", To: []string{"https://evil.example/hook", "slack:#general", "!ok:x"}}}})
	if err := n.Notify(context.Background(), []model.Event{testEvent(model.EventExploitable, "CVE-1", "h", "prod")}); err != nil {
		t.Fatal(err)
	}
	if c := hs.roomCounts(); c["!ok:x"] != 1 || len(c) != 1 {
		t.Errorf("rooms = %v", c)
	}
}

func TestNewRejectsInvalidDestinations(t *testing.T) {
	hs := newFakeHS(t, nil)
	mx, _ := NewMatrixChannel(hs.srv.URL, "t", hs.srv.Client())
	for _, cfg := range []Config{
		{Default: []string{"slack:general"}},
		{Ops: []string{"signal:1"}},
		{Routes: []Route{{Label: "a", To: []string{"telegram:@x"}}}},
	} {
		if _, err := New(cfg, nil, mx); err == nil {
			t.Errorf("config %+v accepted", cfg)
		}
	}
}
