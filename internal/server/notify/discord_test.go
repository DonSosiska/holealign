package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/DonSosiska/holealign/internal/model"
)

const (
	testDiscordURL = "https://discord.com/api/webhooks/" + "1234567890123456/AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-secret_token"
	testDiscordTok = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-secret_token"
)

// hookServer is a fake webhook receiver. Tests reach it through a transport that sends every
// request, whatever its URL, to the test server, so the real (validated) URL can be configured.
type hookServer struct {
	t       *testing.T
	srv     *httptest.Server
	mu      sync.Mutex
	reqs    []hookReq
	script  func(call int, w http.ResponseWriter, r *http.Request)
	client  *http.Client
	handled func()
}

type hookReq struct {
	Method, URL string
	Header      http.Header
	Raw         []byte
	Body        map[string]any
}

type rewriteTransport struct{ to *url.URL }

func (rt rewriteTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r2 := r.Clone(r.Context())
	r2.URL.Scheme, r2.URL.Host = rt.to.Scheme, rt.to.Host
	return http.DefaultTransport.RoundTrip(r2)
}

func newHookServer(t *testing.T, script func(call int, w http.ResponseWriter, r *http.Request)) *hookServer {
	t.Helper()
	h := &hookServer{t: t, script: script}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		h.mu.Lock()
		call := len(h.reqs)
		h.reqs = append(h.reqs, hookReq{Method: r.Method, URL: r.URL.String(), Header: r.Header.Clone(), Raw: raw, Body: body})
		h.mu.Unlock()
		if h.script != nil {
			h.script(call, w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"id":"1"}`)
	}))
	t.Cleanup(h.srv.Close)
	u, _ := url.Parse(h.srv.URL)
	h.client = &http.Client{Transport: rewriteTransport{to: u}, Timeout: 10 * time.Second}
	return h
}

func (h *hookServer) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.reqs)
}

func (h *hookServer) req(i int) hookReq {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.reqs[i]
}

func testDiscord(t *testing.T, h *hookServer) *Discord {
	t.Helper()
	d, err := NewDiscordChannel(map[string]string{"ops": testDiscordURL}, h.client)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestDiscordDestinations(t *testing.T) {
	for _, in := range []string{"discord:ops", "discord:a", "discord:prod-eu_1"} {
		if err := ValidateDestination(in); err != nil {
			t.Errorf("%q: %v", in, err)
		}
	}
	for _, in := range []string{"discord:", "discord:Ops", "discord:-x", "discord:" + strings.Repeat("a", 33),
		"discord:https://discord.com/api/webhooks/1/x", "discord:a/b", "discord:a b", "discord:a:b"} {
		if err := ValidateDestination(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestDiscordURLValidation(t *testing.T) {
	if err := ValidDiscordURL(testDiscordURL); err != nil {
		t.Fatal(err)
	}
	if err := ValidDiscordURL(strings.Replace(testDiscordURL, "discord.com", "discordapp.com", 1)); err != nil {
		t.Fatal(err)
	}
	for name, u := range map[string]string{
		"empty":        "",
		"http":         strings.Replace(testDiscordURL, "https", "http", 1),
		"other host":   strings.Replace(testDiscordURL, "discord.com", "evil.example", 1),
		"suffix host":  strings.Replace(testDiscordURL, "discord.com", "discord.com.evil.example", 1),
		"prefix host":  strings.Replace(testDiscordURL, "discord.com", "evildiscord.com", 1),
		"userinfo":     strings.Replace(testDiscordURL, "https://", "https://discord.com@evil.example/", 1),
		"port":         strings.Replace(testDiscordURL, "discord.com", "discord.com:8443", 1),
		"query":        testDiscordURL + "?x=1",
		"empty query":  testDiscordURL + "?",
		"fragment":     testDiscordURL + "#x",
		"wrong path":   strings.Replace(testDiscordURL, "/api/webhooks/", "/api/v10/channels/", 1),
		"short token":  "https://discord.com/api/webhooks/1234567890/abc",
		"no token":     "https://discord.com/api/webhooks/1234567890",
		"bad id":       "https://discord.com/api/webhooks/abc/AbCdEfGhIjKlMnOpQrStUvWxYz",
		"extra path":   testDiscordURL + "/slack",
		"traversal":    "https://discord.com/api/webhooks/1234567890/../../x",
		"not a url":    "::::",
		"scheme-less":  "discord.com/api/webhooks/1234567890/AbCdEfGhIjKlMnOpQrStUvWxYz",
		"ftp":          "ftp://discord.com/api/webhooks/1234567890/AbCdEfGhIjKlMnOpQrStUvWxYz",
		"other scheme": "javascript:alert(1)",
	} {
		err := ValidDiscordURL(u)
		if err == nil {
			t.Errorf("%s: %q accepted", name, u)
		} else if u != "" && strings.Contains(err.Error(), "AbCdEf") {
			t.Errorf("%s: error contains the token: %v", name, err)
		}
	}
	if _, err := NewDiscordChannel(map[string]string{"Bad Name": testDiscordURL}, nil); err == nil {
		t.Error("bad name accepted")
	}
	if _, err := NewDiscordChannel(nil, nil); err == nil {
		t.Error("no webhooks accepted")
	}
}

func TestDiscordRequestShape(t *testing.T) {
	h := newHookServer(t, nil)
	n := newNotifier(t, Config{Default: []string{"discord:ops"}}, nil, testDiscord(t, h))
	if err := n.Notify(context.Background(), []model.Event{testEvent(model.EventExploitable, "CVE-2024-1", "web01")}); err != nil {
		t.Fatal(err)
	}
	if h.count() != 1 {
		t.Fatalf("requests = %d", h.count())
	}
	r := h.req(0)
	if r.Method != "POST" || r.URL != "/api/webhooks/1234567890123456/"+testDiscordTok+"?wait=true" {
		t.Errorf("request %s %s", r.Method, r.URL)
	}
	if r.Header.Get("Content-Type") != "application/json" {
		t.Errorf("content type %q", r.Header.Get("Content-Type"))
	}
	am, _ := r.Body["allowed_mentions"].(map[string]any)
	if p, ok := am["parse"].([]any); !ok || len(p) != 0 {
		t.Errorf("allowed_mentions = %v", r.Body["allowed_mentions"])
	}
	if r.Body["flags"] != float64(4) {
		t.Errorf("flags = %v", r.Body["flags"])
	}
	c, _ := r.Body["content"].(string)
	if !strings.Contains(c, `**EXPLOITABLE\: CVE\-2024\-1 on web01**`) || !strings.Contains(c, "openssl 3.0.1") {
		t.Errorf("content = %q", c)
	}
}

func TestDiscordHostileStringsAreInert(t *testing.T) {
	h := newHookServer(t, nil)
	n := newNotifier(t, Config{Default: []string{"discord:ops"}}, nil, testDiscord(t, h))
	if err := n.Notify(context.Background(), []model.Event{hostile()}); err != nil {
		t.Fatal(err)
	}
	c, _ := h.req(0).Body["content"].(string)
	noCode := regexp.MustCompile("`[^`]*`").ReplaceAllString(c, "")
	for _, bad := range []string{"<@U12345>", "<@", "<#", "<@&", "@everyone", "@here", "@channel", "<a href", "<script>", "[md](https://evil.example)", "<b>"} {
		if strings.Contains(noCode, bad) {
			t.Errorf("content contains %q:\n%s", bad, c)
		}
	}
	// mentions are inert inside code spans as well
	for _, bad := range []string{"<@", "<#", "@everyone", "@here"} {
		if strings.Contains(c, bad) {
			t.Errorf("content (code spans included) contains %q:\n%s", bad, c)
		}
	}
	// the only "<" left are our own <url> links
	for _, m := range regexp.MustCompile(`<[^>]*>`).FindAllString(c, -1) {
		if !strings.HasPrefix(m, "<https://holealign.example/") && !strings.HasPrefix(m, "<"+zwsp) {
			t.Errorf("unexpected angle-bracket construct %q", m)
		}
	}
	if !strings.Contains(c, `\*bold\*`) || !strings.Contains(c, `\[md\]\(https`) {
		t.Errorf("markdown not escaped:\n%s", c)
	}
}

func TestDiscordEscapeSet(t *testing.T) {
	got := discordEsc("a\\b*c_d~e`f|g>h#i-j[k]l(m)n")
	want := `a\\b\*c\_d\~e\` + "`" + `f\|g\>h\#i\-j\[k\]l\(m\)n`
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
	for _, in := range []string{"<@123>", "<@&123>", "<#123>", "@everyone", "@here", "<:e:1>", "<t:1>"} {
		out := discordEsc(in)
		if strings.Contains(out, "<@") || strings.Contains(out, "<#") || strings.Contains(out, "@everyone") || strings.Contains(out, "@here") ||
			strings.Contains(out, "<:") || strings.Contains(out, "<t") {
			t.Errorf("%q -> %q still forms syntax", in, out)
		}
	}
}

func TestDiscordLengthLimit(t *testing.T) {
	var lines []Line
	for i := 0; i < 300; i++ {
		lines = append(lines, Line{txt(strings.Repeat("<*-@", 40))})
	}
	out := formatDiscord(Message{Lines: lines})
	if n := utf8.RuneCountInString(out); n > discordMaxContent {
		t.Errorf("%d characters > %d", n, discordMaxContent)
	}
	if !strings.HasSuffix(out, truncatedNote) {
		t.Error("no truncation note")
	}
	// cut on line boundaries: every kept line is complete
	for _, l := range strings.Split(strings.TrimSuffix(out, "\n"+truncatedNote), "\n") {
		if l != discordEsc(strings.Repeat("<*-@", 40)) {
			t.Errorf("partial line %q", clip(l, 60))
			break
		}
	}
	// one enormous line is cut by characters and still fits
	out = formatDiscord(Message{Lines: []Line{{txt(strings.Repeat("<", 5000))}}})
	if n := utf8.RuneCountInString(out); n > discordMaxContent {
		t.Errorf("single line: %d characters", n)
	}
	// a 10 KB host name through the whole pipeline
	h := newHookServer(t, nil)
	n := newNotifier(t, Config{Default: []string{"discord:ops"}}, nil, testDiscord(t, h))
	ev := testEvent(model.EventExploitable, "CVE-1", strings.Repeat("h<&>", 2500))
	if err := n.Notify(context.Background(), []model.Event{ev}); err != nil {
		t.Fatal(err)
	}
	c, _ := h.req(0).Body["content"].(string)
	if utf8.RuneCountInString(c) > discordMaxContent {
		t.Errorf("host name: %d characters", utf8.RuneCountInString(c))
	}
}

func TestDiscord429RetryAfter(t *testing.T) {
	h := newHookServer(t, func(call int, w http.ResponseWriter, r *http.Request) {
		if call == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"message":"You are being rate limited.","retry_after":0.25,"global":false}`)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	d := testDiscord(t, h)
	msg := buildGroup([]model.Event{testEvent(model.EventExploitable, "CVE-1", "h")})
	err := d.Send(context.Background(), "ops", msg)
	var se *SendError
	if !errors.As(err, &se) || se.Status != 429 || se.Permanent || se.RetryAfter != 250*time.Millisecond {
		t.Fatalf("err = %#v", err)
	}
	// 204 is success; the retry through the notifier works
	h2 := newHookServer(t, func(call int, w http.ResponseWriter, r *http.Request) {
		if call == 0 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	n := newNotifier(t, Config{Default: []string{"discord:ops"}}, nil, testDiscord(t, h2))
	if err := n.Notify(context.Background(), []model.Event{testEvent(model.EventExploitable, "CVE-1", "h")}); err != nil {
		t.Fatal(err)
	}
	if h2.count() != 2 {
		t.Errorf("attempts = %d, want 2", h2.count())
	}
	// Retry-After header when the body has none
	h3 := newHookServer(t, func(call int, w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "3")
		w.WriteHeader(http.StatusTooManyRequests)
	})
	err = testDiscord(t, h3).Send(context.Background(), "ops", msg)
	if !errors.As(err, &se) || se.RetryAfter != 3*time.Second {
		t.Fatalf("header retry-after: %#v", err)
	}
}

func TestDiscordErrorMapping(t *testing.T) {
	cases := []struct {
		status    int
		permanent bool
		attempts  int
	}{
		{400, true, 1}, {401, true, 1}, {403, true, 1}, {404, true, 1}, {302, true, 1},
		{429, false, maxAttempts}, {500, false, maxAttempts}, {503, false, maxAttempts},
	}
	for _, c := range cases {
		h := newHookServer(t, func(_ int, w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "https://evil.example/")
			w.WriteHeader(c.status)
			_, _ = io.WriteString(w, `{"message":"Unknown Webhook","code":10015}`)
		})
		pl := &problemLog{}
		n := newNotifier(t, Config{Default: []string{"discord:ops"}, OnDeliveryProblem: pl.add}, nil, testDiscord(t, h))
		_ = n.Notify(context.Background(), []model.Event{testEvent(model.EventExploitable, "CVE-1", "h")})
		if h.count() != c.attempts {
			t.Errorf("%d: attempts = %d, want %d", c.status, h.count(), c.attempts)
		}
		ps := pl.all()
		if len(ps) != 1 || ps[0].status != c.status || ps[0].permanent != c.permanent || ps[0].room != "discord:ops" {
			t.Errorf("%d: problems = %+v", c.status, ps)
		}
	}
	// an unconfigured name is a permanent failure and never a request
	h := newHookServer(t, nil)
	err := testDiscord(t, h).Send(context.Background(), "other", Message{Lines: []Line{{txt("x")}}})
	var se *SendError
	if !errors.As(err, &se) || !se.Permanent || h.count() != 0 {
		t.Errorf("unknown name: %v, requests %d", err, h.count())
	}
}

func TestDiscordWebhookNeverInErrors(t *testing.T) {
	// error body that echoes the URL, and a transport error that carries it
	h := newHookServer(t, func(_ int, w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, "bad request "+testDiscordURL+" token "+testDiscordTok)
	})
	d := testDiscord(t, h)
	err := d.Send(context.Background(), "ops", Message{Lines: []Line{{txt("x")}}})
	if err == nil || strings.Contains(err.Error(), testDiscordTok) || strings.Contains(err.Error(), "discord.com/api") {
		t.Errorf("error leaks the webhook: %v", err)
	}
	d2, _ := NewDiscordChannel(map[string]string{"ops": testDiscordURL}, &http.Client{Transport: failingTransport{}})
	err = d2.Send(context.Background(), "ops", Message{Lines: []Line{{txt("x")}}})
	if err == nil || strings.Contains(err.Error(), testDiscordTok) || strings.Contains(err.Error(), "/api/webhooks") {
		t.Errorf("network error leaks the webhook: %v", err)
	}
	// the error the Notifier returns (and logs) carries no token either
	n := newNotifier(t, Config{Default: []string{"discord:ops"}}, nil, d2)
	if nerr := n.Notify(context.Background(), []model.Event{testEvent(model.EventExploitable, "CVE-1", "h")}); nerr == nil ||
		strings.Contains(nerr.Error(), testDiscordTok) {
		t.Errorf("notifier error: %v", nerr)
	}
}

// failingTransport fails like a dial error that names the request URL.
type failingTransport struct{}

func (failingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return nil, errors.New("dial tcp: lookup " + r.URL.Host + " failed for " + r.URL.String() + " " + r.URL.Path)
}

func TestDiscordDoesNotFollowRedirects(t *testing.T) {
	var hit int
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit++ }))
	defer evil.Close()
	h := newHookServer(t, func(_ int, w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL, http.StatusTemporaryRedirect)
	})
	err := testDiscord(t, h).Send(context.Background(), "ops", Message{Lines: []Line{{txt("x")}}})
	var se *SendError
	if !errors.As(err, &se) || !se.Permanent || se.Status != 307 || hit != 0 {
		t.Errorf("err = %v, redirect target hit %d times", err, hit)
	}
}
