package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DonSosiska/holealign/internal/model"
)

const (
	testHookSecret = "0123456789abcdef-webhook-secret"
	testHookURL    = "https://hooks.example.org/holealign/in?token=URLTOKEN123456"
)

func testWebhook(t *testing.T, h *hookServer, headers map[string]string) *Webhook {
	t.Helper()
	w, err := NewWebhookChannel(map[string]WebhookEndpoint{"siem": {URL: testHookURL, Secret: testHookSecret, Headers: headers}}, h.client)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestWebhookDestinations(t *testing.T) {
	if err := ValidateDestination("webhook:siem"); err != nil {
		t.Error(err)
	}
	for _, in := range []string{"webhook:", "webhook:SIEM", "webhook:https://x.example/", "webhook:a/b", "webhook:a b"} {
		if err := ValidateDestination(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestWebhookConstructorValidation(t *testing.T) {
	ok := WebhookEndpoint{URL: testHookURL, Secret: testHookSecret}
	if _, err := NewWebhookChannel(map[string]WebhookEndpoint{"a": ok}, nil); err != nil {
		t.Fatal(err)
	}
	bad := map[string]WebhookEndpoint{
		"http":          {URL: "http://hooks.example.org/x", Secret: testHookSecret},
		"no host":       {URL: "https:///x", Secret: testHookSecret},
		"userinfo":      {URL: "https://u:p@hooks.example.org/x", Secret: testHookSecret},
		"ftp":           {URL: "ftp://hooks.example.org/x", Secret: testHookSecret},
		"no secret":     {URL: testHookURL},
		"short secret":  {URL: testHookURL, Secret: "short"},
		"newline hdr":   {URL: testHookURL, Secret: testHookSecret, Headers: map[string]string{"X-A": "a\r\nX-Evil: 1"}},
		"bad hdr name":  {URL: testHookURL, Secret: testHookSecret, Headers: map[string]string{"X A": "a"}},
		"reserved sig":  {URL: testHookURL, Secret: testHookSecret, Headers: map[string]string{"x-holealign-signature": "a"}},
		"reserved host": {URL: testHookURL, Secret: testHookSecret, Headers: map[string]string{"Host": "evil"}},
		"reserved ctyp": {URL: testHookURL, Secret: testHookSecret, Headers: map[string]string{"Content-Type": "text/plain"}},
	}
	for name, ep := range bad {
		if _, err := NewWebhookChannel(map[string]WebhookEndpoint{"a": ep}, nil); err == nil {
			t.Errorf("%s accepted", name)
		} else if strings.Contains(err.Error(), "URLTOKEN") || strings.Contains(err.Error(), testHookSecret) {
			t.Errorf("%s: error leaks a secret: %v", name, err)
		}
	}
	if _, err := NewWebhookChannel(map[string]WebhookEndpoint{"a": {URL: "http://127.0.0.1:9/x", Secret: testHookSecret, AllowHTTP: true}}, nil); err != nil {
		t.Errorf("allow_http: %v", err)
	}
	if _, err := NewWebhookChannel(map[string]WebhookEndpoint{"Bad": ok}, nil); err == nil {
		t.Error("bad name accepted")
	}
}

func TestWebhookPayloadAndSignature(t *testing.T) {
	h := newHookServer(t, func(_ int, w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	n := newNotifier(t, Config{Default: []string{"webhook:siem"}}, nil, testWebhook(t, h, map[string]string{"Authorization": "Bearer abc123456"}))
	ev := testEvent(model.EventExploitable, "CVE-2024-1", "web01", "prod", "eu")
	ev.Finding.Aliases = []string{"GHSA-xxxx"}
	ev.Finding.FixedVersions = []string{"3.0.2", "3.0.3"}
	ev.Finding.EPSS = 0.42
	ev.Finding.KEV = true
	ev.Finding.VerdictReason = "reachable via nginx"
	ev.WebURL = "https://holealign.example/findings/9"
	if err := n.Notify(context.Background(), []model.Event{ev}); err != nil {
		t.Fatal(err)
	}
	if h.count() != 1 {
		t.Fatalf("requests = %d", h.count())
	}
	r := h.req(0)
	if r.Method != "POST" || r.URL != "/holealign/in?token=URLTOKEN123456" {
		t.Errorf("request %s %s", r.Method, r.URL)
	}
	if r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Authorization") != "Bearer abc123456" {
		t.Errorf("headers = %v", r.Header)
	}
	var p WebhookPayload
	if err := json.Unmarshal(r.Raw, &p); err != nil {
		t.Fatal(err)
	}
	if p.Version != 1 || p.Kind != "exploitable" || !strings.HasPrefix(p.ID, "holealign-") || p.ID != r.Header.Get(WebhookEventIDHeader) {
		t.Errorf("payload = %+v", p)
	}
	if _, err := time.Parse(time.RFC3339, p.SentAt); err != nil {
		t.Errorf("sent_at = %q", p.SentAt)
	}
	if !strings.Contains(p.Title, "EXPLOITABLE: CVE-2024-1 on web01") || !strings.Contains(p.Text, "Package: openssl 3.0.1") || strings.Contains(p.Text, "<") {
		t.Errorf("title %q text %q", p.Title, p.Text)
	}
	if len(p.Events) != 1 {
		t.Fatalf("events = %+v", p.Events)
	}
	e := p.Events[0]
	want := MessageEvent{Kind: "exploitable", Host: "web01", Labels: []string{"prod", "eu"}, VulnID: "CVE-2024-1", Aliases: []string{"GHSA-xxxx"},
		Package: "openssl", Version: "3.0.1", FixedVersion: "3.0.2, 3.0.3", Verdict: "exploitable", Severity: "High", CVSS: 7.5, EPSS: 0.42, KEV: true,
		Reason: "reachable via nginx", FindingURL: "https://holealign.example/findings/9"}
	if e.Kind != want.Kind || e.Host != want.Host || strings.Join(e.Labels, ",") != "prod,eu" || e.VulnID != want.VulnID ||
		strings.Join(e.Aliases, ",") != "GHSA-xxxx" || e.Package != want.Package || e.Version != want.Version || e.FixedVersion != want.FixedVersion ||
		e.Verdict != want.Verdict || e.Severity != want.Severity || e.CVSS != want.CVSS || e.EPSS != want.EPSS || !e.KEV ||
		e.Reason != want.Reason || e.FindingURL != want.FindingURL {
		t.Errorf("event = %+v\nwant   %+v", e, want)
	}
	// the schema keys are exactly the documented ones
	var generic map[string]any
	_ = json.Unmarshal(r.Raw, &generic)
	for _, k := range []string{"version", "id", "kind", "sent_at", "title", "text", "events"} {
		if _, ok := generic[k]; !ok {
			t.Errorf("payload has no %q", k)
		}
	}
	evKeys := generic["events"].([]any)[0].(map[string]any)
	for _, k := range []string{"kind", "host", "labels", "vuln_id", "aliases", "package", "version", "fixed_version", "verdict", "severity", "cvss", "epss", "kev", "reason", "finding_url"} {
		if _, ok := evKeys[k]; !ok {
			t.Errorf("event has no %q", k)
		}
	}
	if len(evKeys) != 15 {
		t.Errorf("event has %d keys", len(evKeys))
	}
	// signature round trip: a receiver recomputes the HMAC over "<t>.<body>"
	sig := r.Header.Get(WebhookSignatureHeader)
	if err := VerifyWebhookSignature(testHookSecret, sig, r.Raw, time.Now(), 5*time.Minute); err != nil {
		t.Errorf("signature: %v", err)
	}
	if !strings.HasPrefix(sig, "t=") || !strings.Contains(sig, ",v1=") {
		t.Errorf("signature format %q", sig)
	}
}

func TestWebhookSignatureVerification(t *testing.T) {
	body := []byte(`{"version":1}`)
	now := time.Unix(1_700_000_000, 0)
	good := WebhookSignature(testHookSecret, now.Unix(), body)
	if err := VerifyWebhookSignature(testHookSecret, good, body, now.Add(time.Minute), 5*time.Minute); err != nil {
		t.Error(err)
	}
	for name, c := range map[string]struct {
		secret, header string
		body           []byte
		at             time.Time
	}{
		"wrong secret": {"other-secret-0123456", good, body, now},
		"tampered":     {testHookSecret, good, []byte(`{"version":2}`), now},
		"old":          {testHookSecret, good, body, now.Add(6 * time.Minute)},
		"future":       {testHookSecret, good, body, now.Add(-6 * time.Minute)},
		"retimed":      {testHookSecret, strings.Replace(good, "t=1700000000", "t=1700000001", 1), body, now},
		"no v1":        {testHookSecret, "t=1700000000", body, now},
		"garbage":      {testHookSecret, "nonsense", body, now},
		"empty":        {testHookSecret, "", body, now},
	} {
		if err := VerifyWebhookSignature(c.secret, c.header, c.body, c.at, 5*time.Minute); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
	// known answer, computed independently, so receivers in other languages can test against it
	if got := WebhookSignature("key", 1700000000, []byte("body")); got != "t=1700000000,v1=47b6ce0fca59474308e2921c247cb2493dce6b8101d90ac05bd0c6a37d0e046e" {
		t.Errorf("signature = %q", got)
	}
}

func TestWebhookEventIDStableAcrossRetries(t *testing.T) {
	h := newHookServer(t, func(call int, w http.ResponseWriter, r *http.Request) {
		if call < 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	n := newNotifier(t, Config{Default: []string{"webhook:siem"}}, nil, testWebhook(t, h, nil))
	if err := n.Notify(context.Background(), []model.Event{testEvent(model.EventExploitable, "CVE-1", "h")}); err != nil {
		t.Fatal(err)
	}
	if h.count() != 3 {
		t.Fatalf("attempts = %d", h.count())
	}
	id := h.req(0).Header.Get(WebhookEventIDHeader)
	for i := 0; i < 3; i++ {
		r := h.req(i)
		if r.Header.Get(WebhookEventIDHeader) != id || id == "" {
			t.Errorf("attempt %d: event id %q != %q", i, r.Header.Get(WebhookEventIDHeader), id)
		}
		if err := VerifyWebhookSignature(testHookSecret, r.Header.Get(WebhookSignatureHeader), r.Raw, time.Now(), 5*time.Minute); err != nil {
			t.Errorf("attempt %d: %v", i, err)
		}
	}
}

func TestWebhookSummaryAndHealthMessages(t *testing.T) {
	p := BuildWebhookPayload(summaryMessage(nil, ""), time.Unix(0, 0))
	if p.Kind != "summary" || p.Events == nil || len(p.Events) != 0 {
		t.Errorf("summary payload = %+v", p)
	}
	raw, _ := json.Marshal(p)
	if !strings.Contains(string(raw), `"events":[]`) {
		t.Errorf("events must be an empty array: %s", raw)
	}
	ev := model.Event{Kind: model.EventFeedStale, Detail: "feed is 9 days old\nlast ok: yesterday"}
	m := buildGroup([]model.Event{ev})
	p = BuildWebhookPayload(m, time.Now())
	if p.Kind != "feed_stale" && p.Kind != string(model.EventFeedStale) || len(p.Events) != 1 || !strings.Contains(p.Events[0].Reason, "9 days") {
		t.Errorf("health payload = %+v", p)
	}
}

func TestWebhookHostileAndHugeValues(t *testing.T) {
	h := newHookServer(t, nil)
	n := newNotifier(t, Config{Default: []string{"webhook:siem"}}, nil, testWebhook(t, h, nil))
	ev := hostile()
	ev.Host.Hostname = strings.Repeat("h<&>\r\n\x00", 2500) + "@everyone"
	if err := n.Notify(context.Background(), []model.Event{ev}); err != nil {
		t.Fatal(err)
	}
	r := h.req(0)
	if !json.Valid(r.Raw) {
		t.Fatal("body is not valid JSON")
	}
	if len(r.Raw) > 64<<10 {
		t.Errorf("body is %d bytes", len(r.Raw))
	}
	var p WebhookPayload
	_ = json.Unmarshal(r.Raw, &p)
	if got := len([]rune(p.Events[0].Host)); got > maxFieldRunes+1 {
		t.Errorf("host has %d runes", got)
	}
	if strings.ContainsAny(p.Events[0].Host, "\r\n\x00") {
		t.Error("control characters in host")
	}
	// structured fields are data, not markup: no escaping
	if !strings.Contains(p.Events[0].Reason, "<script>") {
		t.Errorf("reason was altered: %q", p.Events[0].Reason)
	}
}

func TestWebhookErrorMapping(t *testing.T) {
	cases := []struct {
		status    int
		permanent bool
		attempts  int
	}{
		{200, false, 1}, {201, false, 1}, {204, false, 1},
		{400, true, 1}, {401, true, 1}, {403, true, 1}, {404, true, 1}, {410, true, 1}, {422, true, 1}, {302, true, 1},
		{429, false, maxAttempts}, {500, false, maxAttempts}, {503, false, maxAttempts},
	}
	for _, c := range cases {
		h := newHookServer(t, func(_ int, w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "https://evil.example/")
			w.WriteHeader(c.status)
		})
		pl := &problemLog{}
		n := newNotifier(t, Config{Default: []string{"webhook:siem"}, OnDeliveryProblem: pl.add}, nil, testWebhook(t, h, nil))
		_ = n.Notify(context.Background(), []model.Event{testEvent(model.EventExploitable, "CVE-1", "h")})
		if h.count() != c.attempts {
			t.Errorf("%d: attempts = %d, want %d", c.status, h.count(), c.attempts)
		}
		ps := pl.all()
		if c.status/100 == 2 {
			if len(ps) != 0 {
				t.Errorf("%d: unexpected problems %+v", c.status, ps)
			}
			continue
		}
		if len(ps) != 1 || ps[0].status != c.status || ps[0].permanent != c.permanent {
			t.Errorf("%d: problems = %+v", c.status, ps)
		}
	}
}

func TestWebhook429RetryAfter(t *testing.T) {
	h := newHookServer(t, func(_ int, w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "12")
		w.WriteHeader(http.StatusTooManyRequests)
	})
	err := testWebhook(t, h, nil).Send(context.Background(), "siem", Message{ID: "x", Lines: []Line{{txt("x")}}})
	var se *SendError
	if !errors.As(err, &se) || se.Status != 429 || se.RetryAfter != 12*time.Second || se.Permanent {
		t.Fatalf("err = %#v", err)
	}
}

func TestWebhookResponseBodyIsCappedAndNoRedirects(t *testing.T) {
	var hits int
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer evil.Close()
	h := newHookServer(t, func(call int, w http.ResponseWriter, r *http.Request) {
		if call == 0 {
			http.Redirect(w, r, evil.URL, http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, strings.Repeat("x", 10<<20))
	})
	w := testWebhook(t, h, nil)
	if err := w.Send(context.Background(), "siem", Message{ID: "x", Lines: []Line{{txt("x")}}}); err == nil || hits != 0 {
		t.Errorf("redirect: err = %v hits = %d", err, hits)
	}
	err := w.Send(context.Background(), "siem", Message{ID: "x", Lines: []Line{{txt("x")}}})
	if err == nil || len(err.Error()) > 400 {
		t.Errorf("error is %d bytes: %v", len(err.Error()), clip(err.Error(), 100))
	}
}

func TestWebhookSecretsNeverInErrors(t *testing.T) {
	h := newHookServer(t, func(_ int, w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, "denied "+testHookURL+" secret="+testHookSecret+" auth="+r.Header.Get("Authorization")+" token=URLTOKEN123456")
	})
	w := testWebhook(t, h, map[string]string{"Authorization": "Bearer abcdefghijkl"})
	for name, ch := range map[string]*Webhook{"http error": w, "network error": func() *Webhook {
		c, _ := NewWebhookChannel(map[string]WebhookEndpoint{"siem": {URL: testHookURL, Secret: testHookSecret}}, &http.Client{Transport: failingTransport{}})
		return c
	}()} {
		err := ch.Send(context.Background(), "siem", Message{ID: "x", Lines: []Line{{txt("x")}}})
		if err == nil {
			t.Fatalf("%s: no error", name)
		}
		for _, leak := range []string{testHookSecret, "URLTOKEN123456", "abcdefghijkl", "/holealign/in"} {
			if strings.Contains(err.Error(), leak) {
				t.Errorf("%s: error contains %q: %v", name, leak, err)
			}
		}
	}
}
