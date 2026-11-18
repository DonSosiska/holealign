package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DonSosiska/holealign/internal/model"
)

// recorded is one request seen by the fake homeserver.
type recorded struct {
	room, txn, auth, ctype string
	body                   message
}

// fakeHS is an httptest server that records requests and answers them via script.
type fakeHS struct {
	t      *testing.T
	srv    *httptest.Server
	mu     sync.Mutex
	reqs   []recorded
	script func(call int, rec recorded) (status int, body string)
}

func newFakeHS(t *testing.T, script func(call int, rec recorded) (int, string)) *fakeHS {
	t.Helper()
	f := &fakeHS{t: t, script: script}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeHS) serve(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	rec := recorded{auth: r.Header.Get("Authorization"), ctype: r.Header.Get("Content-Type")}
	rec.room, rec.txn = parsePath(r.URL.Path)
	if r.Method != http.MethodPut {
		f.t.Errorf("method = %s, want PUT", r.Method)
	}
	if err := json.Unmarshal(raw, &rec.body); err != nil {
		f.t.Errorf("body is not JSON: %v", err)
	}
	f.mu.Lock()
	call := len(f.reqs)
	f.reqs = append(f.reqs, rec)
	script := f.script
	f.mu.Unlock()

	status, body := http.StatusOK, `{"event_id":"$ok"}`
	if script != nil {
		status, body = script(call, rec)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

// parsePath extracts the decoded room ID and txnId from a send path.
func parsePath(p string) (room, txn string) {
	const pre, mid = "/_matrix/client/v3/rooms/", "/send/m.room.message/"
	rest := strings.TrimPrefix(p, pre)
	i := strings.Index(rest, mid)
	if i < 0 {
		return "", ""
	}
	return rest[:i], rest[i+len(mid):]
}

func (f *fakeHS) requests() []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recorded(nil), f.reqs...)
}

func (f *fakeHS) roomCounts() map[string]int {
	counts := map[string]int{}
	for _, r := range f.requests() {
		counts[r.room]++
	}
	return counts
}

func newTestMatrix(t *testing.T, hs *fakeHS, cfg Config, routes RouteSource) *Notifier {
	t.Helper()
	ch, err := NewMatrixChannel(hs.srv.URL, "secret-token", hs.srv.Client())
	if err != nil {
		t.Fatalf("NewMatrixChannel: %v", err)
	}
	m, err := New(cfg, routes, ch)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m.backoff = time.Millisecond // keep retry tests fast
	return m
}

// staticRoutes is a RouteSource returning fixed routes.
type staticRoutes struct {
	routes []Route
	err    error
}

func (s staticRoutes) Routes(context.Context) ([]Route, error) { return s.routes, s.err }

func testEvent(kind model.EventKind, vuln, host string, labels ...string) model.Event {
	return model.Event{
		Kind: kind,
		Finding: model.Finding{
			VulnID:      vuln,
			PackageName: "openssl",
			PackageVer:  "3.0.1",
			Severity:    "High",
			CVSS:        7.5,
			Verdict:     model.VerdictExploitable,
		},
		Host: model.Host{ID: "id-" + host, Hostname: host, Labels: labels},
	}
}

func TestNewMatrixValidation(t *testing.T) {
	if _, err := NewMatrixChannel("https://matrix.example.com", "t", nil); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	cases := map[string][2]string{
		"empty homeserver": {"", "t"},
		"bad scheme":       {"ftp://matrix.example.com", "t"},
		"no host":          {"https://", "t"},
		"empty token":      {"https://matrix.example.com", ""},
	}
	for name, c := range cases {
		if _, err := NewMatrixChannel(c[0], c[1], nil); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := New(Config{}, nil); err == nil {
		t.Error("New without channels accepted")
	}
}

func TestDeliveryPathAuthAndBody(t *testing.T) {
	hs := newFakeHS(t, nil)
	m := newTestMatrix(t, hs, Config{Default: []string{"!room:example.org"}}, nil)

	ev := testEvent(model.EventExploitable, "CVE-2024-1", "web01")
	if err := m.Notify(context.Background(), []model.Event{ev}); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	reqs := hs.requests()
	if len(reqs) != 1 {
		t.Fatalf("requests = %d, want 1", len(reqs))
	}
	r := reqs[0]
	if r.room != "!room:example.org" {
		t.Errorf("room = %q", r.room)
	}
	if r.auth != "Bearer secret-token" {
		t.Errorf("Authorization = %q", r.auth)
	}
	if r.ctype != "application/json" {
		t.Errorf("Content-Type = %q", r.ctype)
	}
	if !strings.HasPrefix(r.txn, "holealign-") {
		t.Errorf("txnId = %q", r.txn)
	}
	if r.body.MsgType != "m.text" || r.body.Format != "org.matrix.custom.html" {
		t.Errorf("msgtype/format = %q/%q", r.body.MsgType, r.body.Format)
	}
	if !strings.Contains(r.body.Body, "EXPLOITABLE: CVE-2024-1 on web01") {
		t.Errorf("body = %q", r.body.Body)
	}
	if !strings.Contains(r.body.FormattedBody, "<b>EXPLOITABLE: CVE-2024-1 on web01</b>") {
		t.Errorf("formatted_body = %q", r.body.FormattedBody)
	}
}

func TestRoomIDIsPathEscaped(t *testing.T) {
	var rawPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawPath = r.URL.EscapedPath()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	ch, err := NewMatrixChannel(srv.URL, "t", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	m, err := New(Config{Default: []string{"!room:example.org"}}, nil, ch)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Notify(context.Background(), []model.Event{testEvent(model.EventResolved, "CVE-1", "h")}); err != nil {
		t.Fatal(err)
	}
	want := "/_matrix/client/v3/rooms/%21room:example.org/send/m.room.message/holealign-"
	if !strings.HasPrefix(rawPath, want) {
		t.Errorf("escaped path = %q, want prefix %q", rawPath, want)
	}
}

func TestTxnIDUnique(t *testing.T) {
	hs := newFakeHS(t, nil)
	m := newTestMatrix(t, hs, Config{Default: []string{"!r:example.org"}}, nil)

	seen := map[string]bool{}
	for range 1000 {
		id := m.newID()
		if seen[id] {
			t.Fatalf("duplicate txnId %q", id)
		}
		seen[id] = true
	}

	var events []model.Event
	for i := range 3 {
		events = append(events, testEvent(model.EventExploitable, fmt.Sprintf("CVE-%d", i), "h"))
	}
	if err := m.Notify(context.Background(), events); err != nil {
		t.Fatal(err)
	}
	txns := map[string]bool{}
	for _, r := range hs.requests() {
		txns[r.txn] = true
	}
	if len(txns) != 3 {
		t.Errorf("distinct txnIds = %d, want 3", len(txns))
	}
}

func TestRetry429HonoursRetryAfter(t *testing.T) {
	hs := newFakeHS(t, func(call int, _ recorded) (int, string) {
		if call == 0 {
			return http.StatusTooManyRequests, `{"errcode":"M_LIMIT_EXCEEDED","retry_after_ms":60}`
		}
		return http.StatusOK, `{}`
	})
	m := newTestMatrix(t, hs, Config{Default: []string{"!r:example.org"}}, nil)

	start := time.Now()
	if err := m.Notify(context.Background(), []model.Event{testEvent(model.EventExploitable, "CVE-1", "h")}); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 60*time.Millisecond {
		t.Errorf("returned after %v, expected to honour retry_after_ms=60", elapsed)
	}
	reqs := hs.requests()
	if len(reqs) != 2 {
		t.Fatalf("requests = %d, want 2", len(reqs))
	}
	if reqs[0].txn != reqs[1].txn {
		t.Errorf("txnId changed across retry: %q vs %q", reqs[0].txn, reqs[1].txn)
	}
}

func TestRetryAfterCapped(t *testing.T) {
	if got := min(matrixRetryAfter([]byte(`{"retry_after_ms": 90000000}`)), maxRetryWait); got != maxRetryWait {
		t.Errorf("retryAfter cap = %v, want %v", got, maxRetryWait)
	}
	if got := matrixRetryAfter([]byte(`not json`)); got != 0 {
		t.Errorf("retryAfter on bad body = %v, want 0", got)
	}
}

func TestRetry5xxThenSuccess(t *testing.T) {
	hs := newFakeHS(t, func(call int, _ recorded) (int, string) {
		if call < 2 {
			return http.StatusServiceUnavailable, `{}`
		}
		return http.StatusOK, `{}`
	})
	m := newTestMatrix(t, hs, Config{Default: []string{"!r:example.org"}}, nil)
	if err := m.Notify(context.Background(), []model.Event{testEvent(model.EventExploitable, "CVE-1", "h")}); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if n := len(hs.requests()); n != 3 {
		t.Errorf("requests = %d, want 3", n)
	}
}

func TestNoRetryOn4xx(t *testing.T) {
	hs := newFakeHS(t, func(int, recorded) (int, string) {
		return http.StatusForbidden, `{"errcode":"M_FORBIDDEN"}`
	})
	m := newTestMatrix(t, hs, Config{Default: []string{"!r:example.org"}}, nil)
	err := m.Notify(context.Background(), []model.Event{testEvent(model.EventExploitable, "CVE-1", "h")})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v, want a 403 error", err)
	}
	if n := len(hs.requests()); n != 1 {
		t.Errorf("requests = %d, want 1 (no retry on 4xx)", n)
	}
}

func TestGivesUpAfterMaxAttempts(t *testing.T) {
	hs := newFakeHS(t, func(int, recorded) (int, string) {
		return http.StatusInternalServerError, `{}`
	})
	m := newTestMatrix(t, hs, Config{Default: []string{"!r:example.org"}}, nil)
	err := m.Notify(context.Background(), []model.Event{testEvent(model.EventExploitable, "CVE-1", "h")})
	if err == nil {
		t.Fatal("expected error after exhausting retries")
	}
	if n := len(hs.requests()); n != maxAttempts {
		t.Errorf("requests = %d, want %d", n, maxAttempts)
	}
}

func TestContextCancelDuringBackoff(t *testing.T) {
	hs := newFakeHS(t, func(int, recorded) (int, string) {
		return http.StatusBadGateway, `{}`
	})
	m := newTestMatrix(t, hs, Config{Default: []string{"!r:example.org"}}, nil)
	m.backoff = time.Hour // the first retry would wait forever without cancellation

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := m.Notify(ctx, []model.Event{testEvent(model.EventExploitable, "CVE-1", "h")})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("Notify took %v after cancel", elapsed)
	}
}

func TestContextAlreadyCancelled(t *testing.T) {
	hs := newFakeHS(t, nil)
	m := newTestMatrix(t, hs, Config{Default: []string{"!r:example.org"}}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := m.Notify(ctx, []model.Event{testEvent(model.EventExploitable, "CVE-1", "h")})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if n := len(hs.requests()); n != 0 {
		t.Errorf("requests = %d, want 0", n)
	}
}

func TestRouting(t *testing.T) {
	const (
		prod   = "!prod:example.org"
		web    = "!web:example.org"
		deflt  = "!default:example.org"
		shared = "!shared:example.org"
	)
	cfg := Config{
		Default: []string{deflt},
		Routes: []Route{
			{Label: "prod", To: []string{prod}},
			{Label: "web", To: []string{web}},
			{Label: "edge", To: []string{prod, shared}},
		},
	}
	cases := []struct {
		name   string
		labels []string
		want   map[string]int
	}{
		{"single label", []string{"prod"}, map[string]int{prod: 1}},
		{"two labels, two rooms", []string{"prod", "web"}, map[string]int{prod: 1, web: 1}},
		{"overlapping rooms delivered once", []string{"prod", "edge"}, map[string]int{prod: 1, shared: 1}},
		{"no matching label uses default", []string{"unknown"}, map[string]int{deflt: 1}},
		{"no labels uses default", nil, map[string]int{deflt: 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hs := newFakeHS(t, nil)
			m := newTestMatrix(t, hs, cfg, nil)
			ev := testEvent(model.EventExploitable, "CVE-1", "h", tc.labels...)
			if err := m.Notify(context.Background(), []model.Event{ev}); err != nil {
				t.Fatal(err)
			}
			got := hs.roomCounts()
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Errorf("rooms = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNoRoomIsAnError(t *testing.T) {
	hs := newFakeHS(t, nil)
	m := newTestMatrix(t, hs, Config{Routes: []Route{{Label: "prod", To: []string{"!p:x"}}}}, nil)
	err := m.Notify(context.Background(), []model.Event{
		testEvent(model.EventExploitable, "CVE-1", "h", "dev"),
		testEvent(model.EventResolved, "CVE-2", "h", "dev"),
	})
	var de *DeliveryError
	if !errors.As(err, &de) || !strings.Contains(err.Error(), "no notification destination") {
		t.Fatalf("Notify: %v, want a DeliveryError naming the missing destination", err)
	}
	if len(de.Failed) != 1 || de.Failed[0] != 0 {
		t.Errorf("Failed = %v, want only the exploitable event [0]", de.Failed)
	}
	if n := len(hs.requests()); n != 0 {
		t.Errorf("requests = %d, want 0", n)
	}
}

func TestDBRoutesMerged(t *testing.T) {
	hs := newFakeHS(t, nil)
	db := staticRoutes{routes: []Route{
		{Label: "prod", To: []string{"!db:example.org", "!cfg:example.org"}},
		{Label: "db-only", To: []string{"!dbonly:example.org"}},
	}}
	cfg := Config{
		Default: []string{"!default:example.org"},
		Routes:  []Route{{Label: "prod", To: []string{"!cfg:example.org"}}},
	}
	m := newTestMatrix(t, hs, cfg, db)

	events := []model.Event{
		testEvent(model.EventExploitable, "CVE-1", "h", "prod"),
		testEvent(model.EventExploitable, "CVE-2", "h", "db-only"),
	}
	if err := m.Notify(context.Background(), events); err != nil {
		t.Fatal(err)
	}
	got := hs.roomCounts()
	want := map[string]int{"!cfg:example.org": 1, "!db:example.org": 1, "!dbonly:example.org": 1}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("rooms = %v, want %v", got, want)
	}
}

func TestDBRouteErrorStillDeliversConfigRoutes(t *testing.T) {
	hs := newFakeHS(t, nil)
	m := newTestMatrix(t, hs, Config{Routes: []Route{{Label: "prod", To: []string{"!p:example.org"}}}},
		staticRoutes{err: errors.New("db down")})
	err := m.Notify(context.Background(), []model.Event{testEvent(model.EventExploitable, "CVE-1", "h", "prod")})
	if err == nil || !strings.Contains(err.Error(), "db down") {
		t.Errorf("err = %v, want db error", err)
	}
	if n := hs.roomCounts()["!p:example.org"]; n != 1 {
		t.Errorf("config room got %d messages, want 1", n)
	}
}

func TestRoomFailureDoesNotStopOtherRooms(t *testing.T) {
	const bad, good = "!bad:example.org", "!good:example.org"
	hs := newFakeHS(t, func(_ int, rec recorded) (int, string) {
		if rec.room == bad {
			return http.StatusForbidden, `{"errcode":"M_FORBIDDEN"}`
		}
		return http.StatusOK, `{}`
	})
	cfg := Config{Routes: []Route{
		{Label: "a", To: []string{bad}},
		{Label: "b", To: []string{good}},
	}}
	m := newTestMatrix(t, hs, cfg, nil)
	events := []model.Event{testEvent(model.EventExploitable, "CVE-1", "h", "a", "b")}
	err := m.Notify(context.Background(), events)
	if err == nil || !strings.Contains(err.Error(), bad) {
		t.Errorf("err = %v, want error naming %s", err, bad)
	}
	if strings.Contains(fmt.Sprint(err), good) {
		t.Errorf("err mentions the successful room: %v", err)
	}
	if n := hs.roomCounts()[good]; n != 1 {
		t.Errorf("good room got %d messages, want 1", n)
	}
}

func TestBurstSummary(t *testing.T) {
	hs := newFakeHS(t, nil)
	m := newTestMatrix(t, hs, Config{Default: []string{"!r:example.org"}}, nil)

	// 12 exploitable (CVSS = index) and 8 unknown_critical; index 19 is KEV.
	var events []model.Event
	for i := range 20 {
		kind := model.EventExploitable
		if i >= 12 {
			kind = model.EventUnknownCritical
		}
		ev := testEvent(kind, fmt.Sprintf("CVE-%d", i), "web01")
		ev.Finding.CVSS = float64(i)
		ev.WebURL = "https://holealign.example/findings/" + fmt.Sprint(i)
		if i == 19 {
			ev.Finding.KEV = true
		}
		events = append(events, ev)
	}
	if err := m.Notify(context.Background(), events); err != nil {
		t.Fatal(err)
	}

	reqs := hs.requests()
	if len(reqs) != burstKeep+1 {
		t.Fatalf("messages = %d, want %d", len(reqs), burstKeep+1)
	}
	// Individually sent: the 10 most important, exploitable by CVSS desc (11 down to 2).
	if !strings.Contains(reqs[0].body.Body, "CVE-11 ") {
		t.Errorf("first message = %q, want CVE-11 first", reqs[0].body.Body)
	}
	for _, r := range reqs[:burstKeep] {
		if strings.Contains(r.body.Body, "…and") {
			t.Errorf("individual message looks like a summary: %q", r.body.Body)
		}
	}

	summary := reqs[burstKeep].body
	if !strings.Contains(summary.Body, "…and 10 more findings") {
		t.Errorf("summary header missing: %q", summary.Body)
	}
	for _, want := range []string{"CVE-19@web01", "CVE-0@web01", "CVE-12@web01"} {
		if !strings.Contains(summary.Body, want) {
			t.Errorf("summary missing %q: %q", want, summary.Body)
		}
	}
	if strings.Contains(summary.Body, "CVE-11@") {
		t.Errorf("summary lists a finding that was sent individually")
	}
	if !strings.Contains(summary.Body, "https://holealign.example/findings") {
		t.Errorf("summary missing findings link: %q", summary.Body)
	}
}

func TestBurstAtThresholdIsNotSummarised(t *testing.T) {
	hs := newFakeHS(t, nil)
	m := newTestMatrix(t, hs, Config{Default: []string{"!r:example.org"}}, nil)
	var events []model.Event
	for i := range burstThreshold {
		events = append(events, testEvent(model.EventExploitable, fmt.Sprintf("CVE-%d", i), "h"))
	}
	if err := m.Notify(context.Background(), events); err != nil {
		t.Fatal(err)
	}
	if n := len(hs.requests()); n != burstThreshold {
		t.Errorf("messages = %d, want %d", n, burstThreshold)
	}
}
