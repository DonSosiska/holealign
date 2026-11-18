package web

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/DonSosiska/holealign/internal/server/clientip"
	"github.com/DonSosiska/holealign/internal/server/config"
	"github.com/DonSosiska/holealign/internal/server/feeds"
	"github.com/DonSosiska/holealign/internal/server/store"
)

func TestTokenCreateWithOptions(t *testing.T) {
	e := newEnv(t, true)
	c := e.session("admin")
	w := e.post("/settings/tokens", url.Values{"name": {"fleet-b"}, "max_hosts": {"3"}, "expires": {"7d"}, "labels": {"prod, web"}}, c)
	if w.Code != 200 {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	toks, _ := e.st.ListEnrollTokens(context.Background())
	if len(toks) != 1 || toks[0].MaxHosts != 3 || len(toks[0].Labels) != 2 || toks[0].Labels[1] != "web" {
		t.Fatalf("tokens: %+v", toks)
	}
	if d := time.Until(toks[0].ExpiresAt); d < 6*24*time.Hour || d > 7*24*time.Hour+time.Minute {
		t.Fatalf("expires in %v", d)
	}
	body := e.do("GET", "/settings", nil, c).Body.String()
	for _, want := range []string{"0 / 3", "prod, web"} {
		if !strings.Contains(body, want) {
			t.Errorf("token list lacks %q", want)
		}
	}
	for _, bad := range []url.Values{
		{"name": {"x1"}, "max_hosts": {"-1"}},
		{"name": {"x2"}, "max_hosts": {"many"}},
		{"name": {"x3"}, "expires": {"soon"}},
		{"name": {"x4"}, "labels": {"bad label!"}},
	} {
		if w := e.post("/settings/tokens", bad, c); w.Code != 422 {
			t.Errorf("%v: status %d", bad, w.Code)
		}
	}
}

func TestDashboardBanner(t *testing.T) {
	e := newEnv(t, true)
	c := e.session("admin")
	if b := e.do("GET", "/", nil, c).Body.String(); strings.Contains(b, "feed stale") || strings.Contains(b, "Pipeline errors") {
		t.Fatal("banner shown while healthy")
	}
	ctx := context.Background()
	_ = e.st.KVSet(ctx, "health.feed_stale", "vulnerability DB last updated 3d ago — <boom>", time.Now())
	_ = e.st.KVSet(ctx, "health.pipeline_errors", "web1: pipeline failed 3 times in a row\ndb1: x", time.Now())
	_ = e.st.KVSet(ctx, feeds.KVLastError, "", time.Now())
	b := e.do("GET", "/", nil, c).Body.String()
	for _, want := range []string{"Vulnerability feed stale", "last updated 3d ago", "&lt;boom&gt;", "Pipeline errors", "web1: pipeline failed", "db1: x"} {
		if !strings.Contains(b, want) {
			t.Errorf("banner lacks %q", want)
		}
	}
}

// A request from an untrusted peer cannot choose its rate-limit identity via X-Forwarded-For.
func TestLoginLimiterIgnoresSpoofedXFF(t *testing.T) {
	st, err := store.OpenSQLite(t.TempDir() + "/w.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_, proxy, _ := net.ParseCIDR("10.0.0.0/8")
	cfg := config.Default()
	cfg.Matrix.Homeserver = "https://matrix.example.org"
	srv, err := New(Deps{Store: st, Config: &cfg, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		ClientIP: clientip.New([]*net.IPNet{proxy})})
	if err != nil {
		t.Fatal(err)
	}
	get := func(remote, xff string) string {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return srv.ipOf(r)
	}
	if ip := get("203.0.113.5:1", "1.1.1.1"); ip != "203.0.113.5" {
		t.Fatalf("spoofed XFF honoured: %s", ip)
	}
	if ip := get("10.0.0.2:1", "198.51.100.9"); ip != "198.51.100.9" {
		t.Fatalf("trusted proxy XFF ignored: %s", ip)
	}
	_ = http.StatusOK
}
