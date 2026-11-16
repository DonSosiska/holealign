package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"panoptes/internal/model"
)

func TestRedirectRefusedAndBodyNotResent(t *testing.T) {
	var targetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
	}))
	defer target.Close()
	var srvHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		srvHits.Add(1)
		http.Redirect(w, r, target.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()

	c := fast(New(srv.URL, "secret-key"))
	c.MaxAttempts = 3
	_, err := c.Checkin(context.Background(), model.CheckinRequest{Hostname: "h"})
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("err = %v, want redirect refusal", err)
	}
	if targetHits.Load() != 0 {
		t.Error("redirect target was contacted")
	}
	if srvHits.Load() != 1 {
		t.Errorf("redirect must not be retried: %d requests", srvHits.Load())
	}
}

func TestHTTPRefusedWithoutAllowFlag(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()

	c := New(srv.URL, "k")
	c.sleep = func(context.Context, time.Duration) error { return nil }
	if _, err := c.Checkin(context.Background(), model.CheckinRequest{}); err == nil || !strings.Contains(err.Error(), "http://") {
		t.Fatalf("err = %v", err)
	}
	if hits.Load() != 0 {
		t.Error("request was sent over plain http")
	}
	c.AllowInsecureHTTP = true
	if _, err := c.Checkin(context.Background(), model.CheckinRequest{}); err != nil && strings.Contains(err.Error(), "refused") {
		t.Errorf("allow flag ignored: %v", err)
	}
}

func TestURLWithUserinfoRejected(t *testing.T) {
	c := New("https://user:pw@example.com", "")
	c.MaxAttempts = 1
	if _, err := c.Checkin(context.Background(), model.CheckinRequest{}); err == nil || !strings.Contains(err.Error(), "credentials") {
		t.Errorf("err = %v", err)
	}
}

func TestHTTPClientHardening(t *testing.T) {
	c := New("https://example.com", "")
	tr, ok := c.HTTP.Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("transport = %#v", c.HTTP.Transport)
	}
	if tr == http.DefaultTransport {
		t.Error("must not share the default transport")
	}
	if c.HTTP.CheckRedirect == nil {
		t.Error("CheckRedirect not set")
	}
}

func TestEnrollSendsPreviousKeyAndHandles409(t *testing.T) {
	var gotAuth atomic.Value
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth.Store(r.Header.Get("Authorization"))
		w.WriteHeader(status)
		w.Write([]byte(`{"error":"host exists; previous key required"}`))
	}))
	defer srv.Close()

	c := fast(New(srv.URL, "old-key"))
	c.MaxAttempts = 3
	status = http.StatusConflict
	_, err := c.Enroll(context.Background(), model.EnrollRequest{Token: "t"})
	if !errors.Is(err, ErrEnrollConflict) {
		t.Fatalf("err = %v, want ErrEnrollConflict", err)
	}
	if gotAuth.Load() != "Bearer old-key" {
		t.Errorf("Authorization = %v", gotAuth.Load())
	}

	// without stored credentials no header is sent
	c = fast(New(srv.URL, ""))
	c.Enroll(context.Background(), model.EnrollRequest{Token: "t"})
	if gotAuth.Load() != "" {
		t.Errorf("Authorization = %q, want empty", gotAuth.Load())
	}
}
