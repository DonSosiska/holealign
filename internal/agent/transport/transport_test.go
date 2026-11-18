package transport

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DonSosiska/holealign/internal/model"
)

func fast(c *Client) *Client {
	c.AllowInsecureHTTP = true
	c.sleep = func(ctx context.Context, d time.Duration) error { return nil }
	return c
}

func TestEnrollAndCheckin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/enroll":
			var req model.EnrollRequest
			json.NewDecoder(r.Body).Decode(&req)
			if req.Token != "tok" {
				w.WriteHeader(401)
				return
			}
			json.NewEncoder(w).Encode(model.EnrollResponse{AgentID: "a1", AgentKey: "k1"})
		case "/api/v1/checkin":
			if r.Header.Get("Authorization") != "Bearer k1" {
				w.WriteHeader(401)
				return
			}
			json.NewEncoder(w).Encode(model.CheckinResponse{WantInventory: true, NextCheckinSeconds: 7})
		}
	}))
	defer srv.Close()
	c := fast(New(srv.URL, ""))
	ctx := context.Background()
	if _, err := c.Enroll(ctx, model.EnrollRequest{Token: "bad"}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("want ErrUnauthorized, got %v", err)
	}
	er, err := c.Enroll(ctx, model.EnrollRequest{Token: "tok"})
	if err != nil || er.AgentKey != "k1" {
		t.Fatalf("enroll: %v %+v", err, er)
	}
	c.Key = er.AgentKey
	cr, err := c.Checkin(ctx, model.CheckinRequest{Hostname: "h"})
	if err != nil || !cr.WantInventory || cr.NextCheckinSeconds != 7 {
		t.Fatalf("checkin: %v %+v", err, cr)
	}
	c.Key = "wrong"
	if _, err := c.Checkin(ctx, model.CheckinRequest{}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("want 401, got %v", err)
	}
}

func TestUploadInventoryGzip(t *testing.T) {
	var got model.InventoryPayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Encoding") != "gzip" || r.Header.Get("Authorization") != "Bearer k" {
			w.WriteHeader(400)
			return
		}
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		b, _ := io.ReadAll(zr)
		json.Unmarshal(b, &got)
		w.WriteHeader(202)
	}))
	defer srv.Close()
	c := fast(New(srv.URL, "k"))
	p := model.InventoryPayload{Hash: "abc", Targets: []model.InventoryTarget{{Kind: model.TargetHost, Name: "host", SBOM: json.RawMessage(`{"a":1}`)}}}
	if err := c.UploadInventory(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if got.Hash != "abc" || len(got.Targets) != 1 || string(got.Targets[0].SBOM) != `{"a":1}` {
		t.Fatalf("got %+v", got)
	}
}

func TestRetryOn503(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) < 3 {
			w.WriteHeader(503)
			return
		}
		json.NewEncoder(w).Encode(model.CheckinResponse{})
	}))
	defer srv.Close()
	c := fast(New(srv.URL, "k"))
	if _, err := c.Checkin(context.Background(), model.CheckinRequest{}); err != nil {
		t.Fatal(err)
	}
	if n.Load() != 3 {
		t.Fatalf("attempts %d", n.Load())
	}
}

func TestNoRetryOn400AndMaxAttempts(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		if r.URL.Path == "/api/v1/enroll" {
			w.WriteHeader(400)
			w.Write([]byte(`{"error":"bad"}`))
			return
		}
		w.WriteHeader(500)
	}))
	defer srv.Close()
	c := fast(New(srv.URL, "k"))
	if _, err := c.Enroll(context.Background(), model.EnrollRequest{}); err == nil {
		t.Fatal("want error")
	}
	if n.Load() != 1 {
		t.Fatalf("400 retried: %d", n.Load())
	}
	n.Store(0)
	c.MaxAttempts = 3
	if _, err := c.Checkin(context.Background(), model.CheckinRequest{}); err == nil {
		t.Fatal("want error")
	}
	if n.Load() != 3 {
		t.Fatalf("attempts %d", n.Load())
	}
}

func TestBackoffCap(t *testing.T) {
	c := New("http://x", "")
	for a := 0; a < 40; a++ {
		if d := c.backoff(a); d > c.MaxBackoff || d <= 0 {
			t.Fatalf("attempt %d backoff %v", a, d)
		}
	}
}

func TestCredentials(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if _, err := LoadCredentials(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("want not exist, got %v", err)
	}
	if err := SaveCredentials(dir, Credentials{AgentID: "a", AgentKey: "k"}); err != nil {
		t.Fatal(err)
	}
	c, err := LoadCredentials(dir)
	if err != nil || c.AgentID != "a" || c.AgentKey != "k" {
		t.Fatalf("%v %+v", err, c)
	}
	st, _ := os.Stat(filepath.Join(dir, "credentials.json"))
	if st.Mode().Perm() != 0o600 {
		t.Errorf("file mode %v", st.Mode())
	}
	st, _ = os.Stat(dir)
	if st.Mode().Perm() != 0o700 {
		t.Errorf("dir mode %v", st.Mode())
	}
}
