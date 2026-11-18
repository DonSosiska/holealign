package runner

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DonSosiska/holealign/internal/agent/config"
	"github.com/DonSosiska/holealign/internal/agent/transport"
	"github.com/DonSosiska/holealign/internal/model"
)

func TestClampNextCheckin(t *testing.T) {
	def := 5 * time.Minute
	tests := []struct {
		in   int
		want time.Duration
	}{
		{0, def}, {-5, def}, {1, time.Minute}, {59, time.Minute}, {60, time.Minute},
		{300, 5 * time.Minute}, {3600, time.Hour}, {3601, time.Hour},
		{9223372037, time.Hour}, // *1e9 would overflow int64 nanoseconds
		{int(^uint(0) >> 1), time.Hour},
	}
	for _, tc := range tests {
		if got := clampNextCheckin(tc.in, def); got != tc.want {
			t.Errorf("clampNextCheckin(%d) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestScanBackoff(t *testing.T) {
	base := 5 * time.Minute
	if got := scanBackoff(base, 1); got != 10*time.Minute {
		t.Errorf("1 failure: %v", got)
	}
	if got := scanBackoff(base, 3); got != 40*time.Minute {
		t.Errorf("3 failures: %v", got)
	}
	if got := scanBackoff(base, 100); got != 6*time.Hour {
		t.Errorf("cap: %v", got)
	}
}

func TestHonorWantInventoryRateLimited(t *testing.T) {
	r := &Runner{}
	now := time.Now()
	if r.honorWantInventory(false, now) {
		t.Error("no request, no scan")
	}
	if !r.honorWantInventory(true, now) {
		t.Fatal("first request must be honoured")
	}
	if r.honorWantInventory(true, now.Add(9*time.Minute)) {
		t.Error("second request within 10 min must be ignored")
	}
	if !r.honorWantInventory(true, now.Add(11*time.Minute)) {
		t.Error("request after 10 min must be honoured")
	}
}

func newTestRunner(t *testing.T, url string) *Runner {
	t.Helper()
	cfg := config.Default()
	cfg.ServerURL = url
	cfg.AllowInsecureHTTP = true
	cfg.EnrollToken = "tok"
	cfg.StateDir = t.TempDir()
	r := mustNew(t, cfg)
	fk(r).collectFacts = func(context.Context, []model.FactRequest) model.Facts { return nil }
	return r
}

func TestServerWantInventoryNotHonouredBackToBack(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/checkin":
			json.NewEncoder(w).Encode(model.CheckinResponse{WantInventory: true, NextCheckinSeconds: 1})
		default:
			w.WriteHeader(202)
		}
	}))
	defer srv.Close()
	r := newTestRunner(t, srv.URL)
	scans := 0
	fk(r).scan = func(context.Context, config.Config) (model.InventoryPayload, error) {
		scans++
		return model.InventoryPayload{Hash: "h"}, nil
	}
	r.client.Key = "k"
	for i := 0; i < 5; i++ {
		if _, err := r.checkinAndUpload(context.Background(), false); err != nil {
			t.Fatal(err)
		}
	}
	if scans != 1 {
		t.Errorf("scans = %d, want 1 (inventory is otherwise only due once)", scans)
	}
}

func TestScanFailureBackoffAndFact(t *testing.T) {
	var lastFacts model.Facts
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/api/v1/checkin" {
			var cr model.CheckinRequest
			json.NewDecoder(req.Body).Decode(&cr)
			if cr.Facts != nil {
				lastFacts = cr.Facts
			}
			json.NewEncoder(w).Encode(model.CheckinResponse{})
			return
		}
		w.WriteHeader(202)
	}))
	defer srv.Close()
	r := newTestRunner(t, srv.URL)
	r.client.Key = "k"
	scans := 0
	fk(r).scan = func(context.Context, config.Config) (model.InventoryPayload, error) {
		scans++
		return model.InventoryPayload{}, errors.New(strings.Repeat("boom ", 100))
	}
	if _, err := r.checkinAndUpload(context.Background(), false); err == nil {
		t.Fatal("scan error expected")
	}
	// retries within the backoff window do not rescan
	for i := 0; i < 3; i++ {
		if _, err := r.checkinAndUpload(context.Background(), false); err != nil {
			t.Fatal(err)
		}
	}
	if scans != 1 {
		t.Errorf("scans = %d, want 1 during backoff", scans)
	}
	v, _ := lastFacts[inventoryErrKey].(string)
	if v == "" || len(v) > 200 {
		t.Errorf("%s = %q", inventoryErrKey, v)
	}

	// recovery clears the fact
	r.scanRetryAt = time.Time{}
	fk(r).scan = func(context.Context, config.Config) (model.InventoryPayload, error) {
		return model.InventoryPayload{Hash: "ok"}, nil
	}
	if _, err := r.checkinAndUpload(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if r.lastScanErr != "" || r.scanFailures != 0 {
		t.Errorf("state not reset: %q %d", r.lastScanErr, r.scanFailures)
	}
}

func TestEnrollConflictLoggedAndRetriedHourly(t *testing.T) {
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		auth = req.Header.Get("Authorization")
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(`{"error":"host exists; previous key required"}`))
	}))
	defer srv.Close()
	r := newTestRunner(t, srv.URL)
	var logs strings.Builder
	r.log = slog.New(slog.NewTextHandler(&logs, nil))
	// stored credentials from a previous install are sent as the bearer key
	if err := saveOld(r.cfg.StateDir); err != nil {
		t.Fatal(err)
	}
	err := r.enroll(context.Background())
	if err == nil {
		t.Fatal("expected conflict")
	}
	if auth != "Bearer old-key" {
		t.Errorf("Authorization = %q", auth)
	}
	if !strings.Contains(logs.String(), "allow-reenroll") || !strings.Contains(logs.String(), "level=ERROR") {
		t.Errorf("log = %s", logs.String())
	}
	if !errors.Is(err, transport.ErrEnrollConflict) {
		t.Errorf("err = %v, want ErrEnrollConflict (drives the hourly retry)", err)
	}
}

func saveOld(dir string) error {
	return transport.SaveCredentials(dir, transport.Credentials{AgentID: "a", AgentKey: "old-key"})
}

func TestRateLimitedInventoryStaysPending(t *testing.T) {
	var uploads, limited int
	var hashes []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/api/v1/checkin":
			json.NewEncoder(w).Encode(model.CheckinResponse{})
		default:
			if limited == 0 {
				limited++
				w.Header().Set("Retry-After", "600")
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			uploads++
			w.WriteHeader(202)
		}
	}))
	defer srv.Close()
	r := newTestRunner(t, srv.URL)
	r.client.Key = "k"
	scans := 0
	fk(r).scan = func(context.Context, config.Config) (model.InventoryPayload, error) {
		scans++
		hashes = append(hashes, "h1")
		return model.InventoryPayload{Hash: "h1"}, nil
	}
	var logs strings.Builder
	r.log = slog.New(slog.NewTextHandler(&logs, nil))
	delay := r.cycle(context.Background(), false)
	if delay != 600*time.Second {
		t.Errorf("delay = %v, want max(normal, Retry-After) = 600s", delay)
	}
	if !strings.Contains(logs.String(), "rate limited by server") || strings.Contains(logs.String(), "level=ERROR") {
		t.Errorf("log: %s", logs.String())
	}
	if r.scanFailures != 0 || !r.scanRetryAt.IsZero() || r.lastScanErr != "" {
		t.Error("429 must not count as a scan failure")
	}
	if r.pendingInv == nil {
		t.Fatal("inventory must stay pending")
	}
	r.cycle(context.Background(), false)
	if scans != 1 || uploads != 1 || r.pendingInv != nil || r.invHash != "h1" {
		t.Errorf("scans=%d uploads=%d pending=%v hash=%q (same payload must be re-sent without rescanning)", scans, uploads, r.pendingInv, r.invHash)
	}
}

func TestOnceRateLimited(t *testing.T) {
	for _, tc := range []struct {
		retryAfter string
		wantWait   bool
		wantErr    bool
	}{{"30", true, false}, {"600", false, true}} {
		limited := false
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			switch req.URL.Path {
			case "/api/v1/checkin":
				if !limited {
					limited = true
					w.Header().Set("Retry-After", tc.retryAfter)
					w.WriteHeader(http.StatusTooManyRequests)
					return
				}
				json.NewEncoder(w).Encode(model.CheckinResponse{})
			default:
				w.WriteHeader(202)
			}
		}))
		r := newTestRunner(t, srv.URL)
		r.creds = transport.Credentials{AgentID: "a", AgentKey: "k"}
		r.client.Key = "k"
		fk(r).scan = func(context.Context, config.Config) (model.InventoryPayload, error) {
			return model.InventoryPayload{Hash: "h"}, nil
		}
		var waited time.Duration
		r.sleep = func(_ context.Context, d time.Duration) bool { waited = d; return true }
		err := r.RunOnce(context.Background())
		srv.Close()
		if (err != nil) != tc.wantErr {
			t.Errorf("retry-after %s: err = %v", tc.retryAfter, err)
		}
		if tc.wantWait && waited != 30*time.Second {
			t.Errorf("waited %v", waited)
		}
		if tc.wantErr {
			var rl *transport.RateLimitedError
			if !errors.As(err, &rl) || !strings.Contains(err.Error(), "rate limited") || waited != 0 {
				t.Errorf("err = %v waited = %v", err, waited)
			}
		}
	}
}
