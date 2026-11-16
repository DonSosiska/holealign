package runner

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	"panoptes/internal/agent/config"
	"panoptes/internal/model"
)

func TestDiffFacts(t *testing.T) {
	prev := NormalizeFacts(model.Facts{"a": "1", "b": []string{"x"}, "gone": true, "same": map[string]any{"k": 1}})
	cur := NormalizeFacts(model.Facts{"a": "2", "b": []string{"x"}, "new": 3, "same": map[string]any{"k": 1}})
	d := DiffFacts(prev, cur)
	want := model.Facts{"a": "2", "new": float64(3), "gone": nil}
	if !reflect.DeepEqual(d, want) {
		t.Fatalf("got %#v want %#v", d, want)
	}
	raw, _ := json.Marshal(d)
	var m map[string]json.RawMessage
	json.Unmarshal(raw, &m)
	if string(m["gone"]) != "null" {
		t.Fatalf("deleted key must be JSON null: %s", raw)
	}
	if len(DiffFacts(cur, cur)) != 0 {
		t.Fatal("identical facts must give empty diff")
	}
}

func TestParseOSRelease(t *testing.T) {
	m := parseOSRelease([]byte("# c\nID=debian\nVERSION_ID=\"12\"\nPRETTY_NAME='Debian GNU/Linux 12 (bookworm)'\n"))
	if m["ID"] != "debian" || m["VERSION_ID"] != "12" || m["PRETTY_NAME"] != "Debian GNU/Linux 12 (bookworm)" {
		t.Fatalf("%v", m)
	}
}

type fakeDetector struct{ changed bool }

func (f *fakeDetector) Changed(context.Context) bool { r := f.changed; f.changed = false; return r }
func (f *fakeDetector) Reset(context.Context)        {}

func TestRunnerFlow(t *testing.T) {
	var mu sync.Mutex
	var checkins []model.CheckinRequest
	var uploads int
	wantFull, wantInv := false, true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/api/v1/enroll":
			json.NewEncoder(w).Encode(model.EnrollResponse{AgentID: "id", AgentKey: "key"})
		case "/api/v1/checkin":
			if r.Header.Get("Authorization") != "Bearer key" {
				w.WriteHeader(401)
				return
			}
			var req model.CheckinRequest
			json.NewDecoder(r.Body).Decode(&req)
			checkins = append(checkins, req)
			json.NewEncoder(w).Encode(model.CheckinResponse{WantInventory: wantInv, WantFullFacts: wantFull})
		case "/api/v1/inventory":
			zr, err := gzip.NewReader(r.Body)
			if err != nil {
				w.WriteHeader(400)
				return
			}
			io.Copy(io.Discard, zr)
			uploads++
			w.WriteHeader(202)
		}
	}))
	defer srv.Close()

	cfg := config.Default()
	cfg.ServerURL = srv.URL
	cfg.EnrollToken = "tok"
	cfg.StateDir = t.TempDir()
	r := New(cfg, "test", slog.New(slog.NewTextHandler(io.Discard, nil)))
	n := 0
	r.collectFacts = func(context.Context, []model.FactRequest) model.Facts {
		n++
		if n == 1 {
			return model.Facts{"a": "1", "b": "2"}
		}
		return model.Facts{"a": "1", "c": "3"}
	}
	r.scan = func(context.Context, config.Config) (model.InventoryPayload, error) {
		return model.InventoryPayload{Hash: "h1"}, nil
	}
	det := &fakeDetector{}
	r.detector = det
	ctx := context.Background()

	if err := r.ensureEnrolled(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := r.checkinAndUpload(ctx, false); err != nil { // first: full + inventory wanted
		t.Fatal(err)
	}
	wantInv = false
	if _, err := r.checkinAndUpload(ctx, false); err != nil { // diff, no upload
		t.Fatal(err)
	}
	det.changed = true
	if _, err := r.checkinAndUpload(ctx, false); err != nil { // change detector -> upload
		t.Fatal(err)
	}
	wantFull = true
	if _, err := r.checkinAndUpload(ctx, false); err != nil { // sets wantFull for next
		t.Fatal(err)
	}
	if _, err := r.checkinAndUpload(ctx, false); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(checkins) != 5 {
		t.Fatalf("checkins %d", len(checkins))
	}
	if !checkins[0].FactsComplete || len(checkins[0].Facts) != 2 || checkins[0].InventoryHash != "" {
		t.Errorf("first: %+v", checkins[0])
	}
	d := checkins[1]
	if d.FactsComplete || d.InventoryHash != "h1" {
		t.Errorf("second: %+v", d)
	}
	if v, ok := d.Facts["b"]; !ok || v != nil || d.Facts["c"] != "3" || len(d.Facts) != 2 {
		t.Errorf("diff wrong: %#v", d.Facts)
	}
	if !checkins[4].FactsComplete {
		t.Errorf("want full facts after WantFullFacts: %+v", checkins[4])
	}
	if uploads != 2 {
		t.Errorf("uploads %d, want 2", uploads)
	}
}

func TestRunnerReenrollsOn401(t *testing.T) {
	var mu sync.Mutex
	enrolls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/api/v1/enroll":
			enrolls++
			json.NewEncoder(w).Encode(model.EnrollResponse{AgentID: "id", AgentKey: "new"})
		case "/api/v1/checkin":
			if r.Header.Get("Authorization") != "Bearer new" {
				w.WriteHeader(401)
				return
			}
			json.NewEncoder(w).Encode(model.CheckinResponse{})
		}
	}))
	defer srv.Close()
	cfg := config.Default()
	cfg.ServerURL = srv.URL
	cfg.EnrollToken = "tok"
	cfg.StateDir = t.TempDir()
	r := New(cfg, "test", slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.collectFacts = func(context.Context, []model.FactRequest) model.Facts { return nil }
	r.scan = func(context.Context, config.Config) (model.InventoryPayload, error) {
		return model.InventoryPayload{}, nil
	}
	r.detector = &fakeDetector{}
	r.client.Key = "stale"
	r.lastInvAt = time.Now()
	if _, err := r.checkinAndUpload(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if enrolls != 1 || r.client.Key != "new" {
		t.Fatalf("enrolls=%d key=%s", enrolls, r.client.Key)
	}
}
