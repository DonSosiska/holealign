package runner

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DonSosiska/holealign/internal/agent/collector"
	"github.com/DonSosiska/holealign/internal/agent/config"
	"github.com/DonSosiska/holealign/internal/agent/hostdata"
	"github.com/DonSosiska/holealign/internal/model"
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

// fakeSource is a hostdata.Source with injectable behaviour.
type fakeSource struct {
	mu           sync.Mutex
	collectFacts func(ctx context.Context, reqs []model.FactRequest) model.Facts
	scan         func(ctx context.Context, cfg config.Config) (model.InventoryPayload, error)
	changed      bool
}

func (f *fakeSource) Facts(ctx context.Context, reqs []model.FactRequest) (model.Facts, error) {
	f.mu.Lock()
	fn := f.collectFacts
	f.mu.Unlock()
	if fn == nil {
		return model.Facts{}, nil
	}
	return fn(ctx, reqs), nil
}

func (f *fakeSource) Inventory(ctx context.Context) (model.InventoryPayload, error) {
	f.mu.Lock()
	fn := f.scan
	f.mu.Unlock()
	if fn == nil {
		return model.InventoryPayload{}, nil
	}
	return fn(ctx, config.Config{})
}

func (f *fakeSource) Info(context.Context) (hostdata.HostInfo, error) {
	return hostdata.HostInfo{OS: model.OSInfo{ID: "testos", VersionID: "1"}, MachineID: strings.Repeat("ab", 32)}, nil
}

func (f *fakeSource) Changed(context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.changed
	f.changed = false
	return c, nil
}

// fk returns the fake behind a test runner built with mustNew.
func fk(r *Runner) *fakeSource { return r.src.(*fakeSource) }

// TestRunnerFlow runs the whole flow with the in-process source and again through the
// collector's unix socket: the runner must behave identically.
func TestRunnerFlow(t *testing.T) {
	t.Run("in-process", func(t *testing.T) { runnerFlow(t, false) })
	t.Run("socket", func(t *testing.T) { runnerFlow(t, true) })
}

func runnerFlow(t *testing.T, viaSocket bool) {
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
	cfg.AllowInsecureHTTP = true
	cfg.EnrollToken = "tok"
	cfg.StateDir = t.TempDir()
	r := mustNew(t, cfg)
	fake := fk(r)
	if viaSocket {
		r.src = socketSource(t, fake)
	}
	n := 0
	fake.collectFacts = func(context.Context, []model.FactRequest) model.Facts {
		n++
		if n == 1 {
			return model.Facts{"a": "1", "b": "2"}
		}
		return model.Facts{"a": "1", "c": "3"}
	}
	fake.scan = func(context.Context, config.Config) (model.InventoryPayload, error) {
		return model.InventoryPayload{Hash: "h1"}, nil
	}
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
	fake.changed = true
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
	cfg.AllowInsecureHTTP = true
	cfg.EnrollToken = "tok"
	cfg.StateDir = t.TempDir()
	r := mustNew(t, cfg)
	fk(r).collectFacts = func(context.Context, []model.FactRequest) model.Facts { return nil }
	fk(r).scan = func(context.Context, config.Config) (model.InventoryPayload, error) {
		return model.InventoryPayload{}, nil
	}
	r.client.Key = "stale"
	r.lastInvAt = time.Now()
	if _, err := r.checkinAndUpload(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if enrolls != 1 || r.client.Key != "new" {
		t.Fatalf("enrolls=%d key=%s", enrolls, r.client.Key)
	}
}

func mustNew(t *testing.T, cfg config.Config) *Runner {
	t.Helper()
	r, err := New(cfg, "test", slog.New(slog.NewTextHandler(io.Discard, nil)), &fakeSource{})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// socketSource serves fake over a collector on a temporary unix socket and returns a client.
func socketSource(t *testing.T, fake hostdata.Source) hostdata.Source {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "pc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "c.sock")
	srv := &collector.Server{
		Backend: fake, SocketPath: sock, InventoryMinGap: -1, FactsCacheTTL: -1,
		AllowedUIDs: []uint32{uint32(os.Getuid())},
		PeerUID:     func(net.Conn) (uint32, error) { return uint32(os.Getuid()), nil },
		Log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	l, err := srv.Listen()
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { srv.ServeListener(ctx, l); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return hostdata.NewClient(sock)
}
