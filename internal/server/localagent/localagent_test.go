package localagent

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
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DonSosiska/panoptes/internal/agent/collector"
	"github.com/DonSosiska/panoptes/internal/agent/hostdata"
	"github.com/DonSosiska/panoptes/internal/agent/transport"
	"github.com/DonSosiska/panoptes/internal/model"
	"github.com/DonSosiska/panoptes/internal/server/api"
	"github.com/DonSosiska/panoptes/internal/server/config"
	"github.com/DonSosiska/panoptes/internal/server/store"
)

var machineA = strings.Repeat("ab", 32)

// fakeSource is a hostdata.Source with canned data.
type fakeSource struct {
	machineID string
	panicOnce atomic.Bool // panic in the first Info call
	infoCalls atomic.Int32
}

func (f *fakeSource) Facts(context.Context, []model.FactRequest) (model.Facts, error) {
	return model.Facts{"os.libc": "glibc", "services.active": []any{"sshd"}}, nil
}

func (f *fakeSource) Inventory(context.Context) (model.InventoryPayload, error) {
	return model.InventoryPayload{Hash: "h1", Targets: []model.InventoryTarget{{
		Kind: model.TargetHost, Name: "host",
		SBOM: json.RawMessage(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`)}}}, nil
}

func (f *fakeSource) Info(context.Context) (hostdata.HostInfo, error) {
	f.infoCalls.Add(1)
	if f.panicOnce.CompareAndSwap(true, false) {
		panic("boom")
	}
	return hostdata.HostInfo{OS: model.OSInfo{ID: "debian", VersionID: "12", PrettyName: "Debian 12"}, MachineID: f.machineID}, nil
}

func (f *fakeSource) Changed(context.Context) (bool, error) { return false, nil }

type env struct {
	st   *store.SQLite
	mux  http.Handler
	data string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &env{st: st, mux: api.NewMux(api.Deps{Store: st, Logger: log}), data: t.TempDir()}
}

func (e *env) agent(src hostdata.Source, mod func(*Options)) *Agent {
	o := Options{
		Config: config.Default().LocalAgent, DataDir: e.data, Store: e.st, Handler: e.mux, Version: "test",
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Source: src, Hostname: "srv1",
		MinBackoff: 10 * time.Millisecond, MaxBackoff: 20 * time.Millisecond,
	}
	if mod != nil {
		mod(&o)
	}
	return New(o)
}

func eventually(t *testing.T, what string, f func() bool) {
	t.Helper()
	for i := 0; i < 400; i++ {
		if f() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

func TestRoundTripThroughAPI(t *testing.T) {
	e := newEnv(t)
	a := e.agent(&fakeSource{machineID: machineA}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := a.Start(ctx)

	var host model.Host
	eventually(t, "check-in and inventory", func() bool {
		hs, _ := e.st.ListHosts(ctx)
		if len(hs) != 1 {
			return false
		}
		host = hs[0]
		return !host.LastCheckin.IsZero() && host.InventoryHash == "h1"
	})
	cancel()
	<-done

	if host.MachineID != machineA || host.Hostname == "" || !slices.Equal(host.Labels, []string{"server"}) {
		t.Fatalf("host = %+v", host)
	}
	if host.OS.ID != "" && host.OS.ID != "debian" {
		t.Fatalf("os = %+v", host.OS)
	}
	if _, ok := host.Facts["os.libc"]; !ok {
		t.Fatalf("facts not stored: %v", host.Facts)
	}
	tg, _ := e.st.ListTargets(context.Background(), host.ID)
	if len(tg) != 1 {
		t.Fatalf("targets = %d", len(tg))
	}
	if id, _ := e.st.KVGet(context.Background(), KVLocalHost); id != host.ID {
		t.Fatalf("local marker = %q, want %q", id, host.ID)
	}
	adm, _ := e.st.ListHostsAdmin(context.Background())
	if adm[0].TokenName != TokenName {
		t.Fatalf("token name = %q", adm[0].TokenName)
	}
	// labels are authoritative: a check-in claiming others must not change them
	creds, err := transport.LoadCredentials(StateDir(e.data))
	if err != nil || creds.AgentID != host.ID {
		t.Fatalf("credentials = %+v, %v", creds, err)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(transport.CredentialsPath(StateDir(e.data)))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("credentials mode: %v %v", fi, err)
		}
	}
	if _, err := e.st.ApplyCheckin(context.Background(), host.ID, model.CheckinRequest{Hostname: "srv1", Labels: []string{"evil"}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	h2, _ := e.st.GetHost(context.Background(), host.ID)
	if !slices.Equal(h2.Labels, []string{"server"}) {
		t.Fatalf("labels not locked: %v", h2.Labels)
	}
	// the secret is only stored hashed
	if _, err := e.st.HostByAgentKey(context.Background(), store.HashSecret(creds.AgentKey)); err != nil {
		t.Fatalf("key hash lookup: %v", err)
	}
}

func TestRestartReusesCredentials(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a := e.agent(&fakeSource{machineID: machineA}, nil)
	if err := a.Provision(ctx, machineA); err != nil {
		t.Fatal(err)
	}
	c1, _ := transport.LoadCredentials(StateDir(e.data))
	if err := e.agent(&fakeSource{machineID: machineA}, nil).Provision(ctx, machineA); err != nil {
		t.Fatal(err)
	}
	c2, _ := transport.LoadCredentials(StateDir(e.data))
	if c1 != c2 {
		t.Fatalf("credentials changed on restart: %+v -> %+v", c1, c2)
	}
	if hs, _ := e.st.ListHosts(ctx); len(hs) != 1 {
		t.Fatalf("hosts = %d", len(hs))
	}
}

func TestLabelChangeUpdatesHost(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.agent(nil, nil).Provision(ctx, machineA); err != nil {
		t.Fatal(err)
	}
	c1, _ := transport.LoadCredentials(StateDir(e.data))
	if err := e.agent(nil, func(o *Options) { o.Config.Labels = []string{"server", "prod"} }).Provision(ctx, machineA); err != nil {
		t.Fatal(err)
	}
	hs, _ := e.st.ListHosts(ctx)
	if len(hs) != 1 || !slices.Equal(hs[0].Labels, []string{"server", "prod"}) {
		t.Fatalf("hosts = %+v", hs)
	}
	c2, _ := transport.LoadCredentials(StateDir(e.data))
	if c2.AgentKey == c1.AgentKey || c2.AgentID != c1.AgentID {
		t.Fatalf("expected rotated key and same id: %+v -> %+v", c1, c2)
	}
	if _, err := e.st.HostByAgentKey(ctx, store.HashSecret(c1.AgentKey)); err == nil {
		t.Fatal("old key still valid")
	}
}

func TestExistingHostIsNotHijacked(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	// a standalone agent enrolled this machine earlier
	_, hash, _ := store.NewSecret("pa_")
	h, err := e.st.EnrollHost(ctx, store.EnrollParams{MachineID: machineA, Hostname: "srv1", KeyHash: hash, TokenName: "t", Labels: []string{"prod"}})
	if err != nil {
		t.Fatal(err)
	}
	a := e.agent(&fakeSource{machineID: machineA}, nil)
	if err := a.Provision(ctx, machineA); err == nil || !strings.Contains(err.Error(), ErrConflict.Error()) {
		t.Fatalf("Provision err = %v, want conflict", err)
	}
	// Start gives up without touching anything
	done := a.Start(ctx)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("local agent kept running after a conflict")
	}
	if _, err := transport.LoadCredentials(StateDir(e.data)); err == nil {
		t.Fatal("credentials written despite conflict")
	}
	if _, err := e.st.HostByAgentKey(ctx, hash); err != nil {
		t.Fatalf("original agent key was rotated: %v", err)
	}
	got, _ := e.st.GetHost(ctx, h.ID)
	if !slices.Equal(got.Labels, []string{"prod"}) {
		t.Fatalf("labels changed: %v", got.Labels)
	}
	if id, err := e.st.KVGet(ctx, KVLocalHost); err == nil {
		t.Fatalf("host marked local: %q", id)
	}
}

func TestStaleCredentialsAfterHostDeleted(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a := e.agent(nil, nil)
	if err := a.Provision(ctx, machineA); err != nil {
		t.Fatal(err)
	}
	hs, _ := e.st.ListHosts(ctx)
	if err := e.st.DeleteHost(ctx, hs[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := a.Provision(ctx, machineA); err != nil {
		t.Fatal(err)
	}
	hs2, _ := e.st.ListHosts(ctx)
	if len(hs2) != 1 || hs2[0].ID == hs[0].ID {
		t.Fatalf("hosts = %+v", hs2)
	}
	if id, _ := e.st.KVGet(ctx, KVLocalHost); id != hs2[0].ID {
		t.Fatalf("marker %q", id)
	}
}

func TestRecoversFromCrashBetweenCredentialsAndEnroll(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a := e.agent(nil, nil)
	if err := a.Provision(ctx, machineA); err != nil {
		t.Fatal(err)
	}
	// simulate a rotation that wrote new credentials but never reached the database
	if err := transport.SaveCredentials(StateDir(e.data), transport.Credentials{AgentID: "pending", AgentKey: "pa_lost"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Provision(ctx, machineA); err != nil {
		t.Fatalf("our own marked host must be recoverable: %v", err)
	}
	c, _ := transport.LoadCredentials(StateDir(e.data))
	if _, err := e.st.HostByAgentKey(ctx, store.HashSecret(c.AgentKey)); err != nil {
		t.Fatal(err)
	}
}

func TestPanicIsRecoveredAndAgentRestarts(t *testing.T) {
	e := newEnv(t)
	src := &fakeSource{machineID: machineA}
	src.panicOnce.Store(true)
	var runs atomic.Int32
	a := e.agent(src, func(o *Options) { o.OnRun = func() { runs.Add(1) } })
	ctx, cancel := context.WithCancel(context.Background())
	done := a.Start(ctx)
	eventually(t, "check-in after panic", func() bool {
		hs, _ := e.st.ListHosts(ctx)
		return len(hs) == 1 && !hs[0].LastCheckin.IsZero()
	})
	cancel()
	<-done
	if src.infoCalls.Load() < 2 || runs.Load() != 1 {
		t.Fatalf("info calls = %d, runs = %d", src.infoCalls.Load(), runs.Load())
	}
}

func TestSourceSelection(t *testing.T) {
	e := newEnv(t)
	dir, err := os.MkdirTemp("/tmp", "pla")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "run", "c.sock")
	mk := func(src string) *Agent {
		return e.agent(nil, func(o *Options) { o.Config.Source = src; o.Config.CollectorSocket = sock })
	}
	cfg := mk("auto").agentConfig()

	// no socket: auto falls back to in-process, collector stays collector (and fails later)
	if s, kind := mk("auto").selectSource(context.Background(), cfg); kind != config.LocalSourceInProcess {
		t.Fatalf("auto without socket chose %s (%T)", kind, s)
	}
	if _, kind := mk("collector").selectSource(context.Background(), cfg); kind != config.LocalSourceCollector {
		t.Fatalf("collector chose %s", kind)
	}
	if s, kind := mk("inprocess").selectSource(context.Background(), cfg); kind != config.LocalSourceInProcess {
		t.Fatalf("inprocess chose %s (%T)", kind, s)
	} else if _, ok := s.(*hostdata.Local); !ok {
		t.Fatalf("inprocess source is %T", s)
	}

	// a collector listening on the socket: auto uses it
	srv := &collector.Server{
		Backend: &fakeSource{machineID: machineA}, SocketPath: sock,
		AllowedUIDs: []uint32{uint32(os.Getuid())},
		PeerUID:     func(net.Conn) (uint32, error) { return uint32(os.Getuid()), nil },
		Log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	l, err := srv.Listen()
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() { srv.ServeListener(ctx, l); close(served) }()
	t.Cleanup(func() { cancel(); <-served })
	s, kind := mk("auto").selectSource(context.Background(), cfg)
	if kind != config.LocalSourceCollector {
		t.Fatalf("auto with socket chose %s (%T)", kind, s)
	}
	if _, ok := s.(*hostdata.Client); !ok {
		t.Fatalf("collector source is %T", s)
	}
	// and the whole agent works through it
	a := mk("auto")
	done := a.Start(ctx)
	eventually(t, "check-in via collector", func() bool {
		hs, _ := e.st.ListHosts(ctx)
		return len(hs) == 1 && !hs[0].LastCheckin.IsZero() && hs[0].MachineID == machineA
	})
	cancel()
	<-done
}

func TestHandlerTransport(t *testing.T) {
	var gotAddr, gotEnc string
	var gotBody []byte
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAddr, gotEnc = r.RemoteAddr, r.Header.Get("Content-Encoding")
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Encoding", "gzip")
		zw := gzip.NewWriter(w)
		zw.Write([]byte(`{"ok":true}`))
		zw.Close()
	})
	req := httptest.NewRequest("POST", BaseURL+"/x", strings.NewReader("hello"))
	req.RequestURI = "" // client request
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := NewHTTPClient(h).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"ok":true}` || !resp.Uncompressed {
		t.Fatalf("response body %q (uncompressed=%v)", body, resp.Uncompressed)
	}
	if gotAddr != "127.0.0.1:0" || gotEnc != "gzip" || string(gotBody) != "hello" {
		t.Fatalf("handler saw addr=%q enc=%q body=%q", gotAddr, gotEnc, gotBody)
	}
	// a panicking handler is an error, not a crash
	_, err = NewHTTPClient(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("x") })).Get(BaseURL + "/")
	if err == nil {
		t.Fatal("expected an error from a panicking handler")
	}
}

func TestGzipInventoryThroughHandler(t *testing.T) {
	// UploadInventory sends a gzip body; the real mux must accept it through the transport.
	e := newEnv(t)
	ctx := context.Background()
	if err := e.agent(nil, nil).Provision(ctx, machineA); err != nil {
		t.Fatal(err)
	}
	creds, _ := transport.LoadCredentials(StateDir(e.data))
	c := transport.NewWithHTTP(BaseURL, creds.AgentKey, NewHTTPClient(e.mux))
	p, _ := (&fakeSource{}).Inventory(ctx)
	if err := c.UploadInventory(ctx, p); err != nil {
		t.Fatal(err)
	}
	h, _ := e.st.GetHost(ctx, creds.AgentID)
	if h.InventoryHash != p.Hash {
		t.Fatalf("inventory hash %q", h.InventoryHash)
	}
}

func TestDataDirIsNeverScanned(t *testing.T) {
	e := newEnv(t)
	for _, ex := range [][]string{nil, {"/srv"}} {
		a := e.agent(nil, func(o *Options) { o.Config.ExcludePaths = ex })
		got := a.agentConfig().ExcludePaths
		if !slices.Contains(got, e.data) {
			t.Fatalf("data_dir %q not excluded from the in-process scan: %v", e.data, got)
		}
		if ex == nil && !slices.Contains(got, "/proc") {
			t.Fatalf("agent default excludes lost: %v", got)
		}
		if ex != nil && !slices.Contains(got, "/srv") {
			t.Fatalf("configured excludes lost: %v", got)
		}
	}
}
