package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"panoptes/internal/agent/hostdata"
	"panoptes/internal/model"
)

type fakeBackend struct {
	scans   atomic.Int32
	changed atomic.Bool
	scanErr error
}

func (f *fakeBackend) Facts(_ context.Context, reqs []model.FactRequest) (model.Facts, error) {
	return model.Facts{"os.id": "test", "n_requests": len(reqs)}, nil
}

func (f *fakeBackend) Inventory(context.Context) (model.InventoryPayload, error) {
	n := f.scans.Add(1)
	if f.scanErr != nil {
		return model.InventoryPayload{}, f.scanErr
	}
	return model.InventoryPayload{Hash: "h" + string(rune('0'+n)),
		Targets: []model.InventoryTarget{{Kind: model.TargetHost, Name: "host", SBOM: json.RawMessage(`{"a":1}`)}}}, nil
}

func (f *fakeBackend) Info(context.Context) (hostdata.HostInfo, error) {
	return hostdata.HostInfo{OS: model.OSInfo{ID: "debian", VersionID: "12"}, MachineID: strings.Repeat("cd", 32)}, nil
}

func (f *fakeBackend) Changed(context.Context) (bool, error) { return f.changed.Swap(false), nil }

func start(t *testing.T, mod func(*Server), b hostdata.Source) (*Server, *hostdata.Client) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "pcol")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	srv := &Server{
		Backend: b, SocketPath: filepath.Join(dir, "run", "c.sock"),
		AllowedUIDs: []uint32{uint32(os.Getuid())},
		PeerUID:     func(net.Conn) (uint32, error) { return uint32(os.Getuid()), nil },
		Log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if mod != nil {
		mod(srv)
	}
	l, err := srv.Listen()
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { srv.ServeListener(ctx, l); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return srv, hostdata.NewClient(srv.SocketPath)
}

func TestProtocolOperations(t *testing.T) {
	fb := &fakeBackend{}
	_, c := start(t, nil, fb)
	ctx := context.Background()

	f, err := c.Facts(ctx, []model.FactRequest{{Name: "file.match:x", Collector: "file.match"}})
	if err != nil || f["os.id"] != "test" || f["n_requests"] != float64(1) {
		t.Fatalf("facts: %v %v", f, err)
	}
	inv, err := c.Inventory(ctx)
	if err != nil || inv.Hash != "h1" || len(inv.Targets) != 1 || string(inv.Targets[0].SBOM) != `{"a":1}` {
		t.Fatalf("inventory: %+v %v", inv, err)
	}
	info, err := c.Info(ctx)
	if err != nil || info.OS.ID != "debian" || info.MachineID != strings.Repeat("cd", 32) {
		t.Fatalf("osinfo: %+v %v", info, err)
	}
	if ch, err := c.Changed(ctx); err != nil || ch {
		t.Fatalf("changed: %v %v", ch, err)
	}
	fb.changed.Store(true)
	if ch, err := c.Changed(ctx); err != nil || !ch {
		t.Fatalf("changed after change: %v %v", ch, err)
	}
}

func TestSocketPermissions(t *testing.T) {
	srv, _ := start(t, nil, &fakeBackend{})
	fi, err := os.Stat(srv.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o660 {
		t.Errorf("socket mode = %v, want 0660", fi.Mode().Perm())
	}
	di, _ := os.Stat(filepath.Dir(srv.SocketPath))
	if di.Mode().Perm() != 0o750 {
		t.Errorf("dir mode = %v, want 0750", di.Mode().Perm())
	}
}

func TestInventoryAtMostOncePerGap(t *testing.T) {
	fb := &fakeBackend{}
	_, c := start(t, func(s *Server) { s.InventoryMinGap = time.Hour }, fb)
	for i := 0; i < 4; i++ {
		inv, err := c.Inventory(context.Background())
		if err != nil || inv.Hash != "h1" {
			t.Fatalf("call %d: %+v %v", i, inv, err)
		}
	}
	if n := fb.scans.Load(); n != 1 {
		t.Errorf("scans = %d, want 1 (cached within the gap, whoever asks)", n)
	}
}

func TestInventoryErrorAlsoRateLimited(t *testing.T) {
	fb := &fakeBackend{scanErr: errors.New("boom")}
	_, c := start(t, func(s *Server) { s.InventoryMinGap = time.Hour }, fb)
	for i := 0; i < 3; i++ {
		if _, err := c.Inventory(context.Background()); err == nil || !strings.Contains(err.Error(), "boom") {
			t.Fatalf("err = %v", err)
		}
	}
	if n := fb.scans.Load(); n != 1 {
		t.Errorf("scans = %d, want 1", n)
	}
}

func rawRequest(t *testing.T, path string, payload []byte) string {
	t.Helper()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	go func() { conn.Write(payload) }()
	out, _ := io.ReadAll(conn)
	return string(out)
}

func TestRequestSizeCapAndBadRequests(t *testing.T) {
	_, c := start(t, nil, &fakeBackend{})
	big := append([]byte(`{"op":"facts","fact_requests":[{"name":"`), bytes.Repeat([]byte("a"), hostdata.MaxRequestBytes)...)
	big = append(big, []byte("\"}]}\n")...)
	if out := rawRequest(t, c.Path, big); !strings.Contains(out, "request too large") {
		t.Errorf("oversized request answer: %q", out)
	}
	// a request without newline that exceeds the cap is cut off too
	if out := rawRequest(t, c.Path, bytes.Repeat([]byte("x"), hostdata.MaxRequestBytes+10)); !strings.Contains(out, "request too large") {
		t.Errorf("answer: %q", out)
	}
	if out := rawRequest(t, c.Path, []byte("not json\n")); !strings.Contains(out, `"ok":false`) {
		t.Errorf("bad json answer: %q", out)
	}
	if out := rawRequest(t, c.Path, []byte(`{"op":"rm -rf"}`+"\n")); !strings.Contains(out, "unknown op") {
		t.Errorf("unknown op answer: %q", out)
	}
	if out := rawRequest(t, c.Path, []byte(`{"op":"facts","extra":1}`+"\n")); !strings.Contains(out, `"ok":false`) {
		t.Errorf("unknown field answer: %q", out)
	}
	// still serving afterwards
	if _, err := c.Facts(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
}

func TestPeerAllowed(t *testing.T) {
	cases := []struct {
		uid     uint32
		allowed []uint32
		want    bool
	}{
		{0, nil, true}, {0, []uint32{999}, true}, {999, []uint32{999}, true},
		{1000, []uint32{999}, false}, {1000, nil, false}, {65534, []uint32{999, 998}, false},
	}
	for _, tc := range cases {
		if got := PeerAllowed(tc.uid, tc.allowed); got != tc.want {
			t.Errorf("PeerAllowed(%d,%v) = %v", tc.uid, tc.allowed, got)
		}
	}
}

func TestUnauthorisedPeerRejected(t *testing.T) {
	fb := &fakeBackend{}
	_, c := start(t, func(s *Server) {
		s.AllowedUIDs = []uint32{4242}
		s.PeerUID = func(net.Conn) (uint32, error) { return 31337, nil }
	}, fb)
	if _, err := c.Inventory(context.Background()); err == nil {
		t.Fatal("peer with an unauthorised uid must be rejected")
	}
	if fb.scans.Load() != 0 {
		t.Error("no scan may run for an unauthorised peer")
	}
	// credential lookup failure rejects as well
	_, c2 := start(t, func(s *Server) {
		s.PeerUID = func(net.Conn) (uint32, error) { return 0, errors.New("no creds") }
	}, fb)
	if _, err := c2.Facts(context.Background(), nil); err == nil {
		t.Fatal("unknown peer credentials must be rejected")
	}
}

// Real SO_PEERCRED: the test process connects to itself, so its own uid is reported.
func TestRealPeerCredentials(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SO_PEERCRED is Linux-only")
	}
	_, c := start(t, func(s *Server) { s.PeerUID = nil; s.AllowedUIDs = []uint32{uint32(os.Getuid())} }, &fakeBackend{})
	if _, err := c.Facts(context.Background(), nil); err != nil {
		t.Fatalf("own uid must be accepted: %v", err)
	}
	if os.Getuid() == 0 {
		t.Log("running as root: the rejection path with a real peer uid is covered by the decision-function test")
		return
	}
	_, c2 := start(t, func(s *Server) { s.PeerUID = nil; s.AllowedUIDs = []uint32{uint32(os.Getuid()) + 1} }, &fakeBackend{})
	if _, err := c2.Facts(context.Background(), nil); err == nil {
		t.Fatal("a uid that is neither root nor allowed must be rejected")
	}
}

// The collector runs as root without network access, so its dependency tree must not
// contain the HTTP transport or the runner (which owns the HTTP client and the credentials).
// `go list -deps` is the check; net/http itself is still linked via the SBOM scanner, which is
// why the unit file additionally denies all IP traffic.
func TestNoTransportDependency(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go tool not available")
	}
	out, err := exec.Command(goBin, "list", "-deps", "panoptes/internal/agent/collector").CombinedOutput()
	if err != nil {
		t.Skipf("go list failed: %v\n%s", err, out)
	}
	for _, pkg := range []string{"panoptes/internal/agent/transport", "panoptes/internal/agent/runner"} {
		if strings.Contains("\n"+string(out), "\n"+pkg+"\n") {
			t.Errorf("collector must not depend on %s", pkg)
		}
	}
}
