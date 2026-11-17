package collector

import (
	"context"
	"errors"
	"os"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"panoptes/internal/agent/hostdata"
	"panoptes/internal/model"
)

// gateBackend blocks Facts and Inventory until released, and counts calls.
type gateBackend struct {
	fakeBackend
	factCalls atomic.Int32
	gate      chan struct{}
	started   chan struct{}
	forgotten atomic.Int32
	forgetErr error
}

func newGateBackend() *gateBackend {
	return &gateBackend{gate: make(chan struct{}), started: make(chan struct{}, 16)}
}

func (g *gateBackend) Facts(ctx context.Context, reqs []model.FactRequest) (model.Facts, error) {
	g.factCalls.Add(1)
	g.started <- struct{}{}
	<-g.gate
	return model.Facts{"n": len(reqs)}, nil
}

func (g *gateBackend) Inventory(ctx context.Context) (model.InventoryPayload, error) {
	g.started <- struct{}{}
	<-g.gate
	return g.fakeBackend.Inventory(ctx)
}

func (g *gateBackend) ForgetEnrollToken(context.Context) error {
	g.forgotten.Add(1)
	return g.forgetErr
}

func TestFactsCachedPerRequestSet(t *testing.T) {
	g := newGateBackend()
	close(g.gate) // never blocks
	_, c := start(t, func(s *Server) { s.FactsCacheTTL = time.Hour }, g)
	ctx := context.Background()
	a := []model.FactRequest{{Name: "file.match:a", Collector: "file.match", Params: map[string]string{"path": "/etc/a", "pattern": "x"}}}
	b := []model.FactRequest{{Name: "file.match:b", Collector: "file.match", Params: map[string]string{"path": "/etc/b", "pattern": "x"}}}
	for i := 0; i < 3; i++ {
		if _, err := c.Facts(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	if n := g.factCalls.Load(); n != 1 {
		t.Errorf("identical requests collected %d times, want 1", n)
	}
	if _, err := c.Facts(ctx, b); err != nil {
		t.Fatal(err)
	}
	if n := g.factCalls.Load(); n != 2 {
		t.Errorf("a different request set must collect again: %d", n)
	}
}

func TestFactsCacheExpires(t *testing.T) {
	g := newGateBackend()
	close(g.gate)
	_, c := start(t, func(s *Server) { s.FactsCacheTTL = 30 * time.Millisecond }, g)
	c.Facts(context.Background(), nil)
	time.Sleep(60 * time.Millisecond)
	c.Facts(context.Background(), nil)
	if n := g.factCalls.Load(); n != 2 {
		t.Errorf("collections = %d, want 2", n)
	}
}

func TestBusyFailsFast(t *testing.T) {
	g := newGateBackend()
	_, c := start(t, func(s *Server) { s.FactsCacheTTL = -1; s.InventoryMinGap = -1 }, g)
	ctx := context.Background()
	var wg sync.WaitGroup
	call := func(f func()) {
		wg.Add(1)
		go func() { defer wg.Done(); f() }()
	}
	// fill both facts slots and the single inventory slot
	for i := 0; i < maxFactsOps; i++ {
		call(func() { c.Facts(ctx, nil) })
		<-g.started
	}
	call(func() { c.Inventory(ctx) })
	<-g.started

	begin := time.Now()
	if _, err := c.Facts(ctx, nil); err == nil || !strings.Contains(err.Error(), "busy") {
		t.Errorf("extra facts request: %v, want busy", err)
	}
	if _, err := c.Inventory(ctx); err == nil || !strings.Contains(err.Error(), "busy") {
		t.Errorf("extra inventory request: %v, want busy", err)
	}
	if d := time.Since(begin); d > 2*time.Second {
		t.Errorf("busy answer took %v, must not queue", d)
	}
	// other operations are unaffected
	if _, err := c.Info(ctx); err != nil {
		t.Errorf("osinfo while busy: %v", err)
	}
	close(g.gate)
	wg.Wait()
	if _, err := c.Facts(ctx, nil); err != nil {
		t.Errorf("facts after release: %v", err)
	}
}

func TestPendingChangeBypassesCacheButIsRateLimited(t *testing.T) {
	fb := &fakeBackend{}
	_, c := start(t, func(s *Server) { s.InventoryMinGap = time.Hour; s.ChangeMinGap = 150 * time.Millisecond }, fb)
	ctx := context.Background()
	if inv, err := c.Inventory(ctx); err != nil || inv.Hash != "h1" {
		t.Fatalf("first scan: %+v %v", inv, err)
	}
	fb.changed.Store(true)
	if ch, err := c.Changed(ctx); err != nil || !ch {
		t.Fatalf("changed: %v %v", ch, err)
	}
	// the backend consumed its signal, but the collector keeps reporting it
	if ch, _ := c.Changed(ctx); !ch {
		t.Fatal("change flag lost before a real scan")
	}
	// inside the change gap: still the cached inventory (bounds a hostile peer)
	if inv, _ := c.Inventory(ctx); inv.Hash != "h1" || fb.scans.Load() != 1 {
		t.Fatalf("scan inside the change gap: %+v scans=%d", inv, fb.scans.Load())
	}
	if ch, _ := c.Changed(ctx); !ch {
		t.Fatal("change flag must survive a cached answer")
	}
	time.Sleep(200 * time.Millisecond)
	if inv, err := c.Inventory(ctx); err != nil || inv.Hash != "h2" {
		t.Fatalf("change did not trigger a real scan: %+v %v", inv, err)
	}
	if ch, _ := c.Changed(ctx); ch {
		t.Error("flag must be cleared by the real scan")
	}
	// without a pending change the cache is used again
	if inv, _ := c.Inventory(ctx); inv.Hash != "h2" || fb.scans.Load() != 2 {
		t.Errorf("unexpected scan: %+v scans=%d", inv, fb.scans.Load())
	}
}

func TestFailedScanKeepsChangePending(t *testing.T) {
	fb := &fakeBackend{scanErr: errors.New("boom")}
	_, c := start(t, func(s *Server) { s.InventoryMinGap = time.Hour; s.ChangeMinGap = 10 * time.Millisecond }, fb)
	ctx := context.Background()
	fb.changed.Store(true)
	c.Changed(ctx)
	c.Inventory(ctx) // fails
	if ch, _ := c.Changed(ctx); !ch {
		t.Error("a failed scan must not clear the change flag")
	}
}

func TestForgetEnrollTokenOp(t *testing.T) {
	g := newGateBackend()
	_, c := start(t, nil, g)
	ctx := context.Background()
	if err := c.ForgetEnrollToken(ctx); err != nil || g.forgotten.Load() != 1 {
		t.Fatalf("forget: err=%v calls=%d", err, g.forgotten.Load())
	}
	g.forgetErr = errors.New("read-only")
	if err := c.ForgetEnrollToken(ctx); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Errorf("error not reported: %v", err)
	}
	// a backend without the capability answers with an error
	_, c2 := start(t, nil, &fakeBackend{})
	if err := c2.ForgetEnrollToken(ctx); err == nil {
		t.Error("backend without ForgetEnrollToken must fail")
	}
}

func TestClientReportsUnavailable(t *testing.T) {
	c := hostdata.NewClient("/nonexistent/collector.sock")
	_, err := c.Facts(context.Background(), nil)
	if !errors.Is(err, hostdata.ErrUnavailable) {
		t.Errorf("err = %v, want ErrUnavailable", err)
	}
	// an answering collector that reports an error is NOT "unavailable"
	_, c2 := start(t, func(s *Server) { s.InventoryMinGap = time.Hour }, &fakeBackend{scanErr: errors.New("x")})
	if _, err := c2.Inventory(context.Background()); errors.Is(err, hostdata.ErrUnavailable) {
		t.Errorf("collector error classified as unavailable: %v", err)
	}
}

// Listen with the group already right (systemd Group=, UMask=) yields the right socket.
func TestListenKeepsCorrectSocketWithoutWarning(t *testing.T) {
	u, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	g, err := user.LookupGroupId(u.Gid)
	if err != nil {
		t.Skip(err)
	}
	srv, c := start(t, func(s *Server) { s.Group = g.Name }, &fakeBackend{})
	fi, err := os.Stat(srv.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o660 {
		t.Errorf("mode = %v", fi.Mode().Perm())
	}
	if gid, ok := fileGID(fi); ok && u.Gid != "" && strconv.Itoa(gid) != u.Gid {
		t.Errorf("gid = %d, want %s", gid, u.Gid)
	}
	if _, err := c.Facts(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
}
