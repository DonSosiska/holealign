package collector

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/DonSosiska/holealign/internal/model"
)

// ctxBackend blocks Facts until its context ends and reports that it did.
type ctxBackend struct {
	fakeBackend
	started chan struct{}
	ended   chan error
}

func (b *ctxBackend) Facts(ctx context.Context, _ []model.FactRequest) (model.Facts, error) {
	b.started <- struct{}{}
	<-ctx.Done()
	b.ended <- ctx.Err()
	return model.Facts{}, nil
}

func TestFactsRequestDeadline(t *testing.T) {
	b := &ctxBackend{started: make(chan struct{}, 1), ended: make(chan error, 1)}
	_, c := start(t, func(s *Server) { s.FactsTimeout = 200 * time.Millisecond }, b)
	go c.Facts(context.Background(), nil)
	<-b.started
	select {
	case err := <-b.ended:
		if err != context.DeadlineExceeded {
			t.Errorf("ctx err = %v, want deadline exceeded", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("facts request not bounded by the deadline")
	}
}

func TestFactsCancelledWhenClientCloses(t *testing.T) {
	b := &ctxBackend{started: make(chan struct{}, 1), ended: make(chan error, 1)}
	srv, _ := start(t, func(s *Server) { s.FactsTimeout = time.Minute }, b)
	conn, err := net.Dial("unix", srv.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte(`{"op":"facts"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	<-b.started
	conn.Close()
	select {
	case err := <-b.ended:
		if err != context.Canceled {
			t.Errorf("ctx err = %v, want canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("facts collection kept running after the client closed")
	}
}

// slowInvBackend blocks Inventory until released.
type slowInvBackend struct {
	fakeBackend
	started chan struct{}
	release chan struct{}
}

func (b *slowInvBackend) Inventory(ctx context.Context) (model.InventoryPayload, error) {
	b.started <- struct{}{}
	<-b.release
	return b.fakeBackend.Inventory(ctx)
}

func TestInventoryInProgressIsBusyNotNil(t *testing.T) {
	b := &slowInvBackend{started: make(chan struct{}, 1), release: make(chan struct{})}
	srv, c := start(t, nil, b)
	first := make(chan error, 1)
	go func() { _, err := c.Inventory(context.Background()); first <- err }()
	<-b.started

	p, err := srv.inventory(context.Background())
	if err == nil || p != nil {
		t.Fatalf("concurrent request got (%v, %v), want a busy error", p, err)
	}
	close(b.release)
	if err := <-first; err != nil {
		t.Fatalf("first scan: %v", err)
	}
	if p, err := srv.inventory(context.Background()); err != nil || p == nil {
		t.Fatalf("after the scan: (%v, %v), want the cached inventory", p, err)
	}
}

// flakyListener fails the first Accept calls with a temporary error.
type flakyListener struct {
	net.Listener
	fails atomic.Int32
	err   error
}

func (l *flakyListener) Accept() (net.Conn, error) {
	if l.fails.Add(-1) >= 0 {
		return nil, &net.OpError{Op: "accept", Err: os.NewSyscallError("accept", l.err)}
	}
	return l.Listener.Accept()
}

func TestServeSurvivesTemporaryAcceptErrors(t *testing.T) {
	for _, e := range []error{syscall.EMFILE, syscall.ENFILE, syscall.ECONNABORTED} {
		dir, err := os.MkdirTemp("/tmp", "pcol")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)
		sock := filepath.Join(dir, "c.sock")
		l, err := net.Listen("unix", sock)
		if err != nil {
			t.Skipf("unix sockets unavailable: %v", err)
		}
		fl := &flakyListener{Listener: l, err: e}
		fl.fails.Store(3)
		srv := &Server{
			Backend: &fakeBackend{}, SocketPath: sock,
			PeerUID: func(net.Conn) (uint32, error) { return 0, nil },
			Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- srv.ServeListener(ctx, fl) }()

		deadline := time.Now().Add(5 * time.Second)
		var ok bool
		for time.Now().Before(deadline) && !ok {
			select {
			case err := <-done:
				t.Fatalf("%v: ServeListener returned %v", e, err)
			default:
			}
			conn, err := net.Dial("unix", sock)
			if err == nil {
				conn.Write([]byte(`{"op":"osinfo"}` + "\n"))
				conn.SetReadDeadline(time.Now().Add(time.Second))
				buf := make([]byte, 1)
				if n, _ := conn.Read(buf); n == 1 {
					ok = true
				}
				conn.Close()
			}
		}
		cancel()
		<-done
		if !ok {
			t.Errorf("%v: no request served after temporary accept errors", e)
		}
	}
}
