//go:build unix

package inventory

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// Every check-in builds a fresh docker client; without DisableKeepAlives each one would
// leave an idle connection (and its goroutines) behind.
func TestDockerClientDoesNotLeakConnections(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "pdock")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "d.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`[]`))
	})}
	go srv.Serve(l)
	defer srv.Close()

	call := func() {
		c := newDockerClient(sock)
		if c == nil {
			t.Fatal("no client")
		}
		if _, err := c.images(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	call() // warm up lazily started runtime goroutines
	time.Sleep(100 * time.Millisecond)
	before := runtime.NumGoroutine()
	for i := 0; i < 50; i++ {
		call()
	}
	time.Sleep(200 * time.Millisecond)
	if after := runtime.NumGoroutine(); after > before+5 {
		t.Errorf("goroutines grew from %d to %d over 50 clients", before, after)
	}
}
