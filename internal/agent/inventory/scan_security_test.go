package inventory

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DonSosiska/holealign/internal/agent/config"
)

func TestSafeScanRecoversPanic(t *testing.T) {
	out, err := safeScan("host", time.Minute, context.Background(), func(context.Context) ([]byte, error) {
		var m map[string]int
		//lint:ignore SA5000 intentional nil map write to test panic recovery
		m["x"] = 1 // nil map write panics
		return []byte("unreachable"), nil
	})
	if out != nil || err == nil || !strings.Contains(err.Error(), "panicked") {
		t.Fatalf("out=%q err=%v", out, err)
	}
}

func TestSafeScanPassesResultAndError(t *testing.T) {
	out, err := safeScan("x", 0, context.Background(), func(context.Context) ([]byte, error) { return []byte("ok"), nil })
	if err != nil || string(out) != "ok" {
		t.Fatalf("%q %v", out, err)
	}
	want := errors.New("bad")
	if _, err := safeScan("x", time.Minute, context.Background(), func(context.Context) ([]byte, error) { return nil, want }); !errors.Is(err, want) {
		t.Fatalf("err = %v", err)
	}
}

func TestSafeScanTimeout(t *testing.T) {
	_, err := safeScan("x", 20*time.Millisecond, context.Background(), func(ctx context.Context) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
}

func TestDefaultExcludes(t *testing.T) {
	d := config.Default()
	for _, p := range []string{"/mnt", "/media", "/var/lib/containers", "/var/lib/kubelet", "/var/lib/lxc", "/var/lib/lxd", "/home/*/.cache"} {
		found := false
		for _, e := range d.ExcludePaths {
			found = found || e == p
		}
		if !found {
			t.Errorf("default exclude %s missing", p)
		}
	}
	if d.HostScanTimeout != 10*time.Minute || d.ImageScanTimeout != 5*time.Minute {
		t.Errorf("timeouts %v %v", d.HostScanTimeout, d.ImageScanTimeout)
	}
	pats := excludePatterns([]string{"/home/*/.cache"})
	if len(pats) != 2 || pats[0] != "./home/*/.cache" {
		t.Errorf("patterns %v", pats)
	}
}
