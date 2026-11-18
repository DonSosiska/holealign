package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/DonSosiska/panoptes/internal/model"
)

// stalledUpload starts an inventory upload whose body never completes; it returns the pipe to
// finish it and a channel with the response status.
func (e *env) stalledUpload(t *testing.T, key string) (*io.PipeWriter, <-chan int) {
	t.Helper()
	pr, pw := io.Pipe()
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/inventory", pr)
	req.Header.Set("Authorization", "Bearer "+key)
	done := make(chan int, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			done <- -1
			return
		}
		resp.Body.Close()
		done <- resp.StatusCode
	}()
	_, _ = pw.Write([]byte(`{"hash":`)) // the handler is now blocked inside the decoder
	time.Sleep(150 * time.Millisecond)
	return pw, done
}

func TestInventoryAttemptBucketChargedBeforeBody(t *testing.T) {
	now := time.Now()
	e := setupWith(t, func(d *Deps) {
		d.Now = func() time.Time { return now }
		d.CheckinInterval, d.EnrollPerMinute, d.BadAuthPerMinute = -1, -1, -1
		d.InvalidInventoryPerMinute = 1000
	})
	er := e.enroll(t, "m")
	js, _ := json.Marshal(model.InventoryPayload{Hash: "same", Targets: []model.InventoryTarget{{Kind: model.TargetHost, Name: "host", SBOM: cdxMin}}})
	var ra string
	for i := 0; i < 8; i++ {
		resp, _ := e.do(t, "POST", "/api/v1/inventory", er.AgentKey, js, nil)
		want := 202 // identical-hash re-uploads included: burst 6, then 429
		if i >= 6 {
			want = 429
			ra = resp.Header.Get("Retry-After")
		}
		if resp.StatusCode != want {
			t.Fatalf("request %d: %d, want %d", i, resp.StatusCode, want)
		}
	}
	if ra != "6" { // 10/min -> one token per 6 s
		t.Fatalf("Retry-After=%q", ra)
	}
	now = now.Add(7 * time.Second)
	if resp, _ := e.do(t, "POST", "/api/v1/inventory", er.AgentKey, js, nil); resp.StatusCode != 202 {
		t.Fatalf("after refill: %d", resp.StatusCode)
	}
}

func TestInventoryOneDecodePerHost(t *testing.T) {
	e := setupWith(t, func(d *Deps) {
		d.CheckinInterval, d.EnrollPerMinute, d.BadAuthPerMinute = -1, -1, -1
	})
	er := e.enroll(t, "m")
	pw, done := e.stalledUpload(t, er.AgentKey)
	js, _ := json.Marshal(model.InventoryPayload{Hash: "x", Targets: []model.InventoryTarget{{Kind: model.TargetHost, Name: "host", SBOM: cdxMin}}})
	resp, body := e.do(t, "POST", "/api/v1/inventory", er.AgentKey, js, nil)
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("concurrent upload: %d %s", resp.StatusCode, body)
	}
	_ = pw.CloseWithError(io.ErrClosedPipe)
	<-done
	if resp, body := e.do(t, "POST", "/api/v1/inventory", er.AgentKey, js, nil); resp.StatusCode != 202 {
		t.Fatalf("after release: %d %s", resp.StatusCode, body)
	}
}

func TestInventoryGlobalDecodeSemaphore(t *testing.T) {
	e := setupWith(t, func(d *Deps) {
		d.CheckinInterval, d.EnrollPerMinute, d.BadAuthPerMinute = -1, -1, -1
		d.InventoryConcurrentDecodes = 1
	})
	a, b := e.enroll(t, "a"), e.enroll(t, "b")
	pw, done := e.stalledUpload(t, a.AgentKey)
	js, _ := json.Marshal(model.InventoryPayload{Hash: "x", Targets: []model.InventoryTarget{{Kind: model.TargetHost, Name: "host", SBOM: cdxMin}}})
	resp, body := e.do(t, "POST", "/api/v1/inventory", b.AgentKey, js, nil)
	if resp.StatusCode != 503 || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("semaphore full: %d %s", resp.StatusCode, body)
	}
	_ = pw.CloseWithError(io.ErrClosedPipe)
	<-done
	if resp, body := e.do(t, "POST", "/api/v1/inventory", b.AgentKey, js, nil); resp.StatusCode != 202 {
		t.Fatalf("after release: %d %s", resp.StatusCode, body)
	}
}

func TestCheckinOSBlockStoredCleaned(t *testing.T) {
	e := setup(t)
	er := e.enroll(t, "m")
	big := strings.Repeat("a", 1<<20)
	req := model.CheckinRequest{OS: model.OSInfo{
		ID: "Debian", VersionID: "12.1", PrettyName: "Evil‮ OS\x00" + big, Kernel: "6.1​.0" + big, Arch: "amd64" + big,
	}}
	if resp, body := e.do(t, "POST", "/api/v1/checkin", er.AgentKey, req, nil); resp.StatusCode != 200 {
		t.Fatalf("checkin: %d %s", resp.StatusCode, body)
	}
	h, err := e.st.GetHost(context.Background(), er.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	if h.OS.ID != "" || h.OS.VersionID != "12.1" {
		t.Fatalf("id/version: %+v", h.OS)
	}
	if len(h.OS.PrettyName) > 128 || strings.ContainsAny(h.OS.PrettyName, "‮\x00") || len(h.OS.Kernel) > 128 || strings.Contains(h.OS.Kernel, "​") || len(h.OS.Arch) > 64 {
		t.Fatalf("not cleaned: %d %d %d", len(h.OS.PrettyName), len(h.OS.Kernel), len(h.OS.Arch))
	}
}

func TestCleanOS(t *testing.T) {
	long := strings.Repeat("x", 5000)
	got := cleanOS(model.OSInfo{ID: "debian", VersionID: "12.4", PrettyName: "Debian‮ GNU\x00/Linux​ " + long, Kernel: "6.1.0-⁦x" + long, Arch: long})
	if got.ID != "debian" || got.VersionID != "12.4" {
		t.Fatalf("id/version: %+v", got)
	}
	if len([]rune(got.PrettyName)) != 128 || strings.ContainsAny(got.PrettyName, "‮\x00​") || !strings.HasPrefix(got.PrettyName, "Debian GNU/Linux ") {
		t.Fatalf("pretty: %q", got.PrettyName)
	}
	if len([]rune(got.Kernel)) != 128 || strings.Contains(got.Kernel, "⁦") || len(got.Arch) != 64 {
		t.Fatalf("kernel/arch: %q %d", got.Kernel, len(got.Arch))
	}
	// ids outside the conservative charset are dropped, not rejected
	for _, bad := range []string{"Debian", "de bian", "deb;ian", "-debian", "debïan"} {
		if g := cleanOS(model.OSInfo{ID: bad, VersionID: bad}); g.ID != "" || g.VersionID != "" {
			t.Fatalf("%q kept: %+v", bad, g)
		}
	}
	if g := cleanOS(model.OSInfo{ID: "ubuntu​"}); g.ID != "ubuntu" {
		t.Fatalf("zero-width stripped then validated: %q", g.ID)
	}
	if g := cleanOS(model.OSInfo{ID: strings.Repeat("a", 100)}); len(g.ID) != 64 {
		t.Fatalf("id cap: %d", len(g.ID))
	}
}
