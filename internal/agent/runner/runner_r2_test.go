package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/DonSosiska/holealign/internal/agent/config"
	"github.com/DonSosiska/holealign/internal/agent/hostdata"
	"github.com/DonSosiska/holealign/internal/model"
)

func fr(name, path, pattern string) model.FactRequest {
	return model.FactRequest{Name: name, Collector: "file.match", Params: map[string]string{"path": path, "pattern": pattern}}
}

func TestSanitizeFactRequests(t *testing.T) {
	var in []model.FactRequest
	in = append(in,
		fr("file.match:ok", "/etc/a", "x"),
		fr("file.match:ok", "/etc/dup-name", "x"),                 // duplicate name
		fr("nomatch:x", "/etc/a", "x"),                            // wrong prefix
		fr("file.match:", "/etc/a", "x"),                          // empty id
		fr("file.match:"+strings.Repeat("n", 120), "/etc/a", "x"), // name > 128
		fr("file.match:rel", "etc/a", "x"),                        // relative path
		fr("file.match:nopat", "/etc/a", ""),
		fr("file.match:longpath", "/"+strings.Repeat("p", 512), "x"),
		fr("file.match:longpat", "/etc/a", strings.Repeat("p", 513)),
		fr("file.match:nul", "/etc/a\x00b", "x"),
		fr("file.match:badutf", "/etc/\xff", "x"),
		model.FactRequest{Name: "file.match:coll", Collector: "shell", Params: map[string]string{"path": "/etc/a", "pattern": "x"}},
	)
	in[0].Params["extra"] = "ignored"
	out, dropped := sanitizeFactRequests(in)
	if len(out) != 1 || out[0].Name != "file.match:ok" || len(out[0].Params) != 2 {
		t.Fatalf("kept %+v", out)
	}
	if dropped != len(in)-1 {
		t.Errorf("dropped = %d, want %d", dropped, len(in)-1)
	}

	// at most 20
	many := make([]model.FactRequest, 0, 50)
	for i := 0; i < 50; i++ {
		many = append(many, fr(fmt.Sprintf("file.match:r%d", i), "/etc/a", "x"))
	}
	if out, _ := sanitizeFactRequests(many); len(out) != maxFactRequests {
		t.Errorf("kept %d, want %d", len(out), maxFactRequests)
	}

	// worst-case JSON escaping must still fit the collector's request cap
	big := make([]model.FactRequest, 0, 20)
	for i := 0; i < 20; i++ {
		big = append(big, fr(fmt.Sprintf("file.match:%0100d", i), "/"+strings.Repeat("\x01", 500), strings.Repeat("<", 500)))
	}
	out, _ = sanitizeFactRequests(big)
	line, _ := json.Marshal(hostdata.Request{Op: hostdata.OpFacts, FactRequests: out})
	if len(line)+1 > hostdata.MaxRequestBytes {
		t.Errorf("request line is %d bytes, over the cap", len(line))
	}
}

// scriptSource lets a test drive Facts/Info results and observe forget calls.
type scriptSource struct {
	fakeSource
	mu2       sync.Mutex
	factsFn   func(reqs []model.FactRequest) (model.Facts, error)
	infoErr   error
	calls     [][]model.FactRequest
	forgotten int
	forgetErr error
}

func (s *scriptSource) Facts(_ context.Context, reqs []model.FactRequest) (model.Facts, error) {
	s.mu2.Lock()
	defer s.mu2.Unlock()
	s.calls = append(s.calls, reqs)
	return s.factsFn(reqs)
}

func (s *scriptSource) Info(ctx context.Context) (hostdata.HostInfo, error) {
	if s.infoErr != nil {
		return hostdata.HostInfo{}, s.infoErr
	}
	return s.fakeSource.Info(ctx)
}

func (s *scriptSource) ForgetEnrollToken(context.Context) error {
	s.forgotten++
	return s.forgetErr
}

type serverRec struct {
	mu       sync.Mutex
	checkins []model.CheckinRequest
	respond  model.CheckinResponse
}

func (sr *serverRec) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sr.mu.Lock()
		defer sr.mu.Unlock()
		switch r.URL.Path {
		case "/api/v1/enroll":
			json.NewEncoder(w).Encode(model.EnrollResponse{AgentID: "id", AgentKey: "key"})
		case "/api/v1/checkin":
			var req model.CheckinRequest
			json.NewDecoder(r.Body).Decode(&req)
			sr.checkins = append(sr.checkins, req)
			json.NewEncoder(w).Encode(sr.respond)
		default:
			w.WriteHeader(202)
		}
	})
}

func scriptedRunner(t *testing.T, src hostdata.Source) (*Runner, *serverRec) {
	t.Helper()
	rec := &serverRec{}
	srv := httptest.NewServer(rec.handler())
	t.Cleanup(srv.Close)
	cfg := config.Default()
	cfg.ServerURL = srv.URL
	cfg.AllowInsecureHTTP = true
	cfg.EnrollToken = "tok"
	cfg.StateDir = t.TempDir()
	r := mustNew(t, cfg)
	r.src = src
	r.lastInvAt = r.lastInvAt.Add(1) // not zero: no inventory needed in these tests
	return r, rec
}

func TestServerFactRequestsAreFilteredBeforeStorage(t *testing.T) {
	src := &scriptSource{factsFn: func([]model.FactRequest) (model.Facts, error) { return model.Facts{"a": "1"}, nil }}
	r, rec := scriptedRunner(t, src)
	rec.respond.FactRequests = append([]model.FactRequest{fr("evil:x", "/etc/passwd", "."), fr("file.match:ok", "/etc/a", "x")}, make([]model.FactRequest, 100)...)
	if err := r.ensureEnrolled(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.checkinAndUpload(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if len(r.factRequests) != 1 || r.factRequests[0].Name != "file.match:ok" {
		t.Errorf("stored %+v", r.factRequests)
	}
}

func TestCollectorErrorDoesNotBlockCheckin(t *testing.T) {
	fail := false
	src := &scriptSource{factsFn: func([]model.FactRequest) (model.Facts, error) {
		if fail {
			return nil, errors.New("collector: boom " + strings.Repeat("x", 400))
		}
		return model.Facts{"a": "1", "b": "2"}, nil
	}}
	r, rec := scriptedRunner(t, src)
	ctx := context.Background()
	r.ensureEnrolled(ctx)
	if _, err := r.checkinAndUpload(ctx, false); err != nil {
		t.Fatal(err)
	}
	fail = true
	if _, err := r.checkinAndUpload(ctx, false); err != nil {
		t.Fatalf("collector error blocked the check-in: %v", err)
	}
	rec.mu.Lock()
	d := rec.checkins[1]
	rec.mu.Unlock()
	msg, _ := d.Facts[collectorErrKey].(string)
	if msg == "" || len(msg) > 200 || !strings.HasPrefix(msg, "collector: boom") {
		t.Errorf("collector_error = %q", msg)
	}
	if _, gone := d.Facts["a"]; gone && d.Facts["a"] == nil {
		t.Error("known facts must not be deleted by a collector error")
	}
	if len(d.Facts) != 1 {
		t.Errorf("diff should only add the error: %v", d.Facts)
	}
	// recovery removes the error fact
	fail = false
	if _, err := r.checkinAndUpload(ctx, false); err != nil {
		t.Fatal(err)
	}
	rec.mu.Lock()
	d = rec.checkins[2]
	rec.mu.Unlock()
	if v, ok := d.Facts[collectorErrKey]; !ok || v != nil {
		t.Errorf("collector_error must be cleared: %v", d.Facts)
	}
}

func TestCollectorErrorOnFirstCheckin(t *testing.T) {
	src := &scriptSource{factsFn: func([]model.FactRequest) (model.Facts, error) { return nil, errors.New("collector: busy") }}
	r, rec := scriptedRunner(t, src)
	r.ensureEnrolled(context.Background())
	if _, err := r.checkinAndUpload(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if len(rec.checkins) != 1 || rec.checkins[0].Facts[collectorErrKey] != "collector: busy" {
		t.Errorf("checkins = %+v", rec.checkins)
	}
}

func TestUnreachableCollectorStillSkipsTheCycle(t *testing.T) {
	src := &scriptSource{factsFn: func([]model.FactRequest) (model.Facts, error) {
		return nil, fmt.Errorf("%w: dial unix: no such file", hostdata.ErrUnavailable)
	}}
	r, rec := scriptedRunner(t, src)
	r.ensureEnrolled(context.Background())
	if _, err := r.checkinAndUpload(context.Background(), false); err == nil {
		t.Error("an unreachable collector must still fail the cycle")
	}
	if len(rec.checkins) != 0 {
		t.Error("no check-in without a collector")
	}
}

func TestRejectedFactRequestsAreClearedAndRetriedOnce(t *testing.T) {
	for _, msg := range []string{"collector: request too large", "collector: bad request: invalid character"} {
		src := &scriptSource{factsFn: func(reqs []model.FactRequest) (model.Facts, error) {
			if len(reqs) > 0 {
				return nil, errors.New(msg)
			}
			return model.Facts{"a": "1"}, nil
		}}
		r, rec := scriptedRunner(t, src)
		r.ensureEnrolled(context.Background())
		r.factRequests = []model.FactRequest{fr("file.match:x", "/etc/a", "x")}
		if _, err := r.checkinAndUpload(context.Background(), false); err != nil {
			t.Fatalf("%s: %v", msg, err)
		}
		if len(r.factRequests) != 0 || len(src.calls) != 2 || len(src.calls[1]) != 0 {
			t.Errorf("%s: requests=%v calls=%v", msg, r.factRequests, src.calls)
		}
		if len(rec.checkins) != 1 || rec.checkins[0].Facts["a"] != "1" || rec.checkins[0].Facts[collectorErrKey] != nil {
			t.Errorf("%s: check-in %+v", msg, rec.checkins)
		}
	}
}

func TestEnrollTokenForgottenOnceAfterFirstCheckin(t *testing.T) {
	src := &scriptSource{factsFn: func([]model.FactRequest) (model.Facts, error) { return model.Facts{}, nil }}
	r, _ := scriptedRunner(t, src)
	ctx := context.Background()
	if err := r.ensureEnrolled(ctx); err != nil {
		t.Fatal(err)
	}
	if src.forgotten != 0 {
		t.Fatal("forgot before any check-in")
	}
	for i := 0; i < 3; i++ {
		if _, err := r.checkinAndUpload(ctx, false); err != nil {
			t.Fatal(err)
		}
	}
	if src.forgotten != 1 {
		t.Errorf("forget_enroll_token called %d times, want 1", src.forgotten)
	}
	if r.cfg.EnrollToken != "" {
		t.Error("in-memory token should be dropped after a successful forget")
	}
}

func TestEnrollTokenForgetFailureIsNotFatalAndNotRetried(t *testing.T) {
	src := &scriptSource{factsFn: func([]model.FactRequest) (model.Facts, error) { return model.Facts{}, nil }, forgetErr: errors.New("read-only")}
	r, _ := scriptedRunner(t, src)
	ctx := context.Background()
	r.ensureEnrolled(ctx)
	for i := 0; i < 2; i++ {
		if _, err := r.checkinAndUpload(ctx, false); err != nil {
			t.Fatal(err)
		}
	}
	if src.forgotten != 1 {
		t.Errorf("calls = %d, want 1", src.forgotten)
	}
	if r.cfg.EnrollToken == "" {
		t.Error("token must stay usable in memory when the file could not be changed")
	}
}

func TestNoForgetWithoutToken(t *testing.T) {
	src := &scriptSource{factsFn: func([]model.FactRequest) (model.Facts, error) { return model.Facts{}, nil }}
	r, _ := scriptedRunner(t, src)
	r.cfg.EnrollToken = ""
	r.creds.AgentKey = "k"
	r.client.Key = "k"
	if _, err := r.checkinAndUpload(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if src.forgotten != 0 {
		t.Error("nothing to forget")
	}
}
