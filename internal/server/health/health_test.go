package health

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"panoptes/internal/model"
	"panoptes/internal/server/feeds"
	"panoptes/internal/server/notify"
	"panoptes/internal/server/store"
)

type fakeNotifier struct {
	mu     sync.Mutex
	events []model.Event
	fail   bool
}

func (f *fakeNotifier) Notify(_ context.Context, evs []model.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		de := &notify.DeliveryError{Err: errors.New("down")}
		for i := range evs {
			de.Failed = append(de.Failed, i)
		}
		return de
	}
	f.events = append(f.events, evs...)
	return nil
}

func (f *fakeNotifier) take() []model.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.events
	f.events = nil
	return out
}

type env struct {
	t   *testing.T
	st  store.Store
	n   *fakeNotifier
	m   *Monitor
	now time.Time
	ctx context.Context
}

func newEnv(t *testing.T, o Options) *env {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	e := &env{t: t, st: st, n: &fakeNotifier{}, now: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC), ctx: context.Background()}
	o.Now = func() time.Time { return e.now }
	e.m = New(st, e.n, o)
	e.now = e.now.Add(time.Hour) // past the start-up grace
	return e
}

func (e *env) host(name string, labels ...string) model.Host {
	e.t.Helper()
	h, err := e.st.EnrollHost(e.ctx, store.EnrollParams{MachineID: "m-" + name, Hostname: name, Labels: labels, KeyHash: "k-" + name})
	if err != nil {
		e.t.Fatal(err)
	}
	return h
}

func (e *env) checkin(h model.Host) {
	e.t.Helper()
	if _, err := e.st.ApplyCheckin(e.ctx, h.ID, model.CheckinRequest{Hostname: h.Hostname, Labels: h.Labels, FactsComplete: true}, e.now); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) check() []model.Event {
	e.t.Helper()
	if err := e.m.Check(e.ctx); err != nil {
		e.t.Fatal(err)
	}
	return e.n.take()
}

func kinds(evs []model.Event) string {
	var s []string
	for _, e := range evs {
		s = append(s, string(e.Kind))
	}
	return strings.Join(s, ",")
}

func TestAgentSilentBackSilentAgain(t *testing.T) {
	e := newEnv(t, Options{AgentSilentAfter: 30 * time.Minute})
	h := e.host("web1", "prod")
	e.checkin(h)

	if evs := e.check(); len(evs) != 0 {
		t.Fatalf("fresh host alerted: %v", kinds(evs))
	}
	e.now = e.now.Add(47 * time.Minute)
	evs := e.check()
	if len(evs) != 1 || evs[0].Kind != model.EventAgentSilent || evs[0].Host.ID != h.ID {
		t.Fatalf("want one agent_silent, got %v", kinds(evs))
	}
	if !strings.Contains(evs[0].Detail, "no check-in for 47m") || evs[0].ServerLevel() {
		t.Fatalf("detail=%q serverLevel=%v", evs[0].Detail, evs[0].ServerLevel())
	}
	e.now = e.now.Add(10 * time.Minute)
	if evs := e.check(); len(evs) != 0 {
		t.Fatalf("still silent must not repeat: %v", kinds(evs))
	}
	e.checkin(h)
	evs = e.check()
	if len(evs) != 1 || evs[0].Kind != model.EventAgentBack {
		t.Fatalf("want agent_back, got %v", kinds(evs))
	}
	if evs := e.check(); len(evs) != 0 {
		t.Fatalf("back must not repeat: %v", kinds(evs))
	}
	e.now = e.now.Add(time.Hour)
	if evs := e.check(); len(evs) != 1 || evs[0].Kind != model.EventAgentSilent {
		t.Fatalf("silent again must alert again, got %v", kinds(evs))
	}
}

func TestNeverCheckedInAndStartupGrace(t *testing.T) {
	e := newEnv(t, Options{AgentSilentAfter: 30 * time.Minute})
	e.host("never") // enrolled, no check-in
	e.now = e.now.Add(5 * time.Hour)
	if evs := e.check(); len(evs) != 0 {
		t.Fatalf("host without check-in alerted: %v", kinds(evs))
	}
	// A monitor that has just started holds back.
	st, _ := store.OpenSQLite(filepath.Join(t.TempDir(), "g.db"))
	defer st.Close()
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	n := &fakeNotifier{}
	m := New(st, n, Options{AgentSilentAfter: time.Minute, Now: func() time.Time { return now }})
	h, _ := st.EnrollHost(context.Background(), store.EnrollParams{MachineID: "x", Hostname: "x", KeyHash: "kx"})
	_, _ = st.ApplyCheckin(context.Background(), h.ID, model.CheckinRequest{Hostname: "x", FactsComplete: true}, now.Add(-time.Hour))
	if err := m.Check(context.Background()); err != nil || len(n.take()) != 0 {
		t.Fatal("alerted during start-up grace")
	}
}

func TestDisabled(t *testing.T) {
	e := newEnv(t, Options{AgentSilentAfter: 0, FeedStaleAfter: 0})
	h := e.host("web1")
	e.checkin(h)
	e.now = e.now.Add(100 * time.Hour)
	_ = e.st.KVSet(e.ctx, feeds.KVUpdatedAt, e.now.Add(-90*time.Hour).Format(time.RFC3339), e.now)
	if evs := e.check(); len(evs) != 0 {
		t.Fatalf("disabled monitor alerted: %v", kinds(evs))
	}
}

func TestMassSilenceAggregated(t *testing.T) {
	e := newEnv(t, Options{AgentSilentAfter: 30 * time.Minute})
	var hs []model.Host
	for i := 0; i < 30; i++ {
		h := e.host(fmt.Sprintf("srv%02d", i), "prod")
		e.checkin(h)
		hs = append(hs, h)
	}
	e.now = e.now.Add(time.Hour)
	evs := e.check()
	if len(evs) != 1 {
		t.Fatalf("want one aggregated event, got %d", len(evs))
	}
	ev := evs[0]
	if ev.Kind != model.EventAgentSilent || ev.Host.ID != "" || !ev.ServerLevel() {
		t.Fatalf("not an aggregated server-level event: %+v", ev)
	}
	if !strings.HasPrefix(ev.Detail, "30 agents silent — server/network problem?") {
		t.Fatalf("detail=%q", ev.Detail)
	}
	if got := strings.Count(ev.Detail, "• "); got != 20 || !strings.Contains(ev.Detail, "…and 10 more") {
		t.Fatalf("listed %d hostnames: %q", got, ev.Detail)
	}
	if evs := e.check(); len(evs) != 0 {
		t.Fatalf("aggregated hosts alerted again: %v", kinds(evs))
	}
	// they recover one by one: a single host is not "mass", so individual agent_back events... up to
	// the threshold; here all 30 return at once -> one aggregated back.
	for _, h := range hs {
		e.checkin(h)
	}
	evs = e.check()
	if len(evs) != 1 || evs[0].Kind != model.EventAgentBack || evs[0].Host.ID != "" {
		t.Fatalf("want one aggregated agent_back, got %v", kinds(evs))
	}
}

func TestFiveSilentAreIndividual(t *testing.T) {
	e := newEnv(t, Options{AgentSilentAfter: 30 * time.Minute})
	for i := 0; i < 5; i++ {
		e.checkin(e.host(fmt.Sprintf("s%d", i)))
	}
	e.now = e.now.Add(time.Hour)
	if evs := e.check(); len(evs) != 5 {
		t.Fatalf("want 5 individual events, got %d", len(evs))
	}
}

func TestFeedStaleOK(t *testing.T) {
	built := time.Time{}
	e := newEnv(t, Options{FeedStaleAfter: 48 * time.Hour, FeedBuilt: func() time.Time { return built }})
	set := func(k, v string) { _ = e.st.KVSet(e.ctx, k, v, e.now) }

	set(feeds.KVUpdatedAt, e.now.Add(-time.Hour).Format(time.RFC3339))
	if evs := e.check(); len(evs) != 0 {
		t.Fatalf("fresh feed alerted: %v", kinds(evs))
	}
	e.now = e.now.Add(72 * time.Hour)
	set(feeds.KVLastError, "dial tcp: lookup failed")
	evs := e.check()
	if len(evs) != 1 || evs[0].Kind != model.EventFeedStale || !evs[0].ServerLevel() {
		t.Fatalf("want feed_stale, got %v", kinds(evs))
	}
	if !strings.Contains(evs[0].Detail, "last updated 3d") || !strings.Contains(evs[0].Detail, "lookup failed") {
		t.Fatalf("detail=%q", evs[0].Detail)
	}
	if v, _ := e.st.KVGet(e.ctx, KVFeedStale); v == "" {
		t.Fatal("banner kv not set")
	}
	if evs := e.check(); len(evs) != 0 {
		t.Fatalf("stale repeated: %v", kinds(evs))
	}
	// recovery: DB updated, error cleared
	set(feeds.KVUpdatedAt, e.now.Format(time.RFC3339))
	set(feeds.KVLastError, "")
	evs = e.check()
	if len(evs) != 1 || evs[0].Kind != model.EventFeedOK {
		t.Fatalf("want feed_ok, got %v", kinds(evs))
	}
	if v, _ := e.st.KVGet(e.ctx, KVFeedStale); v != "" {
		t.Fatalf("banner kv not cleared: %q", v)
	}
	if evs := e.check(); len(evs) != 0 {
		t.Fatalf("ok repeated: %v", kinds(evs))
	}
	// stale again alerts again
	e.now = e.now.Add(72 * time.Hour)
	if evs := e.check(); len(evs) != 1 || evs[0].Kind != model.EventFeedStale {
		t.Fatalf("want a new feed_stale, got %v", kinds(evs))
	}
}

func TestFeedBuiltTimeAndPersistentError(t *testing.T) {
	built := time.Time{}
	e := newEnv(t, Options{FeedStaleAfter: 48 * time.Hour, FeedBuilt: func() time.Time { return built }})
	// recent updated_at but DB build time wins when newer; both fresh: nothing
	built = e.now.Add(-time.Hour)
	if evs := e.check(); len(evs) != 0 {
		t.Fatalf("got %v", kinds(evs))
	}
	// an error must persist for more than 2 consecutive checks
	_ = e.st.KVSet(e.ctx, feeds.KVLastError, "boom", e.now)
	for i := 0; i < 2; i++ {
		if evs := e.check(); len(evs) != 0 {
			t.Fatalf("check %d alerted early: %v", i, kinds(evs))
		}
	}
	if evs := e.check(); len(evs) != 1 || evs[0].Kind != model.EventFeedStale {
		t.Fatalf("third failing check should alert, got %v", kinds(evs))
	}
}

func TestPipelineErrors(t *testing.T) {
	e := newEnv(t, Options{})
	h := e.host("web1")
	boom := errors.New("no vuln DB")
	e.m.ReportRun(h.ID, boom)
	e.m.ReportRun(h.ID, boom)
	if evs := e.check(); len(evs) != 0 {
		t.Fatalf("two failures alerted: %v", kinds(evs))
	}
	e.m.ReportRun(h.ID, boom)
	evs := e.check()
	if len(evs) != 1 || evs[0].Kind != model.EventPipelineError || !evs[0].ServerLevel() || evs[0].Host.ID != h.ID {
		t.Fatalf("want pipeline_error, got %v", kinds(evs))
	}
	if v, _ := e.st.KVGet(e.ctx, KVPipelineErrors); !strings.Contains(v, "web1") {
		t.Fatalf("banner kv=%q", v)
	}
	// once per host per 24h
	e.m.ReportRun(h.ID, boom)
	e.now = e.now.Add(time.Hour)
	if evs := e.check(); len(evs) != 0 {
		t.Fatalf("repeated within 24h: %v", kinds(evs))
	}
	// success clears the banner
	e.m.ReportRun(h.ID, nil)
	e.check()
	if v, _ := e.st.KVGet(e.ctx, KVPipelineErrors); v != "" {
		t.Fatalf("banner not cleared: %q", v)
	}
	// poison alerts after 24h have passed
	e.now = e.now.Add(25 * time.Hour)
	e.m.ReportPoison(h.ID, "image:latest")
	evs = e.check()
	if len(evs) != 1 || evs[0].Kind != model.EventPipelineError || !strings.Contains(evs[0].Detail, "image:latest") {
		t.Fatalf("want poison pipeline_error, got %v %+v", kinds(evs), evs)
	}
}

func TestFailedDeliveryIsRetried(t *testing.T) {
	e := newEnv(t, Options{AgentSilentAfter: 30 * time.Minute})
	e.checkin(e.host("web1"))
	e.now = e.now.Add(time.Hour)
	e.n.fail = true
	if err := e.m.Check(e.ctx); err == nil {
		t.Fatal("expected delivery error")
	}
	e.n.fail = false
	if evs := e.check(); len(evs) != 1 {
		t.Fatalf("event not retried: %v", kinds(evs))
	}
}

func TestHumanDuration(t *testing.T) {
	for in, want := range map[time.Duration]string{
		30 * time.Second: "30s", 47 * time.Minute: "47m", 3*time.Hour + 5*time.Minute: "3h5m",
		72 * time.Hour: "3d", 50 * time.Hour: "2d2h",
	} {
		if got := HumanDuration(in); got != want {
			t.Errorf("%v: got %s want %s", in, got, want)
		}
	}
}
