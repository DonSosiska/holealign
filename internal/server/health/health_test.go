package health

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DonSosiska/panoptes/internal/model"
	"github.com/DonSosiska/panoptes/internal/server/feeds"
	"github.com/DonSosiska/panoptes/internal/server/notify"
	"github.com/DonSosiska/panoptes/internal/server/store"
)

type fakeNotifier struct {
	mu     sync.Mutex
	events []model.Event
	fail   bool
	// failFn, when set, fails exactly the events it returns true for (the others are delivered).
	failFn func(model.Event) bool
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
	if f.failFn != nil {
		var de *notify.DeliveryError
		for i, ev := range evs {
			if f.failFn(ev) {
				if de == nil {
					de = &notify.DeliveryError{Err: errors.New("room refused")}
				}
				de.Failed = append(de.Failed, i)
				continue
			}
			f.events = append(f.events, ev)
		}
		if de != nil {
			return de
		}
		return nil
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
	if len(evs) != 2 { // the ops overview and the message for label prod
		t.Fatalf("want an aggregated ops event plus one for the label, got %d: %s", len(evs), kinds(evs))
	}
	ev := evs[0]
	if ev.Kind != model.EventAgentSilent || ev.Host.ID != "" || !ev.ServerLevel() {
		t.Fatalf("not an aggregated server-level event: %+v", ev)
	}
	if !strings.HasPrefix(ev.Detail, "30 agents silent — server/network problem?") {
		t.Fatalf("detail=%q", ev.Detail)
	}
	if got := strings.Count(ev.Detail, "• "); got != 30 {
		t.Fatalf("listed %d hostnames: %q", got, ev.Detail)
	}
	if lab := evs[1]; lab.ServerLevel() || len(lab.Host.Labels) != 1 || lab.Host.Labels[0] != "prod" {
		t.Fatalf("label event: %+v", lab)
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
	if len(evs) != 2 || evs[0].Kind != model.EventAgentBack || evs[0].Host.ID != "" || evs[1].Kind != model.EventAgentBack {
		t.Fatalf("want an aggregated agent_back plus the label's, got %v", kinds(evs))
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

// --- round 2 -------------------------------------------------------------------------------------

func (e *env) massSilence(n int, label func(i int) []string) []model.Host {
	e.t.Helper()
	var hs []model.Host
	for i := 0; i < n; i++ {
		h := e.host(fmt.Sprintf("h%03d", i), label(i)...)
		hs = append(hs, h)
	}
	return hs
}

func (e *env) checkinAt(h model.Host, at time.Time) {
	e.t.Helper()
	if _, err := e.st.ApplyCheckin(e.ctx, h.ID, model.CheckinRequest{Hostname: h.Hostname, Labels: h.Labels, FactsComplete: true}, at); err != nil {
		e.t.Fatal(err)
	}
}

func TestMassSilenceStillReachesTheVictimsLabelRoom(t *testing.T) {
	e := newEnv(t, Options{AgentSilentAfter: 30 * time.Minute, PublicURL: "https://p.example"})
	var victim model.Host
	hs := e.massSilence(20, func(i int) []string {
		if i == 0 {
			return []string{"pci"}
		}
		if i < 14 {
			return []string{"web"}
		}
		return []string{"web", "healthy"}
	})
	victim = hs[0]
	for i, h := range hs {
		if i < 14 {
			e.checkinAt(h, e.now.Add(-time.Duration(i)*time.Minute))
		}
	}
	e.now = e.now.Add(time.Hour)
	for _, h := range hs[14:] { // healthy hosts keep checking in
		e.checkinAt(h, e.now)
	}
	evs := e.check()
	var ops, pci, web *model.Event
	for i := range evs {
		switch {
		case evs[i].ServerLevel():
			ops = &evs[i]
		case len(evs[i].Host.Labels) == 1 && evs[i].Host.Labels[0] == "pci":
			pci = &evs[i]
		case len(evs[i].Host.Labels) == 1 && evs[i].Host.Labels[0] == "web":
			web = &evs[i]
		}
	}
	if ops == nil || pci == nil || web == nil || len(evs) != 3 {
		t.Fatalf("want ops + pci + web events, got %d", len(evs))
	}
	if !strings.Contains(pci.Detail, victim.Hostname) || !strings.Contains(pci.Detail, victim.ID) {
		t.Fatalf("victim not named (with its ID) in the pci message: %q", pci.Detail)
	}
	if strings.Contains(web.Detail, victim.Hostname) {
		t.Fatalf("host listed under a label it does not carry: %q", web.Detail)
	}
	if !strings.Contains(ops.Detail, "14 agents silent") || ops.WebURL != "https://p.example/hosts" {
		t.Fatalf("ops: %q url=%q", ops.Detail, ops.WebURL)
	}
	if sent, _ := e.st.NotificationSent(e.ctx, hostDedupKey(victim.ID, model.EventAgentSilent)); !sent {
		t.Fatal("victim not recorded although named in delivered messages")
	}
	if evs := e.check(); len(evs) != 0 {
		t.Fatalf("repeated: %s", kinds(evs))
	}
}

func TestMassSilenceListsNewestFirstAndRecordsOnlyNamedHosts(t *testing.T) {
	e := newEnv(t, Options{AgentSilentAfter: 30 * time.Minute})
	hs := e.massSilence(120, func(int) []string { return []string{"prod"} })
	for i, h := range hs { // the higher the number, the more recent the last check-in
		e.checkinAt(h, e.now.Add(-time.Duration(200-i)*time.Second))
	}
	e.now = e.now.Add(time.Hour)
	e.n.failFn = func(ev model.Event) bool { return ev.ServerLevel() } // the ops room refuses
	if err := e.m.Check(e.ctx); err == nil {
		t.Fatal("a failed ops message must surface as an error")
	}
	evs := e.n.take()
	if len(evs) != 1 || evs[0].ServerLevel() {
		t.Fatalf("delivered: %s", kinds(evs))
	}
	lab := evs[0]
	if strings.Count(lab.Detail, "• ") != maxSilentListed || !strings.Contains(lab.Detail, "…and 70 more") {
		t.Fatalf("label message lists %d hosts: %.300q", strings.Count(lab.Detail, "• "), lab.Detail)
	}
	// newest check-in first, not by name: h119 leads, h000 is not listed
	if i, j := strings.Index(lab.Detail, "h119"), strings.Index(lab.Detail, "h118"); i < 0 || j < 0 || i > j {
		t.Fatalf("not newest first: %.300q", lab.Detail)
	}
	if strings.Contains(lab.Detail, "h000") {
		t.Fatal("oldest host listed")
	}
	recorded := 0
	for _, h := range hs {
		if sent, _ := e.st.NotificationSent(e.ctx, hostDedupKey(h.ID, model.EventAgentSilent)); sent {
			recorded++
		}
	}
	if recorded != maxSilentListed {
		t.Fatalf("recorded %d hosts, want exactly the %d named in delivered messages", recorded, maxSilentListed)
	}
	// nothing delivered at all: nothing recorded
	e2 := newEnv(t, Options{AgentSilentAfter: 30 * time.Minute})
	hs2 := e2.massSilence(20, func(int) []string { return []string{"a"} })
	for _, h := range hs2 {
		e2.checkinAt(h, e2.now)
	}
	e2.now = e2.now.Add(time.Hour)
	e2.n.fail = true
	_ = e2.m.Check(e2.ctx)
	for _, h := range hs2 {
		if sent, _ := e2.st.NotificationSent(e2.ctx, hostDedupKey(h.ID, model.EventAgentSilent)); sent {
			t.Fatal("host recorded without any delivered message")
		}
	}
	// the remaining 70 are announced on the next pass
	e.n.failFn = nil
	evs = e.check()
	if len(evs) == 0 {
		t.Fatal("hosts that were not named are never announced")
	}
	if !strings.Contains(evs[0].Detail, "70 agents silent") {
		t.Fatalf("follow-up: %.200q", evs[0].Detail)
	}
}

func TestUnlabelledHostsAreNotLost(t *testing.T) {
	e := newEnv(t, Options{AgentSilentAfter: 30 * time.Minute})
	hs := e.massSilence(10, func(int) []string { return nil })
	for _, h := range hs {
		e.checkinAt(h, e.now)
	}
	e.now = e.now.Add(time.Hour)
	evs := e.check()
	if len(evs) != 2 {
		t.Fatalf("want ops + unlabelled group, got %s", kinds(evs))
	}
	if g := evs[1]; g.ServerLevel() || len(g.Host.Labels) != 0 || !strings.Contains(g.Detail, "h000") {
		t.Fatalf("group event: %+v", g)
	}
}

func TestPipelineDetailIsOneLineAndDeletedHostsForgotten(t *testing.T) {
	e := newEnv(t, Options{})
	h := e.host("web1")
	boom := errors.New("grype failed\nsecond line \x1b[31m@room " + strings.Repeat("x", 1000))
	for i := 0; i < 3; i++ {
		e.m.ReportRun(h.ID, boom)
	}
	evs := e.check()
	if len(evs) != 1 {
		t.Fatalf("want one pipeline_error, got %d", len(evs))
	}
	if strings.ContainsAny(evs[0].Detail, "\n\x1b") || len([]rune(evs[0].Detail)) > 500 {
		t.Fatalf("detail not cleaned: %q", evs[0].Detail)
	}

	// a deleted host disappears from the in-memory state
	h2 := e.host("web2")
	e.m.ReportRun(h2.ID, boom)
	e.m.ReportPoison(h2.ID, "image:x")
	if err := e.st.DeleteHost(e.ctx, h2.ID); err != nil {
		t.Fatal(err)
	}
	e.check()
	e.m.mu.Lock()
	_, a := e.m.failures[h2.ID]
	_, b := e.m.poisoned[h2.ID]
	_, c := e.m.pending[h2.ID]
	e.m.mu.Unlock()
	if a || b || c {
		t.Fatalf("state of the deleted host kept: %v %v %v", a, b, c)
	}
	e.m.ReportRun(h.ID, boom)
	e.m.ForgetHost(h.ID)
	e.m.mu.Lock()
	n := len(e.m.failures) + len(e.m.lastErr) + len(e.m.poisoned) + len(e.m.pending)
	e.m.mu.Unlock()
	if n != 0 {
		t.Fatalf("ForgetHost left %d entries", n)
	}
}

func TestNotifyProblemRecorder(t *testing.T) {
	e := newEnv(t, Options{})
	rec := NewProblemRecorder(e.st, nil)
	rec("!r:s\n<b>", 403, model.EventExploitable, true)
	rec("!r:s\n<b>", 403, model.EventExploitable, true) // same problem: one entry
	for i := 0; i < 30; i++ {
		rec(fmt.Sprintf("!room%d:s", i), 403, model.EventAgentSilent, true)
	}
	raw, err := e.st.KVGet(e.ctx, KVNotifyErrors)
	if err != nil {
		t.Fatal(err)
	}
	var ps []NotifyProblem
	if err := json.Unmarshal([]byte(raw), &ps); err != nil || len(ps) != maxNotifyProblems {
		t.Fatalf("stored %d problems (%v)", len(ps), err)
	}
	if ps[len(ps)-1].Room != "!room29:s" || strings.Contains(raw, "\\n") {
		t.Fatalf("newest last, values cleaned: %s", raw)
	}
}

// End to end through the real Matrix notifier: the victim is named in the room routed for its label.
func TestMassSilenceVictimNamedInLabelRoomViaMatrix(t *testing.T) {
	var mu sync.Mutex
	got := map[string][]string{} // room -> bodies
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Body string `json:"body"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		parts := strings.Split(r.URL.EscapedPath(), "/")
		room, _ := url.PathUnescape(parts[5])
		mu.Lock()
		got[room] = append(got[room], body.Body)
		mu.Unlock()
		_, _ = w.Write([]byte(`{"event_id":"$x"}`))
	}))
	defer srv.Close()
	mx, err := notify.NewMatrix(notify.Config{Homeserver: srv.URL, AccessToken: "t", OpsRooms: []string{"!ops:x"},
		DefaultRooms: []string{"!def:x"}, Routes: []notify.Route{{Label: "pci", Rooms: []string{"!pci:x"}}, {Label: "web", Rooms: []string{"!web:x"}}}}, nil, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, Options{AgentSilentAfter: 30 * time.Minute})
	e.m.n = mx
	hs := e.massSilence(20, func(i int) []string {
		if i == 0 {
			return []string{"pci"}
		}
		return []string{"web"}
	})
	for _, h := range hs {
		e.checkinAt(h, e.now)
	}
	e.now = e.now.Add(time.Hour)
	if err := e.m.Check(e.ctx); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got["!pci:x"]) != 1 || !strings.Contains(got["!pci:x"][0], "h000") || !strings.Contains(got["!pci:x"][0], hs[0].ID) {
		t.Fatalf("pci room: %q", got["!pci:x"])
	}
	if len(got["!ops:x"]) != 1 || !strings.Contains(got["!ops:x"][0], "20 agents silent") {
		t.Fatalf("ops room: %q", got["!ops:x"])
	}
	if len(got["!web:x"]) != 1 || strings.Contains(got["!web:x"][0], "h000") {
		t.Fatalf("web room: %q", got["!web:x"])
	}
}

func TestProblemWordingAndCleanClearsBanner(t *testing.T) {
	e := newEnv(t, Options{AgentSilentAfter: time.Hour})
	h := e.host("web1")
	e.m.ReportProblem(h.ID, "host", "matching failed: boom")
	evs := e.check()
	if len(evs) != 1 || strings.Contains(evs[0].Detail, "crashed") || !strings.Contains(evs[0].Detail, "matching failed: boom") {
		t.Fatalf("problem event: %+v", evs)
	}
	if v, _ := e.st.KVGet(e.ctx, KVPipelineErrors); !strings.Contains(v, "web1") || strings.Contains(v, "crashed") {
		t.Fatalf("banner=%q", v)
	}
	e.m.ReportClean(h.ID)
	e.check()
	if v, _ := e.st.KVGet(e.ctx, KVPipelineErrors); v != "" {
		t.Fatalf("banner not cleared by a clean run: %q", v)
	}

	// a panic keeps the "crashed" wording
	e.m.ReportPoison(h.ID, "image:x")
	e.check()
	if v, _ := e.st.KVGet(e.ctx, KVPipelineErrors); !strings.Contains(v, "crashed") {
		t.Fatalf("banner=%q", v)
	}
	e.m.ReportClean(h.ID)
	e.check()
	if v, _ := e.st.KVGet(e.ctx, KVPipelineErrors); v != "" {
		t.Fatalf("poison banner not cleared: %q", v)
	}
}
