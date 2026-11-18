package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DonSosiska/holealign/internal/model"
)

type problem struct {
	room      string
	status    int
	kind      model.EventKind
	permanent bool
}

type problemLog struct {
	mu sync.Mutex
	ps []problem
}

func (p *problemLog) add(room string, status int, kind model.EventKind, permanent bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ps = append(p.ps, problem{room, status, kind, permanent})
}

func (p *problemLog) all() []problem {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]problem(nil), p.ps...)
}

func TestPermanent403OnCriticalKindsIsFailedAndReported(t *testing.T) {
	for _, kind := range []model.EventKind{model.EventExploitable, model.EventUnknownCritical} {
		hs := newFakeHS(t, func(int, recorded) (int, string) { return http.StatusForbidden, `{"errcode":"M_FORBIDDEN"}` })
		pl := &problemLog{}
		m := newTestMatrix(t, hs, Config{Default: []string{"!r:example.org"}, OnDeliveryProblem: pl.add}, nil)
		err := m.Notify(context.Background(), []model.Event{testEvent(kind, "CVE-1", "h")})
		var de *DeliveryError
		if !errors.As(err, &de) || len(de.Failed) != 1 || de.Failed[0] != 0 {
			t.Fatalf("%s: err = %v, want event 0 reported failed", kind, err)
		}
		if n := len(hs.requests()); n != 1 {
			t.Errorf("%s: requests = %d, a permanent error must not be retried within a run", kind, n)
		}
		ps := pl.all()
		if len(ps) != 1 || ps[0].room != "!r:example.org" || ps[0].status != 403 || ps[0].kind != kind || !ps[0].permanent {
			t.Errorf("%s: problems = %+v", kind, ps)
		}
	}
	// health kinds agent_silent and feed_stale are critical as well
	for _, ev := range []model.Event{
		{Kind: model.EventAgentSilent, Host: model.Host{ID: "h1", Hostname: "h1"}, Detail: "x"},
		{Kind: model.EventFeedStale, Detail: "stale"},
	} {
		hs := newFakeHS(t, func(int, recorded) (int, string) { return http.StatusForbidden, `{}` })
		m := newTestMatrix(t, hs, Config{Default: []string{"!r:example.org"}}, nil)
		var de *DeliveryError
		if err := m.Notify(context.Background(), []model.Event{ev}); !errors.As(err, &de) || len(de.Failed) != 1 {
			t.Errorf("%s: err = %v", ev.Kind, err)
		}
	}
	// non-critical kinds keep the old behaviour (reported, not retried) but are still surfaced
	hs := newFakeHS(t, func(int, recorded) (int, string) { return http.StatusForbidden, `{}` })
	pl := &problemLog{}
	m := newTestMatrix(t, hs, Config{Default: []string{"!r:example.org"}, OnDeliveryProblem: pl.add}, nil)
	var de *DeliveryError
	if err := m.Notify(context.Background(), []model.Event{testEvent(model.EventResolved, "CVE-1", "h")}); !errors.As(err, &de) || len(de.Failed) != 0 {
		t.Fatalf("resolved: %v", err)
	}
	if len(pl.all()) != 1 {
		t.Errorf("resolved problem not surfaced: %+v", pl.all())
	}
}

func TestProblemsReportedOncePerRoomStatusPer10Minutes(t *testing.T) {
	hs := newFakeHS(t, func(int, recorded) (int, string) { return http.StatusForbidden, `{}` })
	pl := &problemLog{}
	m := newTestMatrix(t, hs, Config{Default: []string{"!r:example.org", "!q:example.org"}, OnDeliveryProblem: pl.add}, nil)
	now := time.Now()
	m.now = func() time.Time { return now }
	ev := testEvent(model.EventExploitable, "CVE-1", "h")
	for i := 0; i < 5; i++ {
		_ = m.Notify(context.Background(), []model.Event{ev})
	}
	if n := len(pl.all()); n != 2 { // one per room
		t.Fatalf("callbacks = %d, want 2 (rate limited per room+status)", n)
	}
	now = now.Add(problemEvery + time.Second)
	_ = m.Notify(context.Background(), []model.Event{ev})
	if n := len(pl.all()); n != 4 {
		t.Fatalf("callbacks after 10 min = %d, want 4", n)
	}
}

func TestRetryDoesNotRepostToRoomsThatWereReached(t *testing.T) {
	hs := newFakeHS(t, func(_ int, rec recorded) (int, string) {
		if rec.room == "!bad:example.org" {
			return http.StatusForbidden, `{}`
		}
		return http.StatusOK, `{"event_id":"$x"}`
	})
	m := newTestMatrix(t, hs, Config{Default: []string{"!good:example.org", "!bad:example.org"}}, nil)
	ev := testEvent(model.EventExploitable, "CVE-1", "h")
	for i := 0; i < 3; i++ {
		var de *DeliveryError
		if err := m.Notify(context.Background(), []model.Event{ev}); !errors.As(err, &de) || len(de.Failed) != 1 {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	if n := hs.roomCounts()["!good:example.org"]; n != 1 {
		t.Fatalf("the reachable room got %d copies, want 1", n)
	}
	if n := hs.roomCounts()["!bad:example.org"]; n != 3 {
		t.Fatalf("the failing room was tried %d times, want 3", n)
	}
}

func TestMessageHasEmptyMentions(t *testing.T) {
	hs := newFakeHS(t, nil)
	m := newTestMatrix(t, hs, Config{Default: []string{"!r:example.org"}}, nil)
	var evs []model.Event
	evs = append(evs, testEvent(model.EventExploitable, "CVE-1", "h"))
	for i := 0; i < 30; i++ { // enough for a burst summary as well
		evs = append(evs, testEvent(model.EventExploitable, fmt.Sprintf("CVE-9-%d", i), "h"))
	}
	if err := m.Notify(context.Background(), evs); err != nil {
		t.Fatal(err)
	}
	if len(hs.requests()) < 2 {
		t.Fatal("expected individual messages and a summary")
	}
	b, _ := json.Marshal(message{MsgType: "m.text"})
	if !strings.Contains(string(b), `"m.mentions":{}`) {
		t.Fatalf("message JSON: %s", b)
	}
	for _, r := range hs.requests() {
		raw, _ := json.Marshal(r.body)
		if !strings.Contains(string(raw), `"m.mentions":{}`) {
			t.Fatalf("message without m.mentions: %s", raw)
		}
	}
}

func TestAtRoomNeutralised(t *testing.T) {
	ev := fullExploitable()
	ev.Host.Hostname = "@room-host"
	ev.Finding.VerdictReason = "ping @room and @ROOM and user@example.com"
	ev.Detail = "hello @room"
	plain, h := renderEvent(ev)
	for _, s := range []string{plain, h} {
		if strings.Contains(strings.ToLower(s), "@room") {
			t.Fatalf("literal @room survived: %q", s)
		}
		if !strings.Contains(s, "@\u200broom") {
			t.Fatalf("no zero-width space after @: %q", s)
		}
	}
	if !strings.Contains(plain, "user@\u200bexample.com") {
		t.Fatalf("plain: %q", plain)
	}
	// the server-built fix command stays copy-pasteable except for @room
	ev.FixCmd = "npm install lodash@4.17.21 @room"
	p2, _ := renderEvent(ev)
	if !strings.Contains(p2, "npm install lodash@4.17.21 @\u200broom") {
		t.Fatalf("fix command: %q", p2)
	}
}

func TestGroupAndFixedVersionCaps(t *testing.T) {
	var evs []model.Event
	for i := 0; i < 120; i++ {
		ev := fullExploitable()
		ev.Finding.PackageName = fmt.Sprintf("pkg%03d", i)
		for v := 0; v < 40; v++ {
			ev.Finding.FixedVersions = append(ev.Finding.FixedVersions, fmt.Sprintf("1.%d.%d", i, v))
		}
		evs = append(evs, ev)
	}
	plain, h := renderGroup(evs)
	if strings.Contains(plain, "pkg050") || !strings.Contains(plain, "pkg049") && !strings.Contains(plain, "and") {
		t.Fatalf("group not capped at %d events:\n%s", maxGroupEvents, plain)
	}
	if !strings.Contains(plain, "70 more events") {
		t.Errorf("no count of unlisted events:\n%s", plain)
	}
	if len(plain) > maxBodyBytes || len(h) > maxBodyBytes {
		t.Fatalf("bodies %d/%d", len(plain), len(h))
	}
	one := fullExploitable()
	one.Finding.FixedVersions = nil
	for v := 0; v < 12; v++ {
		one.Finding.FixedVersions = append(one.Finding.FixedVersions, fmt.Sprintf("2.0.%d", v))
	}
	p, _ := renderGroup([]model.Event{one})
	if !strings.Contains(p, "2.0.4") || strings.Contains(p, "2.0.5") || !strings.Contains(p, "+7 more") {
		t.Errorf("fixed versions not capped to %d:\n%s", maxFixedVersions, p)
	}
}

func TestBodyCapAfterEscapingIncludingFallback(t *testing.T) {
	// one huge line full of characters that expand when escaped
	ev := fullExploitable()
	ev.Finding.PackageName = strings.Repeat(`"<&>'`, 60)
	var many []model.Event
	for i := 0; i < 50; i++ {
		e := ev
		e.Finding.PackageVer = strings.Repeat(`"<&>`, 70) + fmt.Sprint(i)
		many = append(many, e)
	}
	plain, h := renderGroup(many)
	if len(plain) > maxBodyBytes || len(h) > maxBodyBytes {
		t.Fatalf("bodies %d/%d exceed the cap after escaping", len(plain), len(h))
	}
	// fallback path: a single line that alone does not fit
	p, f := formatMatrix(Message{Lines: []Line{{txt(strings.Repeat(`"`, 20000))}}})
	if len(p) > maxBodyBytes || len(f) > maxBodyBytes {
		t.Fatalf("fallback bodies %d/%d", len(p), len(f))
	}
	if !strings.Contains(p, "truncated") || !strings.Contains(f, "truncated") {
		t.Fatal("no truncation note")
	}
	// distinct keeps order and drops empties
	if got := distinct([]string{"b", "", "a", "b", "a", "c"}); strings.Join(got, "") != "bac" {
		t.Fatalf("distinct = %v", got)
	}
}
