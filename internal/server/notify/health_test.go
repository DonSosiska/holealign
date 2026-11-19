package notify

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/DonSosiska/holealign/internal/model"
)

func hostEv(kind model.EventKind, name, id string, labels []string, detail string) model.Event {
	return model.Event{Kind: kind, Detail: detail, Host: model.Host{ID: id, Hostname: name, Labels: labels,
		LastCheckin: time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)}}
}

func TestRenderHealthKinds(t *testing.T) {
	cases := []struct {
		ev   model.Event
		want string
	}{
		{hostEv(model.EventAgentSilent, "web1", "h1", nil, "no check-in for 47m (last: 2026-05-01 10:00 UTC)"),
			"🔇 AGENT SILENT: web1 — no check-in for 47m (last: 2026-05-01 10:00 UTC)"},
		{hostEv(model.EventAgentBack, "web1", "h1", nil, "checking in again"), "🔊 AGENT BACK: web1 — checking in again"},
		{model.Event{Kind: model.EventFeedStale, Detail: "vulnerability DB last updated 3d ago — boom"},
			"🟣 FEED STALE: vulnerability DB last updated 3d ago — boom"},
		{model.Event{Kind: model.EventFeedOK}, "✅ FEED OK: vulnerability DB is up to date again"},
		{hostEv(model.EventPipelineError, "web1", "h1", nil, "pipeline failed 3 times in a row: x"),
			"⚠️ PIPELINE ERROR: web1 — pipeline failed 3 times in a row: x"},
	}
	for _, c := range cases {
		plain, h := renderGroup([]model.Event{c.ev})
		if plain != c.want {
			t.Errorf("%s: plain=%q want %q", c.ev.Kind, plain, c.want)
		}
		if strings.Contains(h, "<script") {
			t.Errorf("unescaped html: %s", h)
		}
	}
}

func TestRenderHealthEscapesAndTruncates(t *testing.T) {
	ev := hostEv(model.EventAgentSilent, "<img src=x onerror=1>\nevil", "h1", nil, "<b>x</b>\u202e"+strings.Repeat("A", 1000))
	plain, h := renderGroup([]model.Event{ev})
	if strings.Contains(h, "<img") || strings.Contains(h, "<b>x") || strings.Contains(plain, "\u202e") {
		t.Fatalf("not neutralised: %q / %q", plain, h)
	}
	if len([]rune(plain)) > 300+60 {
		t.Fatalf("not truncated: %d runes", len([]rune(plain)))
	}
}

func TestRenderAggregatedSilence(t *testing.T) {
	ev := model.Event{Kind: model.EventAgentSilent, Detail: "12 agents silent — server/network problem?\n• a\n• <b>b"}
	plain, h := renderGroup([]model.Event{ev})
	if !strings.HasPrefix(plain, "🔇 AGENT SILENT: 12 agents silent — server/network problem?\n• a\n") || strings.Contains(h, "<b>b") {
		t.Fatalf("plain=%q html=%q", plain, h)
	}
}

func TestHealthRouting(t *testing.T) {
	hs := newFakeHS(t, nil)
	m := newTestMatrix(t, hs, Config{
		Default: []string{"!def:x"}, Ops: []string{"!ops:x"},
		Routes: []Route{{Label: "prod", To: []string{"!prod:x"}}},
	}, nil)
	evs := []model.Event{
		hostEv(model.EventAgentSilent, "web1", "h1", []string{"prod"}, "d"),
		hostEv(model.EventPipelineError, "web1", "h1", []string{"prod"}, "d"),
		{Kind: model.EventFeedStale, Detail: "d"},
		{Kind: model.EventAgentSilent, Detail: "3 agents silent"},
	}
	if err := m.Notify(context.Background(), evs); err != nil {
		t.Fatal(err)
	}
	got := hs.roomCounts()
	if got["!prod:x"] != 1 || got["!ops:x"] != 3 || got["!def:x"] != 0 {
		t.Fatalf("routing: %v", got)
	}
}

func TestOpsRoomsFallBackToDefault(t *testing.T) {
	hs := newFakeHS(t, nil)
	m := newTestMatrix(t, hs, Config{Default: []string{"!def:x"}}, nil)
	if err := m.Notify(context.Background(), []model.Event{{Kind: model.EventFeedOK}}); err != nil {
		t.Fatal(err)
	}
	if hs.roomCounts()["!def:x"] != 1 {
		t.Fatalf("got %v", hs.roomCounts())
	}
}

func TestHealthEventsNotMergedNorBursted(t *testing.T) {
	hs := newFakeHS(t, nil)
	m := newTestMatrix(t, hs, Config{Default: []string{"!r:x"}}, nil)
	var evs []model.Event
	for i := 0; i < 40; i++ { // enough findings to trigger burst mode
		evs = append(evs, model.Event{Kind: model.EventExploitable, Host: model.Host{ID: "h", Hostname: "h"},
			Finding: model.Finding{VulnID: fmt.Sprintf("CVE-2026-%04d", i), Target: "host", PackageName: "p", CVSS: 9}})
	}
	for i := 0; i < 3; i++ {
		evs = append(evs, hostEv(model.EventAgentSilent, fmt.Sprintf("web%d", i), "same", nil, "d"))
	}
	if err := m.Notify(context.Background(), evs); err != nil {
		t.Fatal(err)
	}
	silent := 0
	for _, r := range hs.requests() {
		if strings.HasPrefix(r.body.Body, "🔇 AGENT SILENT") {
			silent++
		}
		if strings.Contains(r.body.Body, "AGENT SILENT") && strings.Contains(r.body.Body, "CVE-") {
			t.Fatalf("health event merged into a finding message: %q", r.body.Body)
		}
	}
	if silent != 3 {
		t.Fatalf("want 3 separate silent messages, got %d", silent)
	}
}
