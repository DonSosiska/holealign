package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DonSosiska/holealign/internal/model"
)

const (
	testTeamsURL = "https://prod-12.westeurope.logic.azure.com:443/workflows/0123456789abcdef/triggers/manual/paths/invoke?api-version=2016-06-01&sig=SECRETsigSECRETsigSECRET"
	testTeamsSig = "SECRETsigSECRETsigSECRET"
)

func testTeams(t *testing.T, h *hookServer) *Teams {
	t.Helper()
	c, err := NewTeamsChannel(map[string]TeamsHook{"ops": {URL: testTeamsURL}}, h.client)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestTeamsDestinations(t *testing.T) {
	if err := ValidateDestination("teams:ops"); err != nil {
		t.Error(err)
	}
	for _, in := range []string{"teams:", "teams:Ops", "teams:https://x.logic.azure.com/a", "teams:a/b", "teams:a b"} {
		if err := ValidateDestination(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestTeamsURLValidation(t *testing.T) {
	for _, u := range []string{
		testTeamsURL,
		"https://a.environment.api.powerplatform.com/powerautomate/automations/direct/workflows/x/triggers/manual/paths/invoke?sig=s",
		"https://prod-1.westus.logic.azure.com/workflows/x",
		"https://default1234.14.environment.api.powerplatform.com:443/x",
	} {
		if err := ValidTeamsURL(u, false); err != nil {
			t.Errorf("%q: %v", u, err)
		}
	}
	for name, u := range map[string]string{
		"empty":         "",
		"http":          strings.Replace(testTeamsURL, "https", "http", 1),
		"other host":    "https://evil.example/workflows/x?sig=SECRETSECRET",
		"suffix trick":  "https://logic.azure.com.evil.example/x",
		"bare suffix":   "https://logic.azure.com/x",
		"no dot prefix": "https://evillogic.azure.com/x",
		"userinfo":      "https://x.logic.azure.com@evil.example/x",
		"fragment":      testTeamsURL + "#x",
		"scheme":        "ftp://a.logic.azure.com/x",
		"internal":      "https://127.0.0.1/x",
	} {
		err := ValidTeamsURL(u, false)
		if err == nil {
			t.Errorf("%s: %q accepted", name, u)
		} else if strings.Contains(err.Error(), "SECRETSECRET") {
			t.Errorf("%s: error contains the secret: %v", name, err)
		}
	}
	// allow_any_host lifts the host check only, not https or user info
	if err := ValidTeamsURL("https://hooks.example.org/teams?sig=x", true); err != nil {
		t.Error(err)
	}
	if ValidTeamsURL("http://hooks.example.org/x", true) == nil || ValidTeamsURL("https://u:p@hooks.example.org/x", true) == nil {
		t.Error("allow_any_host must still require https without user info")
	}
	if _, err := NewTeamsChannel(map[string]TeamsHook{"ops": {URL: "https://evil.example/x"}}, nil); err == nil {
		t.Error("foreign host accepted by the constructor")
	}
	if _, err := NewTeamsChannel(map[string]TeamsHook{"ops": {URL: "https://evil.example/x", AllowAnyHost: true}}, nil); err != nil {
		t.Error(err)
	}
}

func TestTeamsRequestShape(t *testing.T) {
	h := newHookServer(t, func(_ int, w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusAccepted) })
	n := newNotifier(t, Config{Default: []string{"teams:ops"}}, nil, testTeams(t, h))
	if err := n.Notify(context.Background(), []model.Event{testEvent(model.EventExploitable, "CVE-2024-1", "web01")}); err != nil {
		t.Fatal(err)
	}
	if h.count() != 1 {
		t.Fatalf("requests = %d", h.count())
	}
	r := h.req(0)
	if r.Method != "POST" || !strings.HasPrefix(r.URL, "/workflows/0123456789abcdef/triggers/manual/paths/invoke?api-version=2016-06-01&sig=") {
		t.Errorf("request %s %s", r.Method, r.URL)
	}
	if r.Body["type"] != "message" {
		t.Errorf("type = %v", r.Body["type"])
	}
	att := r.Body["attachments"].([]any)
	if len(att) != 1 {
		t.Fatalf("attachments = %v", att)
	}
	a := att[0].(map[string]any)
	if a["contentType"] != "application/vnd.microsoft.card.adaptive" {
		t.Errorf("contentType = %v", a["contentType"])
	}
	card := a["content"].(map[string]any)
	if card["$schema"] != "http://adaptivecards.io/schemas/adaptive-card.json" || card["type"] != "AdaptiveCard" || card["version"] != "1.4" {
		t.Errorf("card = %v", card)
	}
	body := card["body"].([]any)
	if len(body) < 3 {
		t.Fatalf("body = %v", body)
	}
	first := body[0].(map[string]any)
	if first["type"] != "TextBlock" || first["wrap"] != true || !strings.Contains(first["text"].(string), "EXPLOITABLE") {
		t.Errorf("first block = %v", first)
	}
}

func TestTeamsHostileStringsAreInert(t *testing.T) {
	h := newHookServer(t, func(_ int, w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusAccepted) })
	n := newNotifier(t, Config{Default: []string{"teams:ops"}}, nil, testTeams(t, h))
	if err := n.Notify(context.Background(), []model.Event{hostile()}); err != nil {
		t.Fatal(err)
	}
	card := h.req(0).Body["attachments"].([]any)[0].(map[string]any)["content"].(map[string]any)
	var all strings.Builder
	for _, b := range card["body"].([]any) {
		all.WriteString(b.(map[string]any)["text"].(string) + "\n")
	}
	txt := all.String()
	if m := regexp.MustCompile(`(^|[^\\])[<>]`).FindString(txt); m != "" {
		t.Errorf("unescaped angle bracket %q in:\n%s", m, txt)
	}
	for _, bad := range []string{"@everyone", "@here", "@channel", "](https://evil.example)"} {
		if strings.Contains(txt, bad) {
			t.Errorf("text contains %q:\n%s", bad, txt)
		}
	}
	if !strings.Contains(txt, `\*bold\*`) || !strings.Contains(txt, `\[md\]\(https`) || !strings.Contains(txt, `\<script\>`) {
		t.Errorf("markdown not escaped:\n%s", txt)
	}
	// the only unescaped "](" is our own link construct
	for _, line := range strings.Split(txt, "\n") {
		if i := strings.Index(line, "](http"); i >= 0 && !strings.Contains(line, "[https://holealign.example/") {
			t.Errorf("unexpected link: %s", line)
		}
	}
}

func TestTeamsCardSizeLimit(t *testing.T) {
	var lines []Line
	for i := 0; i < 400; i++ {
		lines = append(lines, Line{txt(strings.Repeat("<*-@&", 200))})
	}
	raw, err := json.Marshal(formatTeams(Message{Lines: lines}))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > teamsMaxCard {
		t.Errorf("card is %d bytes > %d", len(raw), teamsMaxCard)
	}
	if !strings.Contains(string(raw), truncatedNote) {
		t.Error("no truncation note")
	}
	// 10 KB host name end to end
	h := newHookServer(t, func(_ int, w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusAccepted) })
	n := newNotifier(t, Config{Default: []string{"teams:ops"}}, nil, testTeams(t, h))
	if err := n.Notify(context.Background(), []model.Event{testEvent(model.EventExploitable, "CVE-1", strings.Repeat("h<&>", 2500))}); err != nil {
		t.Fatal(err)
	}
	if n := len(h.req(0).Raw); n > teamsMaxCard {
		t.Errorf("request is %d bytes", n)
	}
}

func TestTeamsErrorMapping(t *testing.T) {
	cases := []struct {
		status    int
		permanent bool
		attempts  int
	}{
		{400, true, 1}, {401, true, 1}, {403, true, 1}, {404, true, 1}, {301, true, 1},
		{429, false, maxAttempts}, {502, false, maxAttempts},
	}
	for _, c := range cases {
		h := newHookServer(t, func(_ int, w http.ResponseWriter, r *http.Request) { w.WriteHeader(c.status) })
		pl := &problemLog{}
		n := newNotifier(t, Config{Default: []string{"teams:ops"}, OnDeliveryProblem: pl.add}, nil, testTeams(t, h))
		_ = n.Notify(context.Background(), []model.Event{testEvent(model.EventExploitable, "CVE-1", "h")})
		if h.count() != c.attempts {
			t.Errorf("%d: attempts = %d, want %d", c.status, h.count(), c.attempts)
		}
		ps := pl.all()
		if len(ps) != 1 || ps[0].status != c.status || ps[0].permanent != c.permanent || ps[0].room != "teams:ops" {
			t.Errorf("%d: problems = %+v", c.status, ps)
		}
	}
}

func TestTeams429RetryAfterThenSuccess(t *testing.T) {
	h := newHookServer(t, func(call int, w http.ResponseWriter, r *http.Request) {
		if call == 0 {
			w.Header().Set("Retry-After", "5")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})
	msg := buildGroup([]model.Event{testEvent(model.EventExploitable, "CVE-1", "h")})
	err := testTeams(t, h).Send(context.Background(), "ops", msg)
	var se *SendError
	if !errors.As(err, &se) || se.Status != 429 || se.RetryAfter != 5*time.Second || se.Permanent {
		t.Fatalf("err = %#v", err)
	}
	if err := testTeams(t, h).Send(context.Background(), "ops", msg); err != nil {
		t.Fatalf("202 must be success: %v", err)
	}
}

func TestTeamsURLNeverInErrors(t *testing.T) {
	h := newHookServer(t, func(_ int, w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, "invalid request for "+testTeamsURL+" sig="+testTeamsSig+" /workflows/0123456789abcdef/triggers/manual/paths/invoke")
	})
	err := testTeams(t, h).Send(context.Background(), "ops", Message{Lines: []Line{{txt("x")}}})
	if err == nil || strings.Contains(err.Error(), testTeamsSig) || strings.Contains(err.Error(), "logic.azure.com") {
		t.Errorf("error leaks the URL: %v", err)
	}
	c, _ := NewTeamsChannel(map[string]TeamsHook{"ops": {URL: testTeamsURL}}, &http.Client{Transport: failingTransport{}})
	err = c.Send(context.Background(), "ops", Message{Lines: []Line{{txt("x")}}})
	if err == nil || strings.Contains(err.Error(), testTeamsSig) || strings.Contains(err.Error(), "/workflows/") {
		t.Errorf("network error leaks the URL: %v", err)
	}
}
