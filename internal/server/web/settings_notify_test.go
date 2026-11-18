package web

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestRoutesUnconfiguredChannelShownInForm(t *testing.T) {
	e := newEnv(t, true)
	e.srv.cfg.Slack.TokenEnv = "" // slack is not configured on this server
	c := e.session("admin")
	w := e.post("/settings/matrix", url.Values{"routes": {"prod = !a:b, slack:C0123456789"}}, c)
	if w.Code != 422 {
		t.Fatalf("code = %d, want 422", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "slack channel, which is not configured") || !strings.Contains(body, "slack.token_env") {
		t.Errorf("error not shown in the form: %s", body)
	}
	if !strings.Contains(body, "prod = !a:b, slack:C0123456789") {
		t.Error("the typed text must stay in the form")
	}
	if _, err := e.st.GetSetting(context.Background(), matrixSettingKey); err == nil {
		t.Fatal("rejected routes were stored")
	}
}

func TestRoutesUnknownSchemeError(t *testing.T) {
	e := newEnv(t, true)
	c := e.session("admin")
	w := e.post("/settings/matrix", url.Values{"routes": {"prod = webhook:https://evil.example/x"}}, c)
	if w.Code != 422 || !strings.Contains(w.Body.String(), "unknown scheme") {
		t.Fatalf("code %d body %s", w.Code, w.Body.String())
	}
}

// Rows stored before notifier channels existed use the key "rooms"; they must still load and show.
func TestLegacyStoredRoutesStillLoad(t *testing.T) {
	e := newEnv(t, true)
	c := e.session("admin")
	if err := e.st.SetSetting(context.Background(), matrixSettingKey,
		[]byte(`[{"label":"prod","rooms":["!x:y","!z:y"]},{"label":"dev","to":["slack:C0123456789"]}]`), time.Now()); err != nil {
		t.Fatal(err)
	}
	b := e.do("GET", "/settings", nil, c).Body.String()
	if !strings.Contains(b, "prod = !x:y, !z:y") || !strings.Contains(b, "dev = slack:C0123456789") {
		t.Errorf("stored routes not shown: %s", b)
	}
	// saving rewrites in the new format
	if w := e.post("/settings/matrix", url.Values{"routes": {"prod = !x:y, !z:y"}}, c); w.Code != 303 {
		t.Fatalf("save: %d", w.Code)
	}
	raw, _ := e.st.GetSetting(context.Background(), matrixSettingKey)
	if !strings.Contains(string(raw), `"to"`) || strings.Contains(string(raw), `"rooms"`) {
		t.Errorf("stored = %s", raw)
	}
}
