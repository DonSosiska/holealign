package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func loadYAML(t *testing.T, yml string) (*Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "s.yaml")
	if err := os.WriteFile(p, []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	return load(p, func(string) (string, bool) { return "", false })
}

func TestNotifySectionMixedDestinations(t *testing.T) {
	cfg, err := loadYAML(t, `
matrix: {homeserver: "https://m.example.org"}
slack: {token_env: HOLEALIGN_SLACK_TOKEN}
telegram: {bot_token_env: HOLEALIGN_TELEGRAM_TOKEN}
notify:
  default: ["!d:x", "slack:C0123456789"]
  ops: ["telegram:-1001234567890/7"]
  routes:
    - {label: prod, to: ["#ops:x", "matrix:!p:x", "slack:G0123456789", "telegram:123456"]}
`)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Deprecated() != "" {
		t.Errorf("deprecation warning without deprecated keys: %v", cfg.Deprecated())
	}
	if len(cfg.Notify.Default) != 2 || len(cfg.Notify.Routes[0].To) != 4 {
		t.Fatalf("notify: %+v warnings %v", cfg.Notify, cfg.Warnings())
	}
}

func TestDeprecatedKeysMergedWithOneWarning(t *testing.T) {
	cfg, err := loadYAML(t, `
matrix:
  homeserver: "https://m.example.org"
  default_rooms: ["!a:x"]
  routes:
    - {label: prod, rooms: ["!p:x"]}
    - {label: web, rooms: ["!w:x"]}
alerts: {ops_rooms: ["!ops:x"]}
slack: {token_env: HOLEALIGN_SLACK_TOKEN}
notify:
  default: ["slack:C0123456789", "!a:x"]
  routes:
    - {label: prod, to: ["slack:C0123456789"]}
`)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cfg.Notify.Default, []string{"slack:C0123456789", "!a:x"}) {
		t.Errorf("default = %v", cfg.Notify.Default)
	}
	if !slices.Equal(cfg.Notify.Ops, []string{"!ops:x"}) {
		t.Errorf("ops = %v", cfg.Notify.Ops)
	}
	if len(cfg.Notify.Routes) != 2 || !slices.Equal(cfg.Notify.Routes[0].To, []string{"slack:C0123456789", "!p:x"}) ||
		cfg.Notify.Routes[1].Label != "web" {
		t.Errorf("routes = %+v", cfg.Notify.Routes)
	}
	dep := cfg.Deprecated()
	if !strings.Contains(dep, "matrix.default_rooms") || !strings.Contains(dep, "alerts.ops_rooms") || !strings.Contains(dep, "matrix.routes") {
		t.Errorf("deprecation warning = %q", dep)
	}
}

func TestNotifyDestinationValidation(t *testing.T) {
	all := `matrix: {homeserver: "https://m.example.org"}
slack: {token_env: HOLEALIGN_SLACK_TOKEN}
telegram: {bot_token_env: HOLEALIGN_TELEGRAM_TOKEN}
`
	bad := map[string]string{
		"unknown scheme":         all + `notify: {default: ["signal:123"]}`,
		"bad slack name":         all + `notify: {default: ["slack:#general"]}`,
		"bad slack lowercase":    all + `notify: {default: ["slack:c0123456789"]}`,
		"bad telegram":           all + `notify: {default: ["telegram:@channel"]}`,
		"telegram bad topic":     all + `notify: {default: ["telegram:-100123/0"]}`,
		"telegram zero chat":     all + `notify: {default: ["telegram:0"]}`,
		"bad matrix":             all + `notify: {ops: ["room:server"]}`,
		"route bad":              all + `notify: {routes: [{label: a, to: ["slack:nope"]}]}`,
		"route empty":            all + `notify: {routes: [{label: a, to: []}]}`,
		"slack not configured":   `matrix: {homeserver: "https://m"}` + "\n" + `notify: {default: ["slack:C0123456789"]}`,
		"tg not configured":      `notify: {default: ["telegram:-100123"]}`,
		"matrix not configured":  `notify: {default: ["!r:x"]}`,
		"old key not configured": `matrix: {default_rooms: ["!r:x"]}`,
		"empty destination":      all + `notify: {default: ["slack:"]}`,
	}
	for name, yml := range bad {
		if _, err := loadYAML(t, yml); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := loadYAML(t, `notify: {default: ["slack:C0123456789"]}`); err == nil || !strings.Contains(err.Error(), "slack.token_env") {
		t.Errorf("unconfigured slack error should name the key: %v", err)
	}
}

func TestSlackTelegramSecretEnvChecks(t *testing.T) {
	for name, yml := range map[string]string{
		"same as matrix":   `matrix: {access_token_env: HOLEALIGN_X}` + "\n" + `slack: {token_env: HOLEALIGN_X}`,
		"slack = telegram": `slack: {token_env: HOLEALIGN_X}` + "\n" + `telegram: {bot_token_env: HOLEALIGN_X}`,
		"telegram = admin": `telegram: {bot_token_env: HOLEALIGN_ADMIN_PASSWORD}`,
		"slack bad name":   `slack: {token_env: HOME}`,
		"telegram bad":     `telegram: {bot_token_env: PATH}`,
	} {
		if _, err := loadYAML(t, yml); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestExampleConfigLoads(t *testing.T) {
	if _, err := load("../../../deploy/server.yaml.example", func(string) (string, bool) { return "", false }); err != nil {
		t.Fatalf("deploy/server.yaml.example: %v", err)
	}
}

func TestRouteJSONReadsOldAndNewKeys(t *testing.T) {
	var rs []NotifyRoute
	if err := json.Unmarshal([]byte(`[{"label":"prod","rooms":["!a:b"]},{"label":"web","to":["slack:C0123456789"]}]`), &rs); err != nil {
		t.Fatal(err)
	}
	if len(rs) != 2 || rs[0].To[0] != "!a:b" || rs[1].To[0] != "slack:C0123456789" {
		t.Fatalf("routes = %+v", rs)
	}
	b, _ := json.Marshal(rs)
	if !strings.Contains(string(b), `"to"`) || strings.Contains(string(b), `"rooms"`) {
		t.Errorf("marshalled = %s", b)
	}
}
