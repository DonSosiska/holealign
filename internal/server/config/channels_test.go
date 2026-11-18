package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadYAMLEnv(t *testing.T, yml string, env map[string]string) (*Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "s.yaml")
	if err := os.WriteFile(p, []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	return load(p, func(k string) (string, bool) { v, ok := env[k]; return v, ok })
}

const discordHook = "https://discord.com/api/webhooks/" + "1234567890123456/AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"

func TestDiscordConfig(t *testing.T) {
	cfg, err := loadYAMLEnv(t, `
discord:
  webhooks:
    ops: {url_env: HOLEALIGN_DISCORD_OPS_URL}
    prod-eu: {}
notify:
  default: ["discord:ops"]
  routes: [{label: prod, to: ["discord:prod-eu"]}]
`, map[string]string{"HOLEALIGN_DISCORD_OPS_URL": discordHook})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Channels()["discord"] {
		t.Error("discord not enabled")
	}
	if got := cfg.DiscordURLEnv("prod-eu"); got != "HOLEALIGN_DISCORD_PROD_EU_URL" {
		t.Errorf("default env = %s", got)
	}
	bad := map[string]string{
		"unknown name":     `discord: {webhooks: {ops: {}}}` + "\n" + `notify: {default: ["discord:other"]}`,
		"not configured":   `notify: {default: ["discord:ops"]}`,
		"bad name":         `discord: {webhooks: {"Ops Room": {}}}`,
		"bad env name":     `discord: {webhooks: {ops: {url_env: PATH}}}`,
		"same env twice":   `discord: {webhooks: {a: {url_env: HOLEALIGN_X}, b: {url_env: HOLEALIGN_X}}}`,
		"reuses admin env": `discord: {webhooks: {a: {url_env: HOLEALIGN_ADMIN_PASSWORD}}}`,
		"url in dest":      `discord: {webhooks: {ops: {}}}` + "\n" + `notify: {default: ["discord:https://discord.com/api/webhooks/1/x"]}`,
		"unknown key":      `discord: {webhooks: {ops: {url: "https://discord.com/api/webhooks/1/x"}}}`,
	}
	for name, y := range bad {
		if _, err := loadYAML(t, y); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// a malformed URL in the environment is rejected at load, naming the key but not the URL
	_, err = loadYAMLEnv(t, `discord: {webhooks: {ops: {}}}`, map[string]string{"HOLEALIGN_DISCORD_OPS_URL": "https://evil.example/api/webhooks/123456/SECRETSECRETSECRETSECRET"})
	if err == nil || !strings.Contains(err.Error(), "discord.webhooks.ops.url_env") || strings.Contains(err.Error(), "SECRETSECRET") {
		t.Errorf("env URL error = %v", err)
	}
	_, err = loadYAML(t, `notify: {default: ["discord:ops"]}`)
	if err == nil || !strings.Contains(err.Error(), "discord.webhooks") {
		t.Errorf("hint = %v", err)
	}
}
