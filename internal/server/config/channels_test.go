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

const teamsHook = "https://prod-1.westeurope.logic.azure.com:443/workflows/abc/triggers/manual/paths/invoke?sig=SECRETSECRETSECRET"

func TestTeamsConfig(t *testing.T) {
	cfg, err := loadYAMLEnv(t, `
teams:
  webhooks:
    ops: {url_env: HOLEALIGN_TEAMS_OPS_URL}
    lab: {allow_any_host: true}
notify: {default: ["teams:ops"], ops: ["teams:lab"]}
`, map[string]string{"HOLEALIGN_TEAMS_OPS_URL": teamsHook, "HOLEALIGN_TEAMS_LAB_URL": "https://hooks.example.org/teams"})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Channels()["teams"] || cfg.TeamsURLEnv("lab") != "HOLEALIGN_TEAMS_LAB_URL" {
		t.Error("teams not enabled or env default wrong")
	}
	found := false
	for _, w := range cfg.Warnings() {
		found = found || strings.Contains(w, "teams.webhooks.lab.allow_any_host")
	}
	if !found {
		t.Errorf("no allow_any_host warning: %v", cfg.Warnings())
	}
	// a foreign host is rejected at load unless allow_any_host is set
	_, err = loadYAMLEnv(t, `teams: {webhooks: {ops: {}}}`, map[string]string{"HOLEALIGN_TEAMS_OPS_URL": "https://evil.example/x?sig=SECRETSECRET"})
	if err == nil || !strings.Contains(err.Error(), "teams.webhooks.ops.url_env") || strings.Contains(err.Error(), "SECRETSECRET") {
		t.Errorf("foreign host: %v", err)
	}
	_, err = loadYAMLEnv(t, `teams: {webhooks: {ops: {allow_any_host: true}}}`, map[string]string{"HOLEALIGN_TEAMS_OPS_URL": "http://evil.example/x"})
	if err == nil {
		t.Error("http accepted with allow_any_host")
	}
	for name, y := range map[string]string{
		"not configured": `notify: {default: ["teams:ops"]}`,
		"unknown name":   `teams: {webhooks: {ops: {}}}` + "\n" + `notify: {default: ["teams:x"]}`,
		"bad name":       `teams: {webhooks: {"A B": {}}}`,
		"duplicate env":  `teams: {webhooks: {a: {url_env: HOLEALIGN_X}}}` + "\n" + `discord: {webhooks: {b: {url_env: HOLEALIGN_X}}}`,
		"unknown key":    `teams: {webhooks: {a: {url: "https://x.logic.azure.com/"}}}`,
	} {
		if _, err := loadYAML(t, y); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestWebhookConfig(t *testing.T) {
	cfg, err := loadYAML(t, `
webhook:
  endpoints:
    siem:
      url: https://siem.example.org/holealign
      secret_env: HOLEALIGN_WEBHOOK_SIEM_SECRET
      headers: {Authorization: "Bearer abc"}
    lab: {url: "http://10.0.0.5:8080/hook", allow_http: true}
notify: {default: ["webhook:siem"], ops: ["webhook:lab"]}
`)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Channels()["webhook"] || cfg.WebhookSecretEnv("lab") != "HOLEALIGN_WEBHOOK_LAB_SECRET" {
		t.Error("webhook not enabled or env default wrong")
	}
	found := false
	for _, w := range cfg.Warnings() {
		found = found || strings.Contains(w, "webhook.endpoints.lab.allow_http")
	}
	if !found {
		t.Errorf("no allow_http warning: %v", cfg.Warnings())
	}
	for name, y := range map[string]string{
		"http without allow_http": `webhook: {endpoints: {a: {url: "http://x.example/h"}}}`,
		"no url":                  `webhook: {endpoints: {a: {}}}`,
		"userinfo":                `webhook: {endpoints: {a: {url: "https://u:p@x.example/h"}}}`,
		"bad scheme":              `webhook: {endpoints: {a: {url: "file:///etc/passwd"}}}`,
		"bad name":                `webhook: {endpoints: {"A": {url: "https://x.example/h"}}}`,
		"bad header":              `webhook: {endpoints: {a: {url: "https://x.example/h", headers: {"X-A": "b\nc"}}}}`,
		"reserved header":         `webhook: {endpoints: {a: {url: "https://x.example/h", headers: {"X-Holealign-Signature": "b"}}}}`,
		"secret env not allowed":  `webhook: {endpoints: {a: {url: "https://x.example/h", secret_env: PATH}}}`,
		"same secret env":         `webhook: {endpoints: {a: {url: "https://x.example/h", secret_env: HOLEALIGN_S}, b: {url: "https://y.example/h", secret_env: HOLEALIGN_S}}}`,
		"not configured":          `notify: {default: ["webhook:a"]}`,
		"unknown endpoint":        `webhook: {endpoints: {a: {url: "https://x.example/h"}}}` + "\n" + `notify: {default: ["webhook:b"]}`,
		"url as destination":      `webhook: {endpoints: {a: {url: "https://x.example/h"}}}` + "\n" + `notify: {default: ["webhook:https://x.example/h"]}`,
	} {
		if _, err := loadYAML(t, y); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// the error names the key but not the URL (it may carry a token)
	_, err = loadYAML(t, `webhook: {endpoints: {a: {url: "http://x.example/h?token=TOKENTOKENTOKEN"}}}`)
	if err == nil || !strings.Contains(err.Error(), "webhook.endpoints.a.url") || strings.Contains(err.Error(), "TOKENTOKEN") {
		t.Errorf("error = %v", err)
	}
}

func TestEmailConfig(t *testing.T) {
	cfg, err := loadYAMLEnv(t, `
email:
  smtp:
    host: smtp.example.com
    username: alerts
    from: "Holealign <alerts@example.com>"
  allowed_domains: [example.com, example.org]
notify: {default: ["email:ops@example.com"], routes: [{label: prod, to: ["email:sec@example.org"]}]}
`, map[string]string{"HOLEALIGN_EMAIL_SMTP_PORT": "465", "HOLEALIGN_EMAIL_SMTP_TLS": "implicit"})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Channels()["email"] || cfg.Email.SMTP.Port != 465 || cfg.Email.SMTP.TLS != "implicit" || cfg.Email.SMTP.PasswordEnv != "HOLEALIGN_SMTP_PASSWORD" {
		t.Errorf("email = %+v", cfg.Email)
	}
	// defaults
	cfg, err = loadYAML(t, `email: {smtp: {host: smtp.example.com, from: "a@example.com"}}`)
	if err != nil || cfg.Email.SMTP.Port != 587 || cfg.Email.SMTP.TLS != "starttls" {
		t.Errorf("defaults: %v %+v", err, cfg)
	}
	for name, y := range map[string]string{
		"not configured":    `notify: {default: ["email:ops@example.com"]}`,
		"no from":           `email: {smtp: {host: smtp.example.com}}`,
		"bad from":          `email: {smtp: {host: smtp.example.com, from: "nope"}}`,
		"plain tls":         `email: {smtp: {host: smtp.example.com, from: "a@example.com", tls: none}}`,
		"empty tls":         `email: {smtp: {host: smtp.example.com, from: "a@example.com", tls: ""}}`,
		"bad port":          `email: {smtp: {host: smtp.example.com, from: "a@example.com", port: 0}}`,
		"port too large":    `email: {smtp: {host: smtp.example.com, from: "a@example.com", port: 70000}}`,
		"bad host":          `email: {smtp: {host: "smtp example.com", from: "a@example.com"}}`,
		"password env bad":  `email: {smtp: {host: smtp.example.com, from: "a@example.com", password_env: PATH}}`,
		"password env dup":  `email: {smtp: {host: smtp.example.com, from: "a@example.com", password_env: HOLEALIGN_ADMIN_PASSWORD}}`,
		"domain upper":      `email: {smtp: {host: smtp.example.com, from: "a@example.com"}, allowed_domains: [Example.com]}`,
		"domain bad":        `email: {smtp: {host: smtp.example.com, from: "a@example.com"}, allowed_domains: ["a b"]}`,
		"domain not listed": `email: {smtp: {host: smtp.example.com, from: "a@example.com"}, allowed_domains: [example.com]}` + "\n" + `notify: {default: ["email:ops@evil.example"]}`,
		"subdomain":         `email: {smtp: {host: smtp.example.com, from: "a@example.com"}, allowed_domains: [example.com]}` + "\n" + `notify: {default: ["email:ops@sub.example.com"]}`,
		"display name dest": `email: {smtp: {host: smtp.example.com, from: "a@example.com"}}` + "\n" + `notify: {default: ["email:Ops <ops@example.com>"]}`,
		"settings w/o host": `email: {allowed_domains: [example.com]}`,
	} {
		if _, err := loadYAML(t, y); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	_, err = loadYAML(t, `email: {smtp: {host: smtp.example.com, from: "a@example.com"}, allowed_domains: [example.com]}`+"\n"+`notify: {default: ["email:ops@evil.example"]}`)
	if err == nil || !strings.Contains(err.Error(), "email.allowed_domains") {
		t.Errorf("error should name the key: %v", err)
	}
}
