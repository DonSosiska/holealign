package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultsWhenNoFile(t *testing.T) {
	t.Setenv("PANOPTES_CONFIG", "")
	cfg, err := load("", func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":8080" || cfg.Feeds.Interval != 6*time.Hour || !cfg.Feeds.Update {
		t.Fatalf("bad defaults: %+v", cfg)
	}
}

func TestFileAndEnvOverride(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "s.yaml")
	yml := `
listen: ":9000"
data_dir: /tmp/x
feeds: {interval: 1h, update: false}
matrix:
  homeserver: https://m.example.com
  default_rooms: ["!a:x"]
  routes:
    - {label: prod, rooms: ["!p:x"]}
`
	if err := os.WriteFile(p, []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"PANOPTES_MATRIX_HOMESERVER": "https://override",
		"PANOPTES_FEEDS_INTERVAL":    "30m",
		"PANOPTES_LLM_DAILY_LIMIT":   "7",
	}
	cfg, err := load(p, func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":9000" || cfg.Feeds.Update || cfg.Feeds.Interval != 30*time.Minute {
		t.Fatalf("unexpected: %+v", cfg)
	}
	if cfg.Matrix.Homeserver != "https://override" || len(cfg.Matrix.Routes) != 1 || cfg.Matrix.Routes[0].Label != "prod" {
		t.Fatalf("matrix: %+v", cfg.Matrix)
	}
	if cfg.LLM.DailyLimit != 7 || cfg.LLM.Provider != "none" {
		t.Fatalf("llm: %+v", cfg.LLM)
	}
}

func TestExplicitMissingFileFails(t *testing.T) {
	if _, err := load(filepath.Join(t.TempDir(), "nope.yaml"), func(string) (string, bool) { return "", false }); err == nil {
		t.Fatal("expected error")
	}
}

func TestUnknownKeyRejected(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.yaml")
	_ = os.WriteFile(p, []byte("bogus: 1\n"), 0o600)
	if _, err := load(p, func(string) (string, bool) { return "", false }); err == nil {
		t.Fatal("expected error for unknown key")
	}
}

func TestEnvNameValidation(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) string {
		p := filepath.Join(dir, "c.yaml")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	none := func(string) (string, bool) { return "", false }
	for _, bad := range []string{
		"matrix:\n  access_token_env: HOME\n",
		"llm:\n  api_key_env: panoptes_x\n",
		"matrix:\n  access_token_env: PANOPTES_ADMIN_PASSWORD\n",
		"admin:\n  initial_password_env: AWS_SECRET\n",
	} {
		if _, err := load(write(bad), none); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, err := load(write("matrix:\n  access_token_env: PANOPTES_MX_1\n"), none); err != nil {
		t.Fatal(err)
	}
}

func TestWarnings(t *testing.T) {
	c := Default()
	if w := c.Warnings(); len(w) != 1 || !strings.Contains(w[0], "listen :8080") {
		t.Fatalf("defaults should warn only about the cleartext agent listener: %v", w)
	}
	c.TLSCert, c.TLSKey = "c.pem", "k.pem"
	if len(c.Warnings()) != 0 {
		t.Fatalf("warnings with TLS: %v", c.Warnings())
	}
	c.PublicURL = "http://panoptes.example.com"
	c.Matrix.Homeserver = "http://10.0.0.5:8008"
	c.LLM.BaseURL = "http://127.0.0.1:11434/v1"
	if n := len(c.Warnings()); n != 2 {
		t.Fatalf("warnings=%v", c.Warnings())
	}
}

func TestRound2Warnings(t *testing.T) {
	c := Default()
	c.TLSCert, c.TLSKey = "c.pem", "k.pem"
	has := func(sub string) bool {
		for _, w := range c.Warnings() {
			if strings.Contains(w, sub) {
				return true
			}
		}
		return false
	}
	c.TrustedProxies = []string{"10.0.0.0/8"}
	if !has("very broad") {
		t.Error("no warning for /8 trusted proxy")
	}
	c.TrustedProxies = []string{"::/0"}
	if !has("spoof") {
		t.Error("no warning for ::/0")
	}
	c.TrustedProxies = []string{"2001:db8::/32"}
	if !has("very broad") {
		t.Error("no warning for /32 v6")
	}
	c.TrustedProxies = []string{"10.1.0.0/16", "192.168.1.5", "2001:db8::/48"}
	if has("broad") || has("spoof") {
		t.Errorf("narrow proxies warned: %v", c.Warnings())
	}
	c.TrustedProxies = nil
	c.AdminListen = "0.0.0.0:8081"
	if !has("admin_listen") {
		t.Error("no warning for non-loopback admin without TLS")
	}
	c.AdminTLSCert, c.AdminTLSKey = "a", "b"
	if has("admin_listen") {
		t.Error("warned despite admin TLS")
	}
	c.AdminListen = "127.0.0.1:8081"
	c.AdminTLSCert, c.AdminTLSKey = "", ""
	if has("admin_listen") {
		t.Error("warned for loopback admin")
	}
}

func TestSecretEnvNamesPairwiseDifferent(t *testing.T) {
	none := func(string) (string, bool) { return "", false }
	p := filepath.Join(t.TempDir(), "c.yaml")
	_ = os.WriteFile(p, []byte("matrix:\n  access_token_env: PANOPTES_SAME\nllm:\n  api_key_env: PANOPTES_SAME\n"), 0o600)
	if _, err := load(p, none); err == nil {
		t.Fatal("matrix and llm env names may not be equal")
	}
}

func TestRetentionAndLimits(t *testing.T) {
	none := func(string) (string, bool) { return "", false }
	c, err := load("", none)
	if err != nil {
		t.Fatal(err)
	}
	if c.Retention.ResolvedFindings.Std() != 30*24*time.Hour || c.Retention.Notifications.Std() != 90*24*time.Hour ||
		c.Limits.FindingsPerHost != 20000 || c.Limits.MatchSecondsPerHostHour != 900 {
		t.Fatalf("defaults: %+v %+v", c.Retention, c.Limits)
	}
	p := filepath.Join(t.TempDir(), "c.yaml")
	_ = os.WriteFile(p, []byte("retention:\n  resolved_findings: 7d\n  notifications: 0\nlimits:\n  findings_per_host: 5\n"), 0o600)
	c, err = load(p, func(k string) (string, bool) {
		if k == "PANOPTES_LIMITS_MATCH_SECONDS_PER_HOST_HOUR" {
			return "12", true
		}
		return "", false
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.Retention.ResolvedFindings.Std() != 7*24*time.Hour || c.Retention.Notifications != 0 || c.Limits.FindingsPerHost != 5 || c.Limits.MatchSecondsPerHostHour != 12 {
		t.Fatalf("parsed: %+v %+v", c.Retention, c.Limits)
	}
	_ = os.WriteFile(p, []byte("limits:\n  findings_per_host: -1\n"), 0o600)
	if _, err := load(p, none); err == nil {
		t.Fatal("negative limit accepted")
	}
}
