package config

import (
	"os"
	"path/filepath"
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
	if len(c.Warnings()) != 0 {
		t.Fatalf("defaults warn: %v", c.Warnings())
	}
	c.PublicURL = "http://panoptes.example.com"
	c.Matrix.Homeserver = "http://10.0.0.5:8008"
	c.LLM.BaseURL = "http://127.0.0.1:11434/v1"
	if n := len(c.Warnings()); n != 2 {
		t.Fatalf("warnings=%v", c.Warnings())
	}
}
