package config

import (
	"path/filepath"
	"testing"
	"time"
)

func TestAlertsAndListenerDefaultsAndEnv(t *testing.T) {
	none := func(string) (string, bool) { return "", false }
	if _, err := load(filepath.Join(t.TempDir(), "absent.yaml"), none); err == nil {
		t.Fatal("explicit missing file must fail")
	}
	t.Setenv("HOLEALIGN_CONFIG", "")
	cfg, err := load("", none)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AdminListen != "127.0.0.1:8081" || cfg.PublicURL != "http://localhost:8081" || cfg.SharedListener() {
		t.Fatalf("listener defaults: %+v", cfg)
	}
	if cfg.Alerts.AgentSilentAfter != 30*time.Minute || cfg.Alerts.FeedStaleAfter != 48*time.Hour || len(cfg.Alerts.OpsRooms) != 0 {
		t.Fatalf("alert defaults: %+v", cfg.Alerts)
	}
	env := map[string]string{
		"HOLEALIGN_ALERTS_AGENT_SILENT_AFTER": "0",
		"HOLEALIGN_ALERTS_FEED_STALE_AFTER":   "72h",
		"HOLEALIGN_ALERTS_OPS_ROOMS":          "!a:x, !b:x",
		"HOLEALIGN_MATRIX_HOMESERVER":         "https://matrix.example.org",
		"HOLEALIGN_ADMIN_LISTEN":              "0.0.0.0:8081",
		"HOLEALIGN_TRUSTED_PROXIES":           "10.0.0.0/8,192.168.1.1",
	}
	cfg, err = load("", func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Alerts.AgentSilentAfter != 0 || cfg.Alerts.FeedStaleAfter != 72*time.Hour || len(cfg.Alerts.OpsRooms) != 2 || len(cfg.Notify.Ops) != 2 ||
		cfg.AdminListen != "0.0.0.0:8081" || len(cfg.TrustedProxies) != 2 {
		t.Fatalf("env overrides: %+v", cfg)
	}
	for k, v := range map[string]string{"HOLEALIGN_TRUSTED_PROXIES": "not-an-ip", "HOLEALIGN_ALERTS_FEED_STALE_AFTER": "-1h"} {
		k, v := k, v
		if _, err := load("", func(n string) (string, bool) { return v, n == k }); err == nil {
			t.Errorf("%s=%q accepted", k, v)
		}
	}
	c := Default()
	c.AdminListen = ""
	if !c.SharedListener() {
		t.Error("empty admin_listen must mean shared")
	}
	c.AdminListen = c.Listen
	if !c.SharedListener() {
		t.Error("equal listeners must mean shared")
	}
}
