package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func loadLocal(t *testing.T, yml string, env map[string]string) (*Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "s.yaml")
	if err := os.WriteFile(p, []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	return load(p, func(k string) (string, bool) { v, ok := env[k]; return v, ok })
}

func TestLocalAgentDefaults(t *testing.T) {
	cfg, err := loadLocal(t, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	l := cfg.LocalAgent
	if l.Enabled {
		t.Fatal("local_agent must be disabled by default")
	}
	if l.Source != "auto" || l.CollectorSocket != "/run/panoptes/collector.sock" ||
		!reflect.DeepEqual(l.Labels, []string{"server"}) || l.CheckinInterval != 5*time.Minute ||
		l.InventoryInterval != 6*time.Hour || !l.ScanLanguagePackages || l.DockerSocket != "/var/run/docker.sock" ||
		len(l.ExcludePaths) != 0 {
		t.Fatalf("defaults: %+v", l)
	}
}

func TestLocalAgentFileAndEnv(t *testing.T) {
	cfg, err := loadLocal(t, `
local_agent:
  enabled: false
  source: inprocess
  labels: [server, prod]
  checkin_interval: 10m
  exclude_paths: ["/srv"]
`, map[string]string{"PANOPTES_LOCAL_AGENT_ENABLED": "true", "PANOPTES_LOCAL_AGENT_SOURCE": "collector"})
	if err != nil {
		t.Fatal(err)
	}
	l := cfg.LocalAgent
	if !l.Enabled || l.Source != "collector" || !reflect.DeepEqual(l.Labels, []string{"server", "prod"}) ||
		l.CheckinInterval != 10*time.Minute || !reflect.DeepEqual(l.ExcludePaths, []string{"/srv"}) {
		t.Fatalf("got %+v", l)
	}
}

func TestLocalAgentValidation(t *testing.T) {
	for name, tc := range map[string]struct{ yml, want string }{
		"source":   {"local_agent: {source: magic}", "local_agent.source"},
		"socket":   {"local_agent: {collector_socket: run/x.sock}", "collector_socket"},
		"docker":   {"local_agent: {docker_socket: docker.sock}", "docker_socket"},
		"checkin":  {"local_agent: {checkin_interval: 10s}", "checkin_interval"},
		"inv":      {"local_agent: {inventory_interval: 0s}", "inventory_interval"},
		"label":    {"local_agent: {labels: [Bad Label]}", "invalid label"},
		"unknown":  {"local_agent: {nope: 1}", "nope"},
		"emptydoc": {"local_agent: {labels: []}", ""},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := loadLocal(t, tc.yml, nil)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}
