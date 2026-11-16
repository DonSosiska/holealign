package config

import (
	"testing"
	"time"
)

func TestDefaults(t *testing.T) {
	c, err := Parse([]byte("server_url: https://p.example.com/\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.ServerURL != "https://p.example.com" {
		t.Errorf("server url %q", c.ServerURL)
	}
	if c.CheckinInterval != 5*time.Minute || c.InventoryInterval != 6*time.Hour {
		t.Errorf("intervals %v %v", c.CheckinInterval, c.InventoryInterval)
	}
	if c.StateDir != "/var/lib/panoptes-agent" || c.DockerSocket != "/var/run/docker.sock" || !c.ScanLanguagePackages {
		t.Errorf("defaults wrong: %+v", c)
	}
	if len(c.ExcludePaths) != 7 {
		t.Errorf("exclude %v", c.ExcludePaths)
	}
}

func TestOverrides(t *testing.T) {
	c, err := Parse([]byte("server_url: http://x:8080\nlabels: [a, b]\ncheckin_interval: 30s\nscan_language_packages: false\nexclude_paths: [/tmp]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.CheckinInterval != 30*time.Second || c.ScanLanguagePackages || len(c.Labels) != 2 || len(c.ExcludePaths) != 1 {
		t.Errorf("%+v", c)
	}
}

func TestValidation(t *testing.T) {
	for _, in := range []string{"", "server_url: ftp://x", "server_url: nohost", "server_url: http://x\ncheckin_interval: 0s"} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("expected error for %q", in)
		}
	}
}

func TestResolvePath(t *testing.T) {
	t.Setenv(EnvConfigPath, "/env")
	if ResolvePath("/flag") != "/flag" || ResolvePath("") != "/env" {
		t.Error("precedence")
	}
	t.Setenv(EnvConfigPath, "")
	if ResolvePath("") != DefaultPath {
		t.Error("default")
	}
}
