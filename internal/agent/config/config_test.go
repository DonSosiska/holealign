package config

import (
	"os"
	"path/filepath"
	"strings"
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
	if c.StateDir != "/var/lib/holealign-agent" || c.DockerSocket != "/var/run/docker.sock" || !c.ScanLanguagePackages {
		t.Errorf("defaults wrong: %+v", c)
	}
	if len(c.ExcludePaths) != 14 {
		t.Errorf("exclude %v", c.ExcludePaths)
	}
}

func TestOverrides(t *testing.T) {
	c, err := Parse([]byte("server_url: http://x:8080\nallow_insecure_http: true\nlabels: [a, b]\ncheckin_interval: 30s\nscan_language_packages: false\nexclude_paths: [/tmp]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.CheckinInterval != 30*time.Second || c.ScanLanguagePackages || len(c.Labels) != 2 || len(c.ExcludePaths) != 1 {
		t.Errorf("%+v", c)
	}
}

func TestValidation(t *testing.T) {
	for _, in := range []string{"", "server_url: ftp://x", "server_url: nohost", "server_url: http://x\ncheckin_interval: 0s", "server_url: http://x:8080", "server_url: https://u:p@x", "server_url: https://x\nhost_scan_timeout: 0s"} {
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

func TestPinningValidation(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	cfg, err := Parse([]byte("server_url: https://x\nserver_cert_sha256: [\"" + strings.ToUpper(pin) + "\"]"))
	if err != nil || cfg.ServerCertSHA256[0] != pin {
		t.Fatalf("valid pin: %v %v", cfg.ServerCertSHA256, err)
	}
	colon := strings.TrimSuffix(strings.Repeat("ab:", 32), ":")
	if cfg, err := Parse([]byte("server_url: https://x\nserver_cert_sha256: [\"" + colon + "\"]")); err != nil || cfg.ServerCertSHA256[0] != pin {
		t.Fatalf("colon pin: %v %v", cfg.ServerCertSHA256, err)
	}
	for _, bad := range []string{"zz", "abcd", strings.Repeat("g", 64), strings.Repeat("ab", 33)} {
		if _, err := Parse([]byte("server_url: https://x\nserver_cert_sha256: [\"" + bad + "\"]")); err == nil {
			t.Errorf("bad pin %q accepted", bad)
		}
	}
}

func TestCAFileValidation(t *testing.T) {
	dir := t.TempDir()
	if _, err := Parse([]byte("server_url: https://x\nca_file: " + dir + "/missing.pem")); err == nil {
		t.Error("unreadable ca_file accepted")
	}
	junk := filepath.Join(dir, "junk.pem")
	os.WriteFile(junk, []byte("hello"), 0o600)
	if _, err := Parse([]byte("server_url: https://x\nca_file: " + junk)); err == nil {
		t.Error("ca_file without certificates accepted")
	}
	if _, err := Parse([]byte("server_url: https://x\nclient_cert: " + junk)); err == nil {
		t.Error("client_cert without client_key accepted")
	}
	if _, err := Parse([]byte("server_url: https://x\nclient_cert: /nope\nclient_key: /nope")); err == nil {
		t.Error("unreadable client cert accepted")
	}
}
