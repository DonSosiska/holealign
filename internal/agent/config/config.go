// Package config loads the agent configuration (docs/contracts.md §2).
package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultPath is the default location of the agent configuration file.
const DefaultPath = "/etc/panoptes/agent.yaml"

// EnvConfigPath overrides the config path (the -config flag wins).
const EnvConfigPath = "PANOPTES_AGENT_CONFIG"

// Config is the agent configuration.
type Config struct {
	ServerURL            string        `yaml:"server_url"`
	EnrollToken          string        `yaml:"enroll_token"`
	Labels               []string      `yaml:"labels"`
	StateDir             string        `yaml:"state_dir"`
	CheckinInterval      time.Duration `yaml:"checkin_interval"`
	InventoryInterval    time.Duration `yaml:"inventory_interval"`
	DockerSocket         string        `yaml:"docker_socket"`
	ScanLanguagePackages bool          `yaml:"scan_language_packages"`
	ExcludePaths         []string      `yaml:"exclude_paths"`
	AllowInsecureHTTP    bool          `yaml:"allow_insecure_http"`
	HostScanTimeout      time.Duration `yaml:"host_scan_timeout"`
	ImageScanTimeout     time.Duration `yaml:"image_scan_timeout"`
}

// DefaultExcludePaths are excluded from the host scan unless configured otherwise.
func DefaultExcludePaths() []string {
	return []string{"/proc", "/sys", "/dev", "/run", "/var/lib/docker", "/var/lib/containerd", "/snap",
		"/mnt", "/media", "/var/lib/containers", "/var/lib/kubelet", "/var/lib/lxc", "/var/lib/lxd", "/home/*/.cache"}
}

// Default returns the configuration with all defaults applied.
func Default() Config {
	return Config{
		StateDir:             "/var/lib/panoptes-agent",
		CheckinInterval:      5 * time.Minute,
		InventoryInterval:    6 * time.Hour,
		DockerSocket:         "/var/run/docker.sock",
		ScanLanguagePackages: true,
		ExcludePaths:         DefaultExcludePaths(),
		HostScanTimeout:      10 * time.Minute,
		ImageScanTimeout:     5 * time.Minute,
	}
}

// ResolvePath picks the config path: flag value, then env, then default.
func ResolvePath(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if v := os.Getenv(EnvConfigPath); v != "" {
		return v
	}
	return DefaultPath
}

// Load reads and validates the file at path.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	return Parse(data)
}

// Parse parses YAML bytes, applies defaults and validates.
func Parse(data []byte) (Config, error) {
	cfg := Default()
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate checks required fields and normalises ServerURL (no trailing slash).
func (c *Config) Validate() error {
	c.ServerURL = strings.TrimRight(strings.TrimSpace(c.ServerURL), "/")
	if c.ServerURL == "" {
		return fmt.Errorf("config: server_url is required")
	}
	u, err := url.Parse(c.ServerURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("config: server_url must be an https URL with a host")
	}
	if u.User != nil {
		return fmt.Errorf("config: server_url must not contain credentials")
	}
	if u.Scheme == "http" && !c.AllowInsecureHTTP {
		return fmt.Errorf("config: server_url must use https:// (set allow_insecure_http: true to permit http)")
	}
	if c.HostScanTimeout <= 0 || c.ImageScanTimeout <= 0 {
		return fmt.Errorf("config: scan timeouts must be positive")
	}
	if c.CheckinInterval <= 0 {
		return fmt.Errorf("config: checkin_interval must be positive")
	}
	if c.InventoryInterval <= 0 {
		return fmt.Errorf("config: inventory_interval must be positive")
	}
	if c.StateDir == "" {
		return fmt.Errorf("config: state_dir must not be empty")
	}
	return nil
}
