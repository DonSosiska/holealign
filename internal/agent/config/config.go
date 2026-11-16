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
}

// DefaultExcludePaths are excluded from the host scan unless configured otherwise.
func DefaultExcludePaths() []string {
	return []string{"/proc", "/sys", "/dev", "/run", "/var/lib/docker", "/var/lib/containerd", "/snap"}
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
		return fmt.Errorf("config: server_url %q must be an http(s) URL with a host", c.ServerURL)
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
