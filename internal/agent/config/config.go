// Package config loads the agent configuration (docs/contracts.md §2).
package config

import (
	"crypto/x509"
	"encoding/hex"
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

	// Server identity pinning (docs/contracts.md §2).
	CAFile           string   `yaml:"ca_file"`            // PEM bundle; when set ONLY these roots are trusted
	ServerCertSHA256 []string `yaml:"server_cert_sha256"` // hex SHA-256 of the leaf SubjectPublicKeyInfo
	ClientCert       string   `yaml:"client_cert"`        // optional mTLS client certificate (PEM)
	ClientKey        string   `yaml:"client_key"`         // key for client_cert (PEM)

	// Privilege separation (docs/contracts.md §2): the root collector listens on this
	// unix socket, the unprivileged sender connects to it. Unused in -mode all.
	CollectorSocket string `yaml:"collector_socket"`
	// CollectorUser is the unprivileged user whose uid may use the socket (plus root);
	// its primary group owns the socket.
	CollectorUser string `yaml:"collector_user"`
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
		CollectorSocket:      "/run/panoptes/collector.sock",
		CollectorUser:        "panoptes",
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
	if c.CollectorSocket == "" || !strings.HasPrefix(c.CollectorSocket, "/") {
		return fmt.Errorf("config: collector_socket must be an absolute path")
	}
	pins, err := NormalizePins(c.ServerCertSHA256)
	if err != nil {
		return err
	}
	c.ServerCertSHA256 = pins
	if c.CAFile != "" {
		if err := checkCAFile(c.CAFile); err != nil {
			return err
		}
	}
	if (c.ClientCert == "") != (c.ClientKey == "") {
		return fmt.Errorf("config: client_cert and client_key must be set together")
	}
	for name, p := range map[string]string{"client_cert": c.ClientCert, "client_key": c.ClientKey} {
		if p == "" {
			continue
		}
		f, err := os.Open(p)
		if err != nil {
			return fmt.Errorf("config: %s: %w", name, err)
		}
		f.Close()
	}
	return nil
}

// NormalizePins validates the hex SHA-256 pins and returns them lower-case without
// separators (a colon-separated openssl style fingerprint is accepted).
func NormalizePins(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	for _, p := range in {
		n := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(p), ":", ""))
		b, err := hex.DecodeString(n)
		if err != nil || len(b) != 32 {
			return nil, fmt.Errorf("config: server_cert_sha256 entry %q is not a 64-character hex SHA-256", p)
		}
		out = append(out, n)
	}
	return out, nil
}

func checkCAFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("config: ca_file: %w", err)
	}
	if !x509.NewCertPool().AppendCertsFromPEM(data) {
		return fmt.Errorf("config: ca_file %s contains no PEM certificate", path)
	}
	return nil
}
