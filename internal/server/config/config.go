// Package config loads the Panoptes server configuration (contracts §6).
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultPath is read when neither -config nor PANOPTES_CONFIG is given and the file exists.
const DefaultPath = "/etc/panoptes/server.yaml"

// Config is the whole server configuration. Every key is optional.
type Config struct {
	Listen string `yaml:"listen"` // agent API (/api/v1/*, /healthz)
	// AdminListen serves the web UI. Empty or equal to Listen: one shared listener (legacy).
	AdminListen string `yaml:"admin_listen"`
	PublicURL   string `yaml:"public_url"` // base URL of the admin web UI
	DataDir     string `yaml:"data_dir"`
	RulesDir    string `yaml:"rules_dir"`

	// Native TLS (optional): both of a pair must be set.
	TLSCert      string `yaml:"tls_cert"`
	TLSKey       string `yaml:"tls_key"`
	AdminTLSCert string `yaml:"admin_tls_cert"`
	AdminTLSKey  string `yaml:"admin_tls_key"`
	// TrustedProxies are CIDRs (or single IPs) of reverse proxies whose X-Forwarded-For is trusted.
	TrustedProxies []string `yaml:"trusted_proxies"`

	Alerts Alerts `yaml:"alerts"`

	Feeds  Feeds  `yaml:"feeds"`
	Matrix Matrix `yaml:"matrix"`
	LLM    LLM    `yaml:"llm"`
	Admin  Admin  `yaml:"admin"`
}

// Feeds configures vulnerability data refresh.
type Feeds struct {
	Interval time.Duration `yaml:"interval"` // refresh period, default 6h
	Update   bool          `yaml:"update"`   // false disables all network updates (tests, air-gapped)
}

// Alerts configures silence/health alerts.
type Alerts struct {
	AgentSilentAfter time.Duration `yaml:"agent_silent_after"` // 0 disables agent_silent/agent_back
	FeedStaleAfter   time.Duration `yaml:"feed_stale_after"`   // 0 disables feed_stale/feed_ok
	// OpsRooms receive server-level events; empty falls back to matrix.default_rooms.
	OpsRooms []string `yaml:"ops_rooms"`
}

// Matrix configures the Matrix notifier (used by another package).
type Matrix struct {
	Homeserver     string        `yaml:"homeserver"`
	AccessTokenEnv string        `yaml:"access_token_env"`
	DefaultRooms   []string      `yaml:"default_rooms"`
	Routes         []MatrixRoute `yaml:"routes"`
}

// MatrixRoute sends findings of hosts carrying Label to Rooms.
type MatrixRoute struct {
	Label string   `yaml:"label" json:"label"`
	Rooms []string `yaml:"rooms" json:"rooms"`
}

// LLM configures rule drafting (used by another package).
type LLM struct {
	Provider   string `yaml:"provider"` // none | anthropic | openai-compatible
	Model      string `yaml:"model"`
	BaseURL    string `yaml:"base_url"`
	APIKeyEnv  string `yaml:"api_key_env"`
	DailyLimit int    `yaml:"daily_limit"`
}

// Admin configures the initial web admin user.
type Admin struct {
	InitialPasswordEnv string `yaml:"initial_password_env"`
}

// Default returns the configuration used when nothing is configured.
func Default() Config {
	return Config{
		Listen:      ":8080",
		AdminListen: "127.0.0.1:8081",
		PublicURL:   "http://localhost:8081",
		DataDir:     "/var/lib/panoptes",
		RulesDir:    "/usr/share/panoptes/rules",
		Alerts:      Alerts{AgentSilentAfter: 30 * time.Minute, FeedStaleAfter: 48 * time.Hour},
		Feeds:       Feeds{Interval: 6 * time.Hour, Update: true},
		Matrix:      Matrix{AccessTokenEnv: "PANOPTES_MATRIX_TOKEN"},
		LLM: LLM{
			Provider:   "none",
			Model:      "claude-sonnet-5-5",
			APIKeyEnv:  "PANOPTES_LLM_API_KEY",
			DailyLimit: 50,
		},
		Admin: Admin{InitialPasswordEnv: "PANOPTES_ADMIN_PASSWORD"},
	}
}

// Load reads the config. path wins over $PANOPTES_CONFIG; with neither, DefaultPath is used
// if it exists, otherwise defaults apply. An explicitly named file must exist.
// Environment overrides (PANOPTES_<SECTION>_<KEY>) are applied last.
func Load(path string) (*Config, error) {
	return load(path, os.LookupEnv)
}

func load(path string, lookup func(string) (string, bool)) (*Config, error) {
	cfg := Default()
	explicit := path != ""
	if path == "" {
		path, explicit = lookup("PANOPTES_CONFIG")
		explicit = explicit && path != ""
	}
	if path == "" {
		path = DefaultPath
	}
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
	case errors.Is(err, fs.ErrNotExist) && !explicit:
		// defaults only
	default:
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := walk(reflect.ValueOf(&cfg).Elem(), "PANOPTES", lookup); err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) validate() error {
	if c.Feeds.Interval <= 0 {
		return errors.New("feeds.interval must be positive")
	}
	if c.DataDir == "" {
		return errors.New("data_dir must not be empty")
	}
	c.PublicURL = strings.TrimRight(c.PublicURL, "/")
	if c.Alerts.AgentSilentAfter < 0 || c.Alerts.FeedStaleAfter < 0 {
		return errors.New("alerts.agent_silent_after and alerts.feed_stale_after must not be negative")
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return errors.New("tls_cert and tls_key must be set together")
	}
	if (c.AdminTLSCert == "") != (c.AdminTLSKey == "") {
		return errors.New("admin_tls_cert and admin_tls_key must be set together")
	}
	if _, err := ParseCIDRs(c.TrustedProxies); err != nil {
		return fmt.Errorf("trusted_proxies: %w", err)
	}
	// *_env values name environment variables; restrict them so a config file cannot be used to
	// read arbitrary variables (HOME, AWS_*, ...) or to reuse the admin password as another secret.
	for _, e := range []struct{ key, val string }{
		{"matrix.access_token_env", c.Matrix.AccessTokenEnv},
		{"llm.api_key_env", c.LLM.APIKeyEnv},
		{"admin.initial_password_env", c.Admin.InitialPasswordEnv},
	} {
		if e.val != "" && !envNameRe.MatchString(e.val) {
			return fmt.Errorf("%s %q must match %s", e.key, e.val, envNameRe)
		}
	}
	if adm := c.Admin.InitialPasswordEnv; adm != "" {
		if c.Matrix.AccessTokenEnv == adm || c.LLM.APIKeyEnv == adm {
			return fmt.Errorf("matrix.access_token_env and llm.api_key_env must not be the admin password variable %s", adm)
		}
	}
	return nil
}

// ParseCIDRs parses CIDRs; a bare IP is treated as a /32 or /128.
func ParseCIDRs(in []string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "/") {
			ip := net.ParseIP(s)
			if ip == nil {
				return nil, fmt.Errorf("%q is not an IP address or CIDR", s)
			}
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			s += "/" + strconv.Itoa(bits)
		}
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", s, err)
		}
		out = append(out, n)
	}
	return out, nil
}

// SharedListener reports whether the admin UI and the agent API share one port (legacy mode).
func (c *Config) SharedListener() bool {
	return c.AdminListen == "" || c.AdminListen == c.Listen
}

var envNameRe = regexp.MustCompile(`^PANOPTES_[A-Z0-9_]+$`)

// Warnings returns non-fatal configuration problems to log at startup (cleartext transports).
func (c *Config) Warnings() []string {
	var w []string
	check := func(key, raw string) {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "http" {
			return
		}
		if !isLoopbackHost(u.Hostname()) {
			w = append(w, fmt.Sprintf("%s is plain http to a non-loopback host (%s): traffic and secrets are sent in cleartext; use https", key, u.Hostname()))
		}
	}
	check("public_url", c.PublicURL)
	check("matrix.homeserver", c.Matrix.Homeserver)
	check("llm.base_url", c.LLM.BaseURL)
	return w
}

func isLoopbackHost(h string) bool {
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// DBPath is the SQLite database file.
func (c *Config) DBPath() string { return filepath.Join(c.DataDir, "panoptes.db") }

// GrypeDBDir is the Grype vulnerability DB cache directory.
func (c *Config) GrypeDBDir() string { return filepath.Join(c.DataDir, "grype-db") }

// walk overrides scalar fields from PANOPTES_<SECTION>_<KEY> (top-level: PANOPTES_<KEY>).
func walk(v reflect.Value, prefix string, lookup func(string) (string, bool)) error {
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		tag := strings.Split(t.Field(i).Tag.Get("yaml"), ",")[0]
		if tag == "" || tag == "-" {
			continue
		}
		name := prefix + "_" + strings.ToUpper(tag)
		f := v.Field(i)
		if f.Kind() == reflect.Struct {
			if err := walk(f, name, lookup); err != nil {
				return err
			}
			continue
		}
		val, ok := lookup(name)
		if !ok || val == "" {
			continue
		}
		if err := setScalar(f, val); err != nil {
			return fmt.Errorf("env %s: %w", name, err)
		}
	}
	return nil
}

func setScalar(f reflect.Value, val string) error {
	switch {
	case f.Type() == reflect.TypeOf(time.Duration(0)):
		d, err := time.ParseDuration(val)
		if err != nil {
			return err
		}
		f.SetInt(int64(d))
	case f.Kind() == reflect.String:
		f.SetString(val)
	case f.Kind() == reflect.Bool:
		b, err := strconv.ParseBool(val)
		if err != nil {
			return err
		}
		f.SetBool(b)
	case f.Kind() == reflect.Int || f.Kind() == reflect.Int64:
		n, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return err
		}
		f.SetInt(n)
	case f.Kind() == reflect.Slice && f.Type().Elem().Kind() == reflect.String:
		var parts []string
		for _, p := range strings.Split(val, ",") {
			if p = strings.TrimSpace(p); p != "" {
				parts = append(parts, p)
			}
		}
		f.Set(reflect.ValueOf(parts))
	default:
		// non-scalar (e.g. routes): not overridable from the environment
	}
	return nil
}
