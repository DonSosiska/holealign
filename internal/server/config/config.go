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

	// Triage tunes how the web UI splits findings into "needs attention" and "background".
	Triage Triage `yaml:"triage"`

	Retention Retention `yaml:"retention"`
	Limits    Limits    `yaml:"limits"`

	Feeds  Feeds  `yaml:"feeds"`
	Matrix Matrix `yaml:"matrix"`
	LLM    LLM    `yaml:"llm"`
	Admin  Admin  `yaml:"admin"`

	// LocalAgent makes the server monitor its own host (agentless mode, contracts §6).
	LocalAgent LocalAgent `yaml:"local_agent"`
}

// Local agent data sources.
const (
	LocalSourceCollector = "collector"
	LocalSourceInProcess = "inprocess"
	LocalSourceAuto      = "auto"
)

// LocalAgent configures the built-in agent that monitors the server's own host.
type LocalAgent struct {
	Enabled bool `yaml:"enabled"`
	// Source: collector (root collector over its unix socket), inprocess (collect inside the
	// server process with its own privileges) or auto (collector if reachable, else inprocess).
	Source          string `yaml:"source"`
	CollectorSocket string `yaml:"collector_socket"`
	// Labels are authoritative for the local host (like enrollment token labels).
	Labels               []string      `yaml:"labels"`
	CheckinInterval      time.Duration `yaml:"checkin_interval"`
	InventoryInterval    time.Duration `yaml:"inventory_interval"`
	ScanLanguagePackages bool          `yaml:"scan_language_packages"`
	// ExcludePaths replaces the agent defaults (empty = agent defaults).
	ExcludePaths []string `yaml:"exclude_paths"`
	DockerSocket string   `yaml:"docker_socket"`
}

// Duration is a time.Duration that also accepts a "d" (days) suffix in YAML and environment
// overrides, e.g. "30d" or "36h". It is used for retention periods.
type Duration time.Duration

// Std returns the value as time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// ParseDuration parses a Go duration with an optional days component ("30d", "1d12h").
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, 'd'); i > 0 {
		days, err := strconv.ParseFloat(s[:i], 64)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		rest := time.Duration(0)
		if s[i+1:] != "" {
			if rest, err = time.ParseDuration(s[i+1:]); err != nil {
				return 0, err
			}
		}
		return time.Duration(days*24*float64(time.Hour)) + rest, nil
	}
	return time.ParseDuration(s)
}

// UnmarshalYAML accepts "30d", "720h", or a bare 0.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	v, err := ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// Retention bounds the growth of the database (0 = keep forever).
type Retention struct {
	ResolvedFindings Duration `yaml:"resolved_findings"` // delete resolved findings after this age
	Notifications    Duration `yaml:"notifications"`     // delete notification dedup rows after this age
}

// Limits protects the server from single hosts (0 = unlimited).
type Limits struct {
	FindingsPerHost         int `yaml:"findings_per_host"`           // open findings kept per host; excess dropped by lowest severity
	MatchSecondsPerHostHour int `yaml:"match_seconds_per_host_hour"` // cumulative matcher time per host per hour
}

// Feeds configures vulnerability data refresh.
type Feeds struct {
	Interval time.Duration `yaml:"interval"` // refresh period, default 6h
	Update   bool          `yaml:"update"`   // false disables all network updates (tests, air-gapped)
}

// Triage configures the priority tiers of the web UI (docs/rules.md, "Reading the dashboard").
type Triage struct {
	// EPSSThreshold (0..1): a conditions_unknown finding with EPSS at or above it needs attention.
	EPSSThreshold float64 `yaml:"epss_threshold"`
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
		Triage:      Triage{EPSSThreshold: 0.1},
		Feeds:       Feeds{Interval: 6 * time.Hour, Update: true},
		Retention:   Retention{ResolvedFindings: Duration(30 * 24 * time.Hour), Notifications: Duration(90 * 24 * time.Hour)},
		Limits:      Limits{FindingsPerHost: 20000, MatchSecondsPerHostHour: 900},
		Matrix:      Matrix{AccessTokenEnv: "PANOPTES_MATRIX_TOKEN"},
		LLM: LLM{
			Provider:   "none",
			Model:      "claude-sonnet-5-5",
			APIKeyEnv:  "PANOPTES_LLM_API_KEY",
			DailyLimit: 50,
		},
		Admin: Admin{InitialPasswordEnv: "PANOPTES_ADMIN_PASSWORD"},
		LocalAgent: LocalAgent{
			Source:               LocalSourceAuto,
			CollectorSocket:      "/run/panoptes/collector.sock",
			Labels:               []string{"server"},
			CheckinInterval:      5 * time.Minute,
			InventoryInterval:    6 * time.Hour,
			ScanLanguagePackages: true,
			DockerSocket:         "/var/run/docker.sock",
		},
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
	if !(c.Triage.EPSSThreshold >= 0 && c.Triage.EPSSThreshold <= 1) {
		return errors.New("triage.epss_threshold must be between 0 and 1")
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
	// The three secret variables must be pairwise different: one leaked/misused name must not
	// expose a second secret (e.g. the admin password used as a Matrix or LLM token).
	envs := []struct{ key, val string }{
		{"matrix.access_token_env", c.Matrix.AccessTokenEnv},
		{"llm.api_key_env", c.LLM.APIKeyEnv},
		{"admin.initial_password_env", c.Admin.InitialPasswordEnv},
	}
	for i := range envs {
		for j := i + 1; j < len(envs); j++ {
			if envs[i].val != "" && envs[i].val == envs[j].val {
				return fmt.Errorf("%s and %s must name different environment variables (both %s)", envs[i].key, envs[j].key, envs[i].val)
			}
		}
	}
	if c.Retention.ResolvedFindings < 0 || c.Retention.Notifications < 0 {
		return errors.New("retention.* must not be negative")
	}
	if c.Limits.FindingsPerHost < 0 || c.Limits.MatchSecondsPerHostHour < 0 {
		return errors.New("limits.* must not be negative")
	}
	return c.LocalAgent.validate()
}

var localLabelRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

func (l *LocalAgent) validate() error {
	switch l.Source {
	case LocalSourceCollector, LocalSourceInProcess, LocalSourceAuto:
	default:
		return fmt.Errorf("local_agent.source %q must be collector, inprocess or auto", l.Source)
	}
	if !strings.HasPrefix(l.CollectorSocket, "/") {
		return errors.New("local_agent.collector_socket must be an absolute path")
	}
	if l.DockerSocket != "" && !strings.HasPrefix(l.DockerSocket, "/") {
		return errors.New("local_agent.docker_socket must be an absolute path (or empty)")
	}
	if l.CheckinInterval < time.Minute {
		return errors.New("local_agent.checkin_interval must be at least 1m")
	}
	if l.InventoryInterval < time.Minute {
		return errors.New("local_agent.inventory_interval must be at least 1m")
	}
	if len(l.Labels) > 32 {
		return errors.New("local_agent.labels: too many labels (max 32)")
	}
	for _, lb := range l.Labels {
		if !localLabelRe.MatchString(lb) {
			return fmt.Errorf("local_agent.labels: invalid label %q (must match %s)", lb, localLabelRe)
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

	if nets, err := ParseCIDRs(c.TrustedProxies); err == nil {
		for _, n := range nets {
			ones, bits := n.Mask.Size()
			switch {
			case ones == 0:
				w = append(w, fmt.Sprintf("trusted_proxies contains %s: every client could spoof X-Forwarded-For (rate limits, audit log)", n))
			case bits == 32 && ones < 16, bits == 128 && ones < 48:
				w = append(w, fmt.Sprintf("trusted_proxies entry %s is very broad (wider than /16 for IPv4 or /48 for IPv6); list only the reverse proxy addresses", n))
			}
		}
	}
	if !c.SharedListener() && !isLoopbackListen(c.AdminListen) && c.AdminTLSCert == "" {
		w = append(w, fmt.Sprintf("admin_listen %s is not loopback and has no admin_tls_cert/admin_tls_key: the web UI (logins, session cookies) is served in cleartext", c.AdminListen))
	}
	// "public-facing" = no trusted reverse proxy configured in front of the agent listener.
	if !isLoopbackListen(c.Listen) && c.TLSCert == "" && len(c.TrustedProxies) == 0 {
		w = append(w, fmt.Sprintf("listen %s is not loopback, has no tls_cert/tls_key and no trusted_proxies (no TLS-terminating reverse proxy): agent keys and inventories travel in cleartext", c.Listen))
	}
	return w
}

// isLoopbackListen reports whether a listen address binds loopback only; ":8080" and "0.0.0.0:80" do not.
func isLoopbackListen(addr string) bool {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		h = addr
	}
	return h != "" && isLoopbackHost(h)
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
	case f.Type() == reflect.TypeOf(Duration(0)):
		d, err := ParseDuration(val)
		if err != nil {
			return err
		}
		f.SetInt(int64(d))
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
	case f.Kind() == reflect.Float64:
		x, err := strconv.ParseFloat(val, 64)
		if err != nil {
			return err
		}
		f.SetFloat(x)
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
