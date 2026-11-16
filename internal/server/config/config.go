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
	Listen    string `yaml:"listen"`
	PublicURL string `yaml:"public_url"`
	DataDir   string `yaml:"data_dir"`
	RulesDir  string `yaml:"rules_dir"`

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
		Listen:    ":8080",
		PublicURL: "http://localhost:8080",
		DataDir:   "/var/lib/panoptes",
		RulesDir:  "/usr/share/panoptes/rules",
		Feeds:     Feeds{Interval: 6 * time.Hour, Update: true},
		Matrix:    Matrix{AccessTokenEnv: "PANOPTES_MATRIX_TOKEN"},
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
