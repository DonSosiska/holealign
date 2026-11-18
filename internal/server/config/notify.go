package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/DonSosiska/holealign/internal/server/notify"
)

// Notify routes events to destinations. A destination is "scheme:target" (slack:C0123456789,
// telegram:-1001234567890/5); one without a known scheme is a Matrix room ("!id:server").
type Notify struct {
	Default []string      `yaml:"default"` // used when no route matches a host's labels
	Routes  []NotifyRoute `yaml:"routes"`
	Ops     []string      `yaml:"ops"` // server-level events (feed, pipeline, aggregated silence); empty: default
}

// NotifyRoute sends findings of hosts carrying Label to the destinations in To. It is also the
// format of the routes edited in the web UI (stored as JSON; the old key "rooms" is still read).
type NotifyRoute struct {
	Label string   `yaml:"label" json:"label"`
	To    []string `yaml:"to" json:"to"`
}

// UnmarshalJSON reads the current format {"label","to"} and the one used before notifier channels
// existed, {"label","rooms"}.
func (r *NotifyRoute) UnmarshalJSON(b []byte) error {
	var v struct {
		Label string   `json:"label"`
		To    []string `json:"to"`
		Rooms []string `json:"rooms"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	r.Label, r.To = v.Label, append(v.To, v.Rooms...)
	return nil
}

// Slack configures the Slack channel (bot token, chat.postMessage). Enabled when TokenEnv is set.
type Slack struct {
	TokenEnv string `yaml:"token_env"`
}

// Telegram configures the Telegram channel (Bot API sendMessage). Enabled when BotTokenEnv is set.
type Telegram struct {
	BotTokenEnv string `yaml:"bot_token_env"`
}

// Discord configures the Discord channel: named webhooks. The destination is "discord:<name>"; the
// webhook URL (which is the secret) is read from the environment variable URLEnv names, never from
// the config file or the web UI. An empty URLEnv defaults to HOLEALIGN_DISCORD_<NAME>_URL.
type Discord struct {
	Webhooks map[string]DiscordWebhook `yaml:"webhooks"`
}

// DiscordWebhook is one Discord webhook.
type DiscordWebhook struct {
	URLEnv string `yaml:"url_env"`
}

// Teams configures the Microsoft Teams channel: named Workflows webhooks ("When a Teams webhook
// request is received"). The destination is "teams:<name>"; the URL (a secret) is read from the
// environment variable URLEnv names (default HOLEALIGN_TEAMS_<NAME>_URL).
type Teams struct {
	Webhooks map[string]TeamsWebhook `yaml:"webhooks"`
}

// TeamsWebhook is one Teams webhook. Its host must end in one of notify.TeamsHostSuffixes unless
// AllowAnyHost is set.
type TeamsWebhook struct {
	URLEnv       string `yaml:"url_env"`
	AllowAnyHost bool   `yaml:"allow_any_host"`
}

// Webhook configures the generic signed webhook channel: named endpoints. The destination is
// "webhook:<name>". Unlike Discord and Teams, the URL is not a secret and is set here; the signing
// secret is read from the environment variable SecretEnv names (default
// HOLEALIGN_WEBHOOK_<NAME>_SECRET).
type Webhook struct {
	Endpoints map[string]WebhookEndpoint `yaml:"endpoints"`
}

// WebhookEndpoint is one generic webhook. URL must be https unless AllowHTTP is set. It may point to
// any host: it comes from this file, which only the operator edits.
type WebhookEndpoint struct {
	URL       string            `yaml:"url"`
	SecretEnv string            `yaml:"secret_env"`
	Headers   map[string]string `yaml:"headers"`
	AllowHTTP bool              `yaml:"allow_http"`
}

// Email configures the email channel. The destination is "email:<address>". TLS is mandatory.
type Email struct {
	SMTP EmailSMTP `yaml:"smtp"`
	// AllowedDomains, when not empty, limits the recipients (and so what an admin can route to in the
	// web UI) to addresses in these domains.
	AllowedDomains []string `yaml:"allowed_domains"`
}

// EmailSMTP is the SMTP server the email channel sends through. Enabled when Host is set. The
// password is read from the environment variable PasswordEnv.
type EmailSMTP struct {
	Host        string `yaml:"host"`
	Port        int    `yaml:"port"` // default 587
	Username    string `yaml:"username"`
	PasswordEnv string `yaml:"password_env"` // default HOLEALIGN_SMTP_PASSWORD
	TLS         string `yaml:"tls"`          // "starttls" (default) or "implicit"; plain text is not supported
	From        string `yaml:"from"`         // "alerts@example.com" or "Holealign <alerts@example.com>"
}

// Channels reports which notification channels are configured, by destination scheme.
func (c *Config) Channels() map[string]bool {
	return map[string]bool{
		"matrix":   c.Matrix.Homeserver != "",
		"slack":    c.Slack.TokenEnv != "",
		"telegram": c.Telegram.BotTokenEnv != "",
		"discord":  len(c.Discord.Webhooks) > 0,
		"teams":    len(c.Teams.Webhooks) > 0,
		"webhook":  len(c.Webhook.Endpoints) > 0,
		"email":    c.Email.SMTP.Host != "",
	}
}

// mergeDeprecated folds matrix.default_rooms, matrix.routes[].rooms and alerts.ops_rooms into
// notify.* and records which deprecated keys were used.
func (c *Config) mergeDeprecated() {
	c.deprecated = nil
	if len(c.Matrix.DefaultRooms) > 0 {
		c.deprecated = append(c.deprecated, "matrix.default_rooms (use notify.default)")
		c.Notify.Default = appendUniq(c.Notify.Default, c.Matrix.DefaultRooms...)
	}
	if len(c.Matrix.Routes) > 0 {
		c.deprecated = append(c.deprecated, "matrix.routes[].rooms (use notify.routes[].to)")
		for _, r := range c.Matrix.Routes {
			merged := false
			for i := range c.Notify.Routes {
				if c.Notify.Routes[i].Label == r.Label {
					c.Notify.Routes[i].To = appendUniq(c.Notify.Routes[i].To, r.Rooms...)
					merged = true
				}
			}
			if !merged {
				c.Notify.Routes = append(c.Notify.Routes, NotifyRoute{Label: r.Label, To: appendUniq(nil, r.Rooms...)})
			}
		}
	}
	if len(c.Alerts.OpsRooms) > 0 {
		c.deprecated = append(c.deprecated, "alerts.ops_rooms (use notify.ops)")
		c.Notify.Ops = appendUniq(c.Notify.Ops, c.Alerts.OpsRooms...)
	}
}

func appendUniq(dst []string, src ...string) []string {
	for _, s := range src {
		s = strings.TrimSpace(s)
		if s != "" && !slices.Contains(dst, s) {
			dst = append(dst, s)
		}
	}
	return dst
}

// ValidateDestination checks one destination's syntax and that its channel is configured. It is
// what config load and the web UI use, so both reject the same inputs.
func (c *Config) ValidateDestination(dest string) error {
	if err := notify.ValidateDestination(dest); err != nil {
		return err
	}
	scheme, target := notify.ParseDestination(dest)
	if !c.Channels()[scheme] {
		return fmt.Errorf("%q uses the %s channel, which is not configured (%s)", dest, scheme, channelHint(scheme))
	}
	switch scheme {
	case "email":
		if len(c.Email.AllowedDomains) > 0 && !slices.Contains(c.Email.AllowedDomains, notify.MailboxDomain(target)) {
			return fmt.Errorf("%q: domain %q is not in email.allowed_domains (%s)", dest, notify.MailboxDomain(target), strings.Join(c.Email.AllowedDomains, ", "))
		}
	case "webhook":
		if _, ok := c.Webhook.Endpoints[target]; !ok {
			return fmt.Errorf("%q: no endpoint named %q under webhook.endpoints (configured: %s)", dest, target, mapKeys(c.Webhook.Endpoints))
		}
	case "teams":
		if _, ok := c.Teams.Webhooks[target]; !ok {
			return fmt.Errorf("%q: no webhook named %q under teams.webhooks (configured: %s)", dest, target, mapKeys(c.Teams.Webhooks))
		}
	case "discord":
		if _, ok := c.Discord.Webhooks[target]; !ok {
			return fmt.Errorf("%q: no webhook named %q under discord.webhooks (configured: %s)", dest, target, mapKeys(c.Discord.Webhooks))
		}
	}
	return nil
}

// validateNotify checks every destination of the notify section.
func (c *Config) validateNotify() error {
	check := func(key, dest string) error {
		if err := c.ValidateDestination(dest); err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
		return nil
	}
	for i, d := range c.Notify.Default {
		if err := check(fmt.Sprintf("notify.default[%d]", i), d); err != nil {
			return err
		}
	}
	for i, d := range c.Notify.Ops {
		if err := check(fmt.Sprintf("notify.ops[%d]", i), d); err != nil {
			return err
		}
	}
	for i, r := range c.Notify.Routes {
		if r.Label == "" {
			return fmt.Errorf("notify.routes[%d]: label is empty", i)
		}
		if len(r.To) == 0 {
			return fmt.Errorf("notify.routes[%d] (%s): \"to\" lists no destinations", i, r.Label)
		}
		for j, d := range r.To {
			if err := check(fmt.Sprintf("notify.routes[%d].to[%d]", i, j), d); err != nil {
				return err
			}
		}
	}
	return nil
}

func channelHint(scheme string) string {
	switch scheme {
	case "slack":
		return "set slack.token_env"
	case "telegram":
		return "set telegram.bot_token_env"
	case "discord":
		return "add a webhook under discord.webhooks"
	case "teams":
		return "add a webhook under teams.webhooks"
	case "webhook":
		return "add an endpoint under webhook.endpoints"
	case "email":
		return "set email.smtp.host"
	default:
		return "set matrix.homeserver"
	}
}

// mapKeys lists the keys of m, sorted, for error messages.
func mapKeys[V any](m map[string]V) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return strings.Join(keys, ", ")
}

// sortedKeys returns the keys of m in order, so errors are deterministic.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// envFor returns the environment variable of a named webhook: the configured one, or the default
// HOLEALIGN_<SECTION>_<NAME>_<SUFFIX> derived from the name.
func envFor(section, name, configured, suffix string) string {
	if configured != "" {
		return configured
	}
	n := strings.ToUpper(strings.NewReplacer("-", "_").Replace(name))
	return "HOLEALIGN_" + section + "_" + n + "_" + suffix
}

// DiscordURLEnv is the environment variable that holds the URL of Discord webhook name.
func (c *Config) DiscordURLEnv(name string) string {
	return envFor("DISCORD", name, c.Discord.Webhooks[name].URLEnv, "URL")
}

// TeamsURLEnv is the environment variable that holds the URL of Teams webhook name.
func (c *Config) TeamsURLEnv(name string) string {
	return envFor("TEAMS", name, c.Teams.Webhooks[name].URLEnv, "URL")
}

// WebhookSecretEnv is the environment variable that holds the signing secret of endpoint name.
func (c *Config) WebhookSecretEnv(name string) string {
	return envFor("WEBHOOK", name, c.Webhook.Endpoints[name].SecretEnv, "SECRET")
}

// validateDiscord checks the names of the webhooks. Their URLs come from the environment.
func (c *Config) validateDiscord() error {
	for _, name := range sortedKeys(c.Discord.Webhooks) {
		if err := notify.ValidName(name); err != nil {
			return fmt.Errorf("discord.webhooks.%s: %w", name, err)
		}
	}
	for _, name := range sortedKeys(c.Teams.Webhooks) {
		if err := notify.ValidName(name); err != nil {
			return fmt.Errorf("teams.webhooks.%s: %w", name, err)
		}
	}
	if err := c.Email.validate(); err != nil {
		return err
	}
	for _, name := range sortedKeys(c.Webhook.Endpoints) {
		ep := c.Webhook.Endpoints[name]
		if err := notify.ValidName(name); err != nil {
			return fmt.Errorf("webhook.endpoints.%s: %w", name, err)
		}
		if err := notify.ValidWebhookURL(ep.URL, ep.AllowHTTP); err != nil {
			return fmt.Errorf("webhook.endpoints.%s.url: %w", name, err)
		}
		if err := notify.ValidWebhookHeaders(ep.Headers); err != nil {
			return fmt.Errorf("webhook.endpoints.%s.headers: %w", name, err)
		}
	}
	return nil
}

// validateEnvURLs checks the webhook URLs that are present in the environment at load time, so a
// malformed or foreign URL is rejected at startup. A URL that is not set is reported when the
// channel is built. Errors name the key and the variable, never the URL.
func (c *Config) validateEnvURLs(lookup func(string) (string, bool)) error {
	for _, name := range sortedKeys(c.Discord.Webhooks) {
		env := c.DiscordURLEnv(name)
		if v, ok := lookup(env); ok && v != "" {
			if err := notify.ValidDiscordURL(v); err != nil {
				return fmt.Errorf("discord.webhooks.%s.url_env (%s): %w", name, env, err)
			}
		}
	}
	for _, name := range sortedKeys(c.Teams.Webhooks) {
		env := c.TeamsURLEnv(name)
		if v, ok := lookup(env); ok && v != "" {
			if err := notify.ValidTeamsURL(v, c.Teams.Webhooks[name].AllowAnyHost); err != nil {
				return fmt.Errorf("teams.webhooks.%s.url_env (%s): %w", name, env, err)
			}
		}
	}
	return nil
}

// validate checks the email section; nothing is checked while no SMTP host is set.
func (e *Email) validate() error {
	for i, d := range e.AllowedDomains {
		if err := notify.ValidMailDomain(d); err != nil {
			return fmt.Errorf("email.allowed_domains[%d] %q: %w", i, d, err)
		}
	}
	s := e.SMTP
	if s.Host == "" {
		if len(e.AllowedDomains) > 0 || s.Username != "" || s.From != "" {
			return fmt.Errorf("email.smtp.host is not set but other email settings are")
		}
		return nil
	}
	if err := notify.ValidSMTPHost(s.Host); err != nil {
		return fmt.Errorf("email.smtp.host: %w", err)
	}
	if s.Port < 1 || s.Port > 65535 {
		return fmt.Errorf("email.smtp.port %d must be 1-65535", s.Port)
	}
	if s.TLS != notify.TLSStartTLS && s.TLS != notify.TLSImplicit {
		return fmt.Errorf("email.smtp.tls %q must be %q or %q (plain text is not supported)", s.TLS, notify.TLSStartTLS, notify.TLSImplicit)
	}
	if s.Username != "" && s.PasswordEnv == "" {
		return errors.New("email.smtp.password_env must be set when email.smtp.username is")
	}
	if strings.ContainsAny(s.Username, "\r\n\x00") {
		return errors.New("email.smtp.username contains control characters")
	}
	if _, err := notify.ParseSender(s.From); err != nil {
		return fmt.Errorf("email.smtp.from: %w", err)
	}
	return nil
}
