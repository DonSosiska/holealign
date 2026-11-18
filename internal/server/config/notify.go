package config

import (
	"encoding/json"
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

// Channels reports which notification channels are configured, by destination scheme.
func (c *Config) Channels() map[string]bool {
	return map[string]bool{
		"matrix":   c.Matrix.Homeserver != "",
		"slack":    c.Slack.TokenEnv != "",
		"telegram": c.Telegram.BotTokenEnv != "",
		"discord":  len(c.Discord.Webhooks) > 0,
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

// validateDiscord checks the names of the webhooks. Their URLs come from the environment.
func (c *Config) validateDiscord() error {
	for _, name := range sortedKeys(c.Discord.Webhooks) {
		if err := notify.ValidName(name); err != nil {
			return fmt.Errorf("discord.webhooks.%s: %w", name, err)
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
	return nil
}
