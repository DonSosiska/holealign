package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	discordScheme = "discord"
	// discordMaxContent is the limit of the "content" field in characters.
	discordMaxContent = 2000
	discordSuppress   = 1 << 2 // message flag SUPPRESS_EMBEDS
)

var (
	discordIDRe    = regexp.MustCompile(`^[0-9]{5,30}$`)
	discordTokenRe = regexp.MustCompile(`^[A-Za-z0-9._-]{20,300}$`)
)

func init() { registerChannel(discordScheme, validDiscordTarget) }

func validDiscordTarget(t string) error { return ValidName(t) }

// ValidDiscordURL checks a Discord webhook URL: https, host discord.com or discordapp.com, path
// /api/webhooks/<id>/<token>, no query. The error never contains the URL.
func ValidDiscordURL(raw string) error {
	u, err := parseHookURL(raw, "https")
	if err != nil {
		return err
	}
	if h := strings.ToLower(u.Hostname()); h != "discord.com" && h != "discordapp.com" {
		return errors.New("URL host must be discord.com or discordapp.com")
	}
	if u.Port() != "" {
		return errors.New("URL must not name a port")
	}
	if u.RawQuery != "" || strings.Contains(raw, "?") {
		return errors.New("URL must not have a query string")
	}
	parts := strings.Split(strings.TrimPrefix(u.EscapedPath(), "/"), "/")
	if len(parts) != 4 || parts[0] != "api" || parts[1] != "webhooks" || !discordIDRe.MatchString(parts[2]) || !discordTokenRe.MatchString(parts[3]) {
		return errors.New("URL path must be /api/webhooks/<id>/<token>")
	}
	return nil
}

// Discord posts messages to Discord webhooks. The webhook URL is the secret; it is never logged or
// included in an error.
type Discord struct {
	hooks  map[string]string
	client *http.Client
}

var _ Channel = (*Discord)(nil)

// NewDiscordChannel takes the webhook URLs by name. httpClient may be nil.
func NewDiscordChannel(hooks map[string]string, httpClient *http.Client) (*Discord, error) {
	if len(hooks) == 0 {
		return nil, errors.New("notify: discord has no webhooks")
	}
	cp := make(map[string]string, len(hooks))
	for name, u := range hooks {
		if err := ValidName(name); err != nil {
			return nil, fmt.Errorf("notify: discord webhook %q: %w", clip(name, 40), err)
		}
		if err := ValidDiscordURL(u); err != nil {
			return nil, fmt.Errorf("notify: discord webhook %q: %w", name, err)
		}
		cp[name] = u
	}
	return &Discord{hooks: cp, client: noRedirect(httpClient)}, nil
}

func (d *Discord) Scheme() string { return discordScheme }

func (d *Discord) ValidTarget(target string) error { return validDiscordTarget(target) }

type discordAllowed struct {
	Parse []string `json:"parse"`
}

type discordPost struct {
	Content         string         `json:"content"`
	AllowedMentions discordAllowed `json:"allowed_mentions"`
	Flags           int            `json:"flags"`
}

func (d *Discord) Send(ctx context.Context, name string, msg Message) error {
	hook, ok := d.hooks[name]
	if !ok {
		return &SendError{Permanent: true, Err: fmt.Errorf("discord webhook %q is not configured", clip(name, 40))}
	}
	secrets := hookSecrets(hook)
	body, err := json.Marshal(discordPost{Content: formatDiscord(msg), AllowedMentions: discordAllowed{Parse: []string{}}, Flags: discordSuppress})
	if err != nil {
		return fmt.Errorf("encode message: %w", err)
	}
	// ?wait=true makes Discord answer with the created message instead of an empty 204, so
	// failures are reported synchronously.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, hook+"?wait=true", bytes.NewReader(body))
	if err != nil {
		return errors.New("build request: " + stripAll(err.Error(), secrets))
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "holealign")

	resp, err := d.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return &SendError{Err: redactNet(err, secrets)}
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, maxRespBody))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	var rl struct {
		RetryAfter float64 `json:"retry_after"` // seconds, may be fractional
	}
	var ra time.Duration
	if resp.StatusCode == http.StatusTooManyRequests && json.Unmarshal(data, &rl) == nil && rl.RetryAfter > 0 && rl.RetryAfter < 24*3600 {
		ra = time.Duration(rl.RetryAfter * float64(time.Second))
	}
	return httpFailure("discord", resp.StatusCode, resp.Header, data, ra, secrets)
}

// --- formatting (Discord markdown) -------------------------------------------------------------

// discordEsc escapes untrusted text for Discord markdown: every markdown character is backslash
// escaped, "@" and "<" are neutralised with a zero-width space so that @everyone, @here and the
// <@id>, <@&id>, <#id>, <:emoji:id> and <t:..> syntaxes cannot form (the request also sets
// allowed_mentions.parse to [] so nothing can ping anyway).
func discordEsc(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\\', '*', '_', '~', '`', '|', '>', '#', '-', '[', ']', '(', ')', '!', ':':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '<':
			b.WriteString("\\<" + zwsp)
		case '@':
			b.WriteString("@" + zwsp)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// discordCode renders a code span: no backtick can close it, mentions stay inert.
func discordCode(s string) string {
	s = strings.ReplaceAll(s, "`", "ˋ")
	s = strings.ReplaceAll(neutralAt(s), "<", "<"+zwsp)
	return "`" + s + "`"
}

// discordURL renders a link as <url>, which Discord shows as a link without an embed. Characters
// that could end the construct are percent-encoded.
func discordURL(u string) string {
	return "<" + strings.NewReplacer(">", "%3E", "<", "%3C", " ", "%20", "\n", "", "\r", "").Replace(u) + ">"
}

// formatDiscord renders the message with at most discordMaxContent characters, cutting on line
// boundaries; a single line that is still too long is cut by characters.
func formatDiscord(m Message) string {
	var out []string
	used := 0
	budget := discordMaxContent - utf8.RuneCountInString(truncatedNote) - 1
	for _, l := range m.Lines {
		l = fitLine(l, 700)
		var b strings.Builder
		for _, s := range l {
			switch s.Kind {
			case SpanBold:
				if strings.TrimSpace(s.Text) != "" {
					b.WriteString("**" + discordEsc(strings.TrimSpace(s.Text)) + "**")
				}
			case SpanCode:
				b.WriteString(discordCode(s.Text))
			case SpanLink:
				b.WriteString(discordURL(s.URL))
			default:
				b.WriteString(discordEsc(s.Text))
			}
		}
		line := b.String()
		if n := utf8.RuneCountInString(line); n > budget { // escaping can triple the length
			line = strings.TrimSuffix(cutRunes(line, budget-1), `\`) + "…"
		}
		n := utf8.RuneCountInString(line) + 1
		if used+n > budget {
			out = append(out, truncatedNote)
			break
		}
		out = append(out, line)
		used += n
	}
	return strings.Join(out, "\n")
}
