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
)

const (
	teamsScheme = "teams"
	// teamsMaxCard is the budget for the JSON of one message. Workflows accept about 28 KB.
	teamsMaxCard = 25 << 10
	// teamsMaxBlock is the visible text of one TextBlock before escaping.
	teamsMaxBlock = 1500
)

// TeamsHostSuffixes are the host name suffixes a Teams workflow URL may have. Anything else needs
// allow_any_host: true on that webhook.
var TeamsHostSuffixes = []string{".logic.azure.com", ".powerplatform.com", ".environment.api.powerplatform.com"}

func init() { registerChannel(teamsScheme, validTeamsTarget) }

func validTeamsTarget(t string) error { return ValidName(t) }

// ValidTeamsURL checks the URL of a Power Automate / Workflows "When a Teams webhook request is
// received" trigger: https, no user info, and (unless allowAnyHost) a host ending in one of
// TeamsHostSuffixes. The error never contains the URL.
func ValidTeamsURL(raw string, allowAnyHost bool) error {
	u, err := parseHookURL(raw, "https")
	if err != nil {
		return err
	}
	if allowAnyHost {
		return nil
	}
	h := strings.ToLower(u.Hostname())
	for _, s := range TeamsHostSuffixes {
		if strings.HasSuffix(h, s) && len(h) > len(s) {
			return nil
		}
	}
	return fmt.Errorf("URL host must end with one of %s (or set allow_any_host: true for this webhook)", strings.Join(TeamsHostSuffixes, ", "))
}

// TeamsHook is one configured Teams webhook.
type TeamsHook struct {
	URL          string
	AllowAnyHost bool
}

// Teams posts Adaptive Card messages to Microsoft Teams through a Workflows webhook. The webhook URL
// carries a signature, so it is secret and never logged or included in an error.
type Teams struct {
	hooks  map[string]string
	client *http.Client
}

var _ Channel = (*Teams)(nil)

// NewTeamsChannel takes the webhooks by name. httpClient may be nil.
func NewTeamsChannel(hooks map[string]TeamsHook, httpClient *http.Client) (*Teams, error) {
	if len(hooks) == 0 {
		return nil, errors.New("notify: teams has no webhooks")
	}
	cp := make(map[string]string, len(hooks))
	for name, h := range hooks {
		if err := ValidName(name); err != nil {
			return nil, fmt.Errorf("notify: teams webhook %q: %w", clip(name, 40), err)
		}
		if err := ValidTeamsURL(h.URL, h.AllowAnyHost); err != nil {
			return nil, fmt.Errorf("notify: teams webhook %q: %w", name, err)
		}
		cp[name] = h.URL
	}
	return &Teams{hooks: cp, client: noRedirect(httpClient)}, nil
}

func (t *Teams) Scheme() string { return teamsScheme }

func (t *Teams) ValidTarget(target string) error { return validTeamsTarget(target) }

type adaptiveTextBlock struct {
	Type   string `json:"type"`
	Text   string `json:"text"`
	Wrap   bool   `json:"wrap"`
	Weight string `json:"weight,omitempty"`
}

type adaptiveCard struct {
	Schema  string              `json:"$schema"`
	Type    string              `json:"type"`
	Version string              `json:"version"`
	Body    []adaptiveTextBlock `json:"body"`
}

type teamsAttachment struct {
	ContentType string       `json:"contentType"`
	ContentURL  *string      `json:"contentUrl"`
	Content     adaptiveCard `json:"content"`
}

type teamsPost struct {
	Type        string            `json:"type"`
	Attachments []teamsAttachment `json:"attachments"`
}

func (t *Teams) Send(ctx context.Context, name string, msg Message) error {
	hook, ok := t.hooks[name]
	if !ok {
		return &SendError{Permanent: true, Err: fmt.Errorf("teams webhook %q is not configured", clip(name, 40))}
	}
	secrets := hookSecrets(hook)
	body, err := json.Marshal(formatTeams(msg))
	if err != nil {
		return fmt.Errorf("encode message: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, hook, bytes.NewReader(body))
	if err != nil {
		return errors.New("build request: " + stripAll(err.Error(), secrets))
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "holealign")

	resp, err := t.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return &SendError{Err: redactNet(err, secrets)}
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, maxRespBody))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 { // 202 Accepted is the normal answer
		return nil
	}
	return httpFailure("teams", resp.StatusCode, resp.Header, data, 0, secrets)
}

// --- formatting (Adaptive Card TextBlocks, markdown subset) ------------------------------------

var leadingNumber = regexp.MustCompile(`^(\s*[0-9]+)\.`)

// teamsEsc escapes untrusted text for the markdown subset of a TextBlock (bold, italic, lists,
// links). "@" is neutralised; mentions would need <at> entities that are never sent, and "<" is
// escaped as well.
func teamsEsc(s string) string {
	var b strings.Builder
	for _, r := range neutralAt(s) {
		switch r {
		case '\\', '*', '_', '`', '~', '[', ']', '(', ')', '<', '>', '#', '|', '!', '-', '+', '&':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	// "1. " would start a list
	return leadingNumber.ReplaceAllString(b.String(), `$1\.`)
}

// teamsURL makes a URL safe inside [label](url).
func teamsURL(u string) string {
	return strings.NewReplacer("(", "%28", ")", "%29", " ", "%20", "<", "%3C", ">", "%3E", "\\", "%5C", "\n", "", "\r", "", "[", "%5B", "]", "%5D").Replace(u)
}

// teamsLine renders one line as markdown.
func teamsLine(l Line) string {
	var b strings.Builder
	for _, s := range l {
		switch s.Kind {
		case SpanBold:
			if strings.TrimSpace(s.Text) != "" {
				b.WriteString("**" + teamsEsc(strings.TrimSpace(s.Text)) + "**")
			}
		case SpanLink:
			b.WriteString("[" + teamsEsc(s.Text) + "](" + teamsURL(s.URL) + ")")
		default: // text, and code (Adaptive Cards have no inline code in a TextBlock)
			b.WriteString(teamsEsc(s.Text))
		}
	}
	return b.String()
}

// formatTeams builds the message with one Adaptive Card. Each line is its own TextBlock; the first
// one (the headline) is bold. Whole lines are dropped to keep the JSON below teamsMaxCard.
func formatTeams(m Message) teamsPost {
	card := adaptiveCard{Schema: "http://adaptivecards.io/schemas/adaptive-card.json", Type: "AdaptiveCard", Version: "1.4"}
	used := 400         // envelope
	const reserve = 160 // room for the truncation note
	for i, l := range m.Lines {
		text := teamsLine(fitLine(l, teamsMaxBlock))
		if strings.TrimSpace(text) == "" {
			continue
		}
		blk := adaptiveTextBlock{Type: "TextBlock", Text: text, Wrap: true}
		if i == 0 {
			blk.Weight = "Bolder"
		}
		raw, _ := json.Marshal(blk)
		if used+len(raw)+1+reserve > teamsMaxCard {
			card.Body = append(card.Body, adaptiveTextBlock{Type: "TextBlock", Text: truncatedNote, Wrap: true})
			break
		}
		used += len(raw) + 1
		card.Body = append(card.Body, blk)
	}
	if len(card.Body) == 0 {
		card.Body = []adaptiveTextBlock{{Type: "TextBlock", Text: "(empty message)", Wrap: true}}
	}
	return teamsPost{Type: "message", Attachments: []teamsAttachment{{ContentType: "application/vnd.microsoft.card.adaptive", Content: card}}}
}
