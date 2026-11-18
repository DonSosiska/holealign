package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// slackAPI is the Slack Web API base. It is a constant on purpose: nothing in the config or the web
// UI can point the server at another host. Tests set Slack.base directly.
const slackAPI = "https://slack.com/api"

const (
	slackScheme      = "slack"
	slackMaxText     = 35000 // runes of the message; Slack truncates at 40,000
	slackMaxLineText = 3000  // visible runes of one line before escaping
)

// slackChannelRe: conversation IDs only (public C, private/group G, DM D), never names.
var slackChannelRe = regexp.MustCompile(`^[CGD][A-Z0-9]{8,20}$`)

func init() { registerChannel(slackScheme, validSlackTarget) }

func validSlackTarget(t string) error {
	if !slackChannelRe.MatchString(t) {
		return errors.New("not a Slack channel ID (expected the ID such as C0123456789, not the name; see docs/notifications.md)")
	}
	return nil
}

// Slack posts messages with chat.postMessage using a bot token (xoxb-...). One token serves many
// channels; the bot must be a member of every channel it posts to.
type Slack struct {
	token  string
	base   string
	client *http.Client
}

var _ Channel = (*Slack)(nil)

// NewSlackChannel validates the bot token. httpClient may be nil.
func NewSlackChannel(botToken string, httpClient *http.Client) (*Slack, error) {
	if !strings.HasPrefix(botToken, "xoxb-") || len(botToken) < 12 {
		return nil, errors.New("notify: slack token is empty or not a bot token (xoxb-...)")
	}
	if httpClient == nil {
		httpClient = newHTTPClient()
	}
	return &Slack{token: botToken, base: slackAPI, client: httpClient}, nil
}

func (s *Slack) Scheme() string { return slackScheme }

func (s *Slack) ValidTarget(target string) error { return validSlackTarget(target) }

type slackPost struct {
	Channel     string `json:"channel"`
	Text        string `json:"text"`
	Mrkdwn      bool   `json:"mrkdwn"`
	UnfurlLinks bool   `json:"unfurl_links"`
	UnfurlMedia bool   `json:"unfurl_media"`
	LinkNames   bool   `json:"link_names"`
}

// slack API errors that retrying cannot fix, with the HTTP-like status they are reported as.
var slackPermanent = map[string]int{
	"invalid_auth": 401, "not_authed": 401, "account_inactive": 401, "token_revoked": 401, "token_expired": 401,
	"missing_scope": 403, "no_permission": 403, "restricted_action": 403, "team_access_not_granted": 403,
	"channel_not_found": 404, "not_in_channel": 403, "is_archived": 403,
	"msg_too_long": 400, "no_text": 400, "invalid_arguments": 400, "invalid_json": 400, "invalid_charset": 400,
}

// slack API errors that are transient.
var slackTransient = map[string]bool{
	"ratelimited": true, "rate_limited": true, "internal_error": true, "fatal_error": true,
	"service_unavailable": true, "request_timeout": true,
}

func (s *Slack) Send(ctx context.Context, channel string, msg Message) error {
	body, err := json.Marshal(slackPost{Channel: channel, Text: formatSlack(msg), Mrkdwn: true})
	if err != nil {
		return fmt.Errorf("encode message: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.base+"/chat.postMessage", bytes.NewReader(body))
	if err != nil {
		return errors.New("build request: " + stripSecret(err.Error(), s.token))
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	resp, err := s.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return &SendError{Err: redactNetErr(err, s.token)}
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, maxRespBody))

	switch code := resp.StatusCode; {
	case code == http.StatusTooManyRequests:
		return &SendError{Status: code, RetryAfter: retryAfterHeader(resp.Header), Err: errors.New("rate limited (429)")}
	case code >= 500:
		return &SendError{Status: code, Err: fmt.Errorf("server error %d", code)}
	case code != http.StatusOK:
		return &SendError{Status: code, Permanent: true, Err: fmt.Errorf("slack responded %d: %s", code, snippet(data))}
	}
	var out struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return &SendError{Status: http.StatusOK, Err: errors.New("slack: unreadable response")}
	}
	if out.OK {
		return nil
	}
	e := clBase(out.Error)
	if len(e) > 64 {
		e = e[:64]
	}
	switch {
	case slackTransient[out.Error]:
		st := http.StatusServiceUnavailable
		if out.Error == "ratelimited" || out.Error == "rate_limited" {
			st = http.StatusTooManyRequests
		}
		return &SendError{Status: st, RetryAfter: retryAfterHeader(resp.Header), Err: fmt.Errorf("slack: %s", e)}
	case slackPermanent[out.Error] != 0:
		return &SendError{Status: slackPermanent[out.Error], Permanent: true, Err: fmt.Errorf("slack: %s", e)}
	default: // unknown API errors: do not hammer the API
		return &SendError{Status: http.StatusBadRequest, Permanent: true, Err: fmt.Errorf("slack: %s", e)}
	}
}

// retryAfterHeader parses a Retry-After header given in seconds.
func retryAfterHeader(h http.Header) time.Duration {
	n, err := strconv.Atoi(strings.TrimSpace(h.Get("Retry-After")))
	if err != nil || n <= 0 {
		return 0
	}
	return time.Duration(n) * time.Second
}

// redactNetErr drops the request URL (which may carry a token) from a transport error.
func redactNetErr(err error, secret string) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	return errors.New("network: " + stripSecret(err.Error(), secret))
}

// --- formatting (Slack mrkdwn) -----------------------------------------------------------------

// formatSlack renders the message as mrkdwn. Every untrusted string is escaped for & < > (which
// also neutralises <!channel>, <!here>, <@U...> and <url|label> injection), "@" gets a zero-width
// space, and formatting characters are guarded so that a host name cannot bold or strike a line.
// Whole lines are dropped to stay below slackMaxText.
func formatSlack(m Message) string {
	var out []string
	used := 0
	for _, l := range m.Lines {
		l = fitLine(l, slackMaxLineText)
		var b strings.Builder
		for _, s := range l {
			switch s.Kind {
			case SpanBold:
				if strings.TrimSpace(s.Text) != "" {
					b.WriteString("*" + slackEsc(strings.TrimSpace(s.Text)) + "*")
				}
			case SpanCode:
				b.WriteString("`" + slackCodeEsc(s.Text) + "`")
			case SpanLink:
				b.WriteString("<" + slackURL(s.URL) + "|" + strings.ReplaceAll(slackEsc(s.Text), "|", "¦") + ">")
			default:
				b.WriteString(slackEsc(s.Text))
			}
		}
		line := b.String()
		n := utf8.RuneCountInString(line) + 1
		if used+n > slackMaxText-len(truncatedNote) {
			out = append(out, truncatedNote)
			break
		}
		out = append(out, line)
		used += n
	}
	return strings.Join(out, "\n")
}

func slackBasicEsc(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// slackEsc escapes untrusted plain text.
func slackEsc(s string) string {
	s = slackBasicEsc(neutralAt(s))
	rs := []rune(s)
	var b strings.Builder
	for i, r := range rs {
		switch r {
		case '*', '~', '`':
			b.WriteString(zwsp + string(r) + zwsp)
		case '_':
			inWord := i > 0 && i < len(rs)-1 && isWordRune(rs[i-1]) && isWordRune(rs[i+1])
			if inWord {
				b.WriteRune(r)
			} else {
				b.WriteString(zwsp + "_" + zwsp)
			}
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func isWordRune(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }

// slackCodeEsc escapes the content of an inline code span: no backtick can end the span.
func slackCodeEsc(s string) string {
	return slackBasicEsc(strings.ReplaceAll(s, "`", "ˋ"))
}

// slackURL makes an absolute URL safe inside <url|label>.
func slackURL(u string) string {
	return strings.NewReplacer("|", "%7C", "<", "%3C", ">", "%3E", " ", "%20", "&", "&amp;").Replace(u)
}
