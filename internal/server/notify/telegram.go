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
	"strconv"
	"strings"
	"time"
)

// telegramAPI is the Bot API base. It is a constant on purpose: nothing in the config or the web
// UI can point the server at another host. Tests set Telegram.base directly.
const telegramAPI = "https://api.telegram.org"

const (
	telegramScheme = "telegram"
	// telegramMaxText is the visible-character budget of one message. The API limit is 4096; the
	// margin covers the zero-width spaces that neutralise "@" mentions.
	telegramMaxText = 3900
)

var (
	telegramTokenRe  = regexp.MustCompile(`^[0-9]{3,}:[A-Za-z0-9_-]{16,}$`)
	telegramTargetRe = regexp.MustCompile(`^(-?[0-9]{1,19})(?:/([0-9]{1,10}))?$`)
)

func init() { registerChannel(telegramScheme, validTelegramTarget) }

// parseTelegramTarget parses "<chat_id>" or "<chat_id>/<message_thread_id>".
func parseTelegramTarget(t string) (chat int64, thread int, err error) {
	m := telegramTargetRe.FindStringSubmatch(t)
	if m == nil {
		return 0, 0, errors.New("not a Telegram chat (expected a numeric chat id such as -1001234567890, optionally /<topic id>)")
	}
	chat, err = strconv.ParseInt(m[1], 10, 64)
	if err != nil || chat == 0 {
		return 0, 0, errors.New("invalid Telegram chat id")
	}
	if m[2] != "" {
		thread, err = strconv.Atoi(m[2])
		if err != nil || thread <= 0 {
			return 0, 0, errors.New("invalid Telegram topic id (message_thread_id must be positive)")
		}
	}
	return chat, thread, nil
}

func validTelegramTarget(t string) error {
	_, _, err := parseTelegramTarget(t)
	return err
}

// Telegram sends messages with the Bot API sendMessage method. The bot token is part of the request
// URL, so URLs are never logged and never included in errors.
type Telegram struct {
	token  string
	base   string
	client *http.Client
}

var _ Channel = (*Telegram)(nil)

// NewTelegramChannel validates the bot token. httpClient may be nil.
func NewTelegramChannel(botToken string, httpClient *http.Client) (*Telegram, error) {
	if !telegramTokenRe.MatchString(botToken) {
		return nil, errors.New("notify: telegram bot token is empty or malformed (expected 123456:ABC...)")
	}
	if httpClient == nil {
		httpClient = newHTTPClient()
	}
	return &Telegram{token: botToken, base: telegramAPI, client: httpClient}, nil
}

func (t *Telegram) Scheme() string { return telegramScheme }

func (t *Telegram) ValidTarget(target string) error { return validTelegramTarget(target) }

type telegramPreview struct {
	IsDisabled bool `json:"is_disabled"`
}

type telegramSend struct {
	ChatID              int64           `json:"chat_id"`
	MessageThreadID     int             `json:"message_thread_id,omitempty"`
	Text                string          `json:"text"`
	ParseMode           string          `json:"parse_mode"`
	LinkPreviewOptions  telegramPreview `json:"link_preview_options"`
	DisableNotification bool            `json:"disable_notification,omitempty"`
}

func (t *Telegram) Send(ctx context.Context, target string, msg Message) error {
	chat, thread, err := parseTelegramTarget(target)
	if err != nil {
		return &SendError{Permanent: true, Err: err}
	}
	body, err := json.Marshal(telegramSend{
		ChatID: chat, MessageThreadID: thread, Text: formatTelegram(msg), ParseMode: "HTML",
		LinkPreviewOptions: telegramPreview{IsDisabled: true}, DisableNotification: msg.Notice,
	})
	if err != nil {
		return fmt.Errorf("encode message: %w", err)
	}
	// The token is in the URL path: never log or return this URL.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.base+"/bot"+t.token+"/sendMessage", bytes.NewReader(body))
	if err != nil {
		return errors.New("build request: " + stripSecret(err.Error(), t.token))
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return &SendError{Err: redactNetErr(err, t.token)}
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, maxRespBody))

	var out struct {
		OK          bool   `json:"ok"`
		ErrorCode   int    `json:"error_code"`
		Description string `json:"description"`
		Parameters  struct {
			RetryAfter int `json:"retry_after"`
		} `json:"parameters"`
	}
	var uerr error
	if len(data) > 0 {
		uerr = json.Unmarshal(data, &out)
	}
	desc := clBase(stripSecret(out.Description, t.token))
	if len(desc) > 120 {
		desc = desc[:120]
	}

	switch code := resp.StatusCode; {
	case code >= 200 && code < 300 && uerr != nil:
		return &SendError{Status: code, Permanent: true, Err: fmt.Errorf("telegram: invalid response JSON: %w", uerr)}
	case code >= 200 && code < 300 && (out.OK || len(data) == 0):
		return nil
	case code >= 200 && code < 300:
		return &SendError{Status: code, Permanent: true, Err: fmt.Errorf("telegram: not ok: %s", desc)}
	case code == http.StatusTooManyRequests:
		return &SendError{Status: code, RetryAfter: time.Duration(max(out.Parameters.RetryAfter, 0)) * time.Second,
			Err: errors.New("rate limited (429)")}
	case code >= 500:
		return &SendError{Status: code, Err: fmt.Errorf("server error %d", code)}
	default: // 400 chat not found, 401 bad token, 403 bot blocked or kicked, ...
		return &SendError{Status: code, Permanent: true, Err: fmt.Errorf("telegram responded %d: %s", code, desc)}
	}
}

// --- formatting (Telegram HTML subset: b, code, a) ---------------------------------------------

// formatTelegram renders the message for parse_mode HTML. Only <b>, <code> and <a href> are
// produced; every untrusted string is escaped for & < > (and " in attributes), "@" gets a zero-width
// space. One message holds at most telegramMaxText visible characters: whole lines are dropped with
// a truncation note, and a single over-long line is cut before its markup is built, so no tag or
// entity is ever split.
func formatTelegram(m Message) string {
	lines := fitLines(m.Lines, telegramMaxText)
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		var b strings.Builder
		for _, s := range l {
			switch s.Kind {
			case SpanBold:
				b.WriteString("<b>" + tgEsc(neutralAt(s.Text)) + "</b>")
			case SpanCode:
				b.WriteString("<code>" + tgEsc(s.Text) + "</code>")
			case SpanLink:
				b.WriteString(`<a href="` + tgAttr(s.URL) + `">` + tgEsc(neutralAt(s.Text)) + `</a>`)
			default:
				b.WriteString(tgEsc(neutralAt(s.Text)))
			}
		}
		out = append(out, b.String())
	}
	return strings.Join(out, "\n")
}

func tgEsc(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func tgAttr(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}
