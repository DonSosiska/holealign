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
	"slices"
	"strings"
	"time"
	"unicode"
)

// Matrix is the Matrix channel: it sends m.room.message events to rooms (docs/contracts.md §5).
// Destinations are room IDs "!id:server" (or "matrix:!id:server"); the bare form is the default.
type Matrix struct {
	homeserver string
	token      string
	client     *http.Client
}

var _ Channel = (*Matrix)(nil)

func init() { registerChannel(matrixScheme, validMatrixTarget) }

// NewMatrixChannel validates the homeserver URL and returns the channel. httpClient may be nil
// (a client with a 30 s timeout is used then).
func NewMatrixChannel(homeserver, accessToken string, httpClient *http.Client) (*Matrix, error) {
	hs := strings.TrimRight(strings.TrimSpace(homeserver), "/")
	if hs == "" {
		return nil, errors.New("notify: matrix homeserver is empty")
	}
	u, err := url.Parse(hs)
	if err != nil {
		return nil, fmt.Errorf("notify: matrix homeserver: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("notify: matrix homeserver must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("notify: matrix homeserver has no host")
	}
	if accessToken == "" {
		return nil, errors.New("notify: matrix access token is empty")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Matrix{homeserver: hs, token: accessToken, client: httpClient}, nil
}

func (m *Matrix) Scheme() string { return matrixScheme }

func (m *Matrix) ValidTarget(target string) error { return validMatrixTarget(target) }

const maxMatrixIDLen = 255

func validMatrixTarget(t string) error {
	if len(t) > maxMatrixIDLen {
		return fmt.Errorf("a Matrix ID is longer than %d characters", maxMatrixIDLen)
	}
	if t == "" || (t[0] != '!' && t[0] != '#') {
		return errors.New("not a Matrix room ID (expected !id:server)")
	}
	if i := strings.IndexByte(t, ':'); i < 2 || i == len(t)-1 {
		return errors.New("not a Matrix room ID (expected !id:server)")
	}
	if strings.IndexFunc(t, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return errors.New("a Matrix ID must not contain whitespace or control characters")
	}
	return nil
}

// message is the content of an m.room.message event.
type message struct {
	MsgType       string `json:"msgtype"`
	Body          string `json:"body"`
	Format        string `json:"format"`
	FormattedBody string `json:"formatted_body"`
	// Mentions is always the empty object: nothing in an alert may ping users or the room.
	Mentions struct{} `json:"m.mentions"`
}

func newMatrixMessage(msg Message) message {
	mt := "m.text"
	if msg.Notice {
		mt = "m.notice"
	}
	plain, h := formatMatrix(msg)
	return message{MsgType: mt, Body: plain, Format: "org.matrix.custom.html", FormattedBody: h}
}

// Send PUTs the message once. The transaction ID is msg.ID, which the Notifier keeps fixed across
// attempts so the homeserver can deduplicate.
func (m *Matrix) Send(ctx context.Context, room string, msg Message) error {
	body, err := json.Marshal(newMatrixMessage(msg))
	if err != nil {
		return fmt.Errorf("encode message: %w", err)
	}
	endpoint := m.homeserver + "/_matrix/client/v3/rooms/" + url.PathEscape(room) +
		"/send/m.room.message/" + url.PathEscape(msg.ID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+m.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return &SendError{Err: fmt.Errorf("network: %w", err)}
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, maxRespBody))

	switch code := resp.StatusCode; {
	case code >= 200 && code < 300:
		return nil
	case code == http.StatusTooManyRequests:
		return &SendError{Status: code, RetryAfter: matrixRetryAfter(data), Err: errors.New("rate limited (429)")}
	case code >= 500:
		return &SendError{Status: code, Err: fmt.Errorf("server error %d", code)}
	default:
		return &SendError{Status: code, Permanent: true, Err: fmt.Errorf("matrix responded %d: %s", code, snippet(data))}
	}
}

// matrixRetryAfter extracts retry_after_ms from a Matrix error body.
func matrixRetryAfter(body []byte) time.Duration {
	var e struct {
		RetryAfterMS int64 `json:"retry_after_ms"`
	}
	if json.Unmarshal(body, &e) != nil || e.RetryAfterMS <= 0 {
		return 0
	}
	return time.Duration(e.RetryAfterMS) * time.Millisecond
}

// formatMatrix returns the plain-text body and the HTML formatted_body. Whole lines are dropped
// (never cut mid-tag) once either body would exceed maxBodyBytes, and a truncation note is appended.
// The limit applies to the bodies as sent, i.e. after HTML escaping, and also holds on the fallback
// path for one huge line.
func formatMatrix(m Message) (string, string) {
	plain := make([]string, len(m.Lines))
	htmls := make([]string, len(m.Lines))
	for i, l := range m.Lines {
		var p, h strings.Builder
		for _, s := range l {
			p.WriteString(s.Text)
			switch s.Kind {
			case SpanBold:
				h.WriteString("<b>" + esc(s.Text) + "</b>")
			case SpanCode:
				h.WriteString("<code>" + esc(s.Text) + "</code>")
			case SpanLink:
				h.WriteString(`<a href="` + esc(s.URL) + `">` + esc(s.Text) + `</a>`)
			default:
				h.WriteString(esc(s.Text))
			}
		}
		plain[i], htmls[i] = p.String(), h.String()
	}
	return fitMatrixLines(plain, htmls)
}

func fitMatrixLines(linesPlain, linesHTML []string) (string, string) {
	const budget = maxBodyBytes - 64 // room for the truncation note
	pl, hl := 0, 0
	keep := 0
	for i := range linesPlain {
		p, h := len(linesPlain[i])+1, len(linesHTML[i])+len("<br>")
		if pl+p > budget || hl+h > budget {
			break
		}
		pl, hl = pl+p, hl+h
		keep = i + 1
	}
	plain, formatted := linesPlain[:keep], linesHTML[:keep]
	if keep < len(linesPlain) {
		if keep == 0 { // a single huge line: fall back to escaped truncated plain text
			t := fitEscaped(linesPlain[0], budget)
			plain, formatted = []string{t}, []string{esc(t)}
		}
		plain = append(slices.Clone(plain), truncatedNote)
		formatted = append(slices.Clone(formatted), truncatedNote)
	}
	p, h := strings.Join(plain, "\n"), strings.Join(formatted, "<br>")
	if len(p) > maxBodyBytes || len(h) > maxBodyBytes { // cannot happen with the accounting above; never send more
		t := fitEscaped(p, budget)
		p, h = t+truncatedNote, esc(t)+truncatedNote
	}
	return p, h
}

// fitEscaped cuts s so that both s and its HTML-escaped form are at most max bytes.
func fitEscaped(s string, max int) string {
	t := cutBytes(s, max)
	for len(esc(t)) > max && len(t) > 0 {
		t = cutBytes(t, len(t)*3/4)
	}
	return t
}
