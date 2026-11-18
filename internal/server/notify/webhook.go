package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	webhookScheme = "webhook"
	// WebhookSchemaVersion is the "version" field of the payload. A change that is not backward
	// compatible (a field removed or its meaning changed) increments it.
	WebhookSchemaVersion = 1
	// WebhookSignatureHeader and WebhookEventIDHeader are the headers every delivery carries.
	WebhookSignatureHeader = "X-Holealign-Signature"
	WebhookEventIDHeader   = "X-Holealign-Event-Id"

	webhookMinSecret  = 16
	webhookMaxText    = 16 << 10
	webhookMaxHeaders = 16
	webhookMaxHeaderV = 1024
)

func init() { registerChannel(webhookScheme, validWebhookTarget) }

func validWebhookTarget(t string) error { return ValidName(t) }

// WebhookPayload is the JSON body of a delivery (schema version 1).
type WebhookPayload struct {
	Version int            `json:"version"`
	ID      string         `json:"id"`      // message ID; the same for every retry of one message
	Kind    string         `json:"kind"`    // kind of the first event; "summary" for a burst summary
	SentAt  string         `json:"sent_at"` // RFC 3339, UTC
	Title   string         `json:"title"`   // first line of the message, plain text
	Text    string         `json:"text"`    // the whole message as plain text
	Events  []MessageEvent `json:"events"`
}

// WebhookSignature returns the value of the X-Holealign-Signature header for a body sent at unix
// time t: "t=<unix>,v1=<hex HMAC-SHA256(secret, "<t>.<body>")>".
func WebhookSignature(secret string, t int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(t, 10)))
	mac.Write([]byte{'.'})
	mac.Write(body)
	return "t=" + strconv.FormatInt(t, 10) + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}

// VerifyWebhookSignature checks the header value against the body: constant-time comparison, and
// the timestamp must be within tolerance of now (the documented receiver rule is 5 minutes).
func VerifyWebhookSignature(secret, header string, body []byte, now time.Time, tolerance time.Duration) error {
	var ts, sig string
	for _, part := range strings.Split(header, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch k {
		case "t":
			ts = v
		case "v1":
			sig = v
		}
	}
	t, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || sig == "" {
		return errors.New("malformed signature header")
	}
	if d := now.Sub(time.Unix(t, 0)); d > tolerance || d < -tolerance {
		return errors.New("timestamp outside the tolerance")
	}
	want := WebhookSignature(secret, t, body)
	_, wantSig, _ := strings.Cut(want, ",v1=")
	if !hmac.Equal([]byte(wantSig), []byte(strings.ToLower(sig))) {
		return errors.New("signature mismatch")
	}
	return nil
}

// ValidWebhookURL checks the URL of a generic webhook: https (http only with allowHTTP), a host, no
// user info. The URL may point anywhere: it comes from the config file, which only the operator
// edits. The error never contains the URL.
func ValidWebhookURL(raw string, allowHTTP bool) error {
	schemes := []string{"https"}
	if allowHTTP {
		schemes = append(schemes, "http")
	}
	_, err := parseHookURL(raw, schemes...)
	if err != nil && !allowHTTP && strings.HasPrefix(strings.ToLower(raw), "http://") {
		return errors.New("URL scheme must be https (set allow_http: true to permit plain http)")
	}
	return err
}

var headerNameRe = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$")

// reservedHeaders cannot be set through the config: they would break the signature scheme or the
// framing of the request.
var reservedHeaders = map[string]bool{
	"host": true, "content-length": true, "content-type": true, "transfer-encoding": true, "connection": true,
	"upgrade": true, "te": true, "trailer": true, "expect": true,
}

// ValidWebhookHeaders checks custom headers: valid names, values without control characters, and no
// reserved or X-Holealign-* names. Errors name the header, never its value.
func ValidWebhookHeaders(h map[string]string) error {
	if len(h) > webhookMaxHeaders {
		return fmt.Errorf("too many headers (max %d)", webhookMaxHeaders)
	}
	names := make([]string, 0, len(h))
	for k := range h {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		v := h[k]
		lk := strings.ToLower(k)
		switch {
		case !headerNameRe.MatchString(k):
			return fmt.Errorf("header %q: invalid name", clip(k, 40))
		case reservedHeaders[lk] || strings.HasPrefix(lk, "x-holealign-"):
			return fmt.Errorf("header %q is set by Holealign and cannot be overridden", k)
		case len(v) > webhookMaxHeaderV:
			return fmt.Errorf("header %q: value too long", k)
		}
		for _, r := range v {
			if r < 0x20 && r != '\t' || r == 0x7f || r > 0x7e {
				return fmt.Errorf("header %q: value must be printable ASCII (no control characters or newlines)", k)
			}
		}
	}
	return nil
}

// WebhookEndpoint is one configured generic webhook.
type WebhookEndpoint struct {
	URL       string
	Secret    string // HMAC key, at least 16 bytes
	Headers   map[string]string
	AllowHTTP bool
}

// Webhook delivers a signed JSON document to configured URLs.
type Webhook struct {
	eps    map[string]WebhookEndpoint
	client *http.Client
	now    func() time.Time
}

var _ Channel = (*Webhook)(nil)

// NewWebhookChannel takes the endpoints by name. httpClient may be nil.
func NewWebhookChannel(eps map[string]WebhookEndpoint, httpClient *http.Client) (*Webhook, error) {
	if len(eps) == 0 {
		return nil, errors.New("notify: webhook has no endpoints")
	}
	cp := make(map[string]WebhookEndpoint, len(eps))
	for name, e := range eps {
		if err := ValidName(name); err != nil {
			return nil, fmt.Errorf("notify: webhook %q: %w", clip(name, 40), err)
		}
		if err := ValidWebhookURL(e.URL, e.AllowHTTP); err != nil {
			return nil, fmt.Errorf("notify: webhook %q: %w", name, err)
		}
		if len(e.Secret) < webhookMinSecret {
			return nil, fmt.Errorf("notify: webhook %q: signing secret is empty or shorter than %d bytes", name, webhookMinSecret)
		}
		if err := ValidWebhookHeaders(e.Headers); err != nil {
			return nil, fmt.Errorf("notify: webhook %q: %w", name, err)
		}
		cp[name] = e
	}
	return &Webhook{eps: cp, client: noRedirect(httpClient), now: time.Now}, nil
}

func (w *Webhook) Scheme() string { return webhookScheme }

func (w *Webhook) ValidTarget(target string) error { return validWebhookTarget(target) }

// BuildWebhookPayload builds the document for msg, sent at the given time.
func BuildWebhookPayload(msg Message, sent time.Time) WebhookPayload {
	kind := string(msg.Kind)
	if kind == "" {
		kind = "summary"
	}
	title := ""
	var text []string
	for i, l := range msg.Lines {
		p := l.plain()
		if i == 0 {
			title = cutRunes(p, 300)
		}
		text = append(text, p)
	}
	events := msg.Events
	if events == nil {
		events = []MessageEvent{}
	}
	return WebhookPayload{
		Version: WebhookSchemaVersion, ID: msg.ID, Kind: kind, SentAt: sent.UTC().Format(time.RFC3339),
		Title: title, Text: cutBytes(strings.Join(text, "\n"), webhookMaxText), Events: events,
	}
}

func (w *Webhook) Send(ctx context.Context, name string, msg Message) error {
	ep, ok := w.eps[name]
	if !ok {
		return &SendError{Permanent: true, Err: fmt.Errorf("webhook %q is not configured", clip(name, 40))}
	}
	secrets := append(hookSecrets(ep.URL), ep.Secret)
	for _, v := range ep.Headers {
		if len(v) >= 6 {
			secrets = append(secrets, v)
		}
	}
	now := w.now()
	body, err := json.Marshal(BuildWebhookPayload(msg, now))
	if err != nil {
		return fmt.Errorf("encode message: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.URL, bytes.NewReader(body))
	if err != nil {
		return errors.New("build request: " + stripAll(err.Error(), secrets))
	}
	for k, v := range ep.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "holealign")
	req.Header.Set(WebhookSignatureHeader, WebhookSignature(ep.Secret, now.Unix(), body))
	req.Header.Set(WebhookEventIDHeader, msg.ID)

	resp, err := w.client.Do(req)
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
	return httpFailure("webhook", resp.StatusCode, resp.Header, data, 0, secrets)
}
