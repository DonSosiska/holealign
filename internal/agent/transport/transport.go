// Package transport is the agent's HTTP client for the server API (docs/contracts.md §1).
package transport

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/DonSosiska/panoptes/internal/model"
)

// ErrUnauthorized is returned when the server answers 401.
var ErrUnauthorized = errors.New("transport: unauthorized (401)")

// ErrEnrollConflict is returned when enrollment answers 409: the host already
// exists and the previous agent key is required (or an operator must allow re-enroll).
var ErrEnrollConflict = errors.New("transport: enroll conflict (409): host exists; previous key required")

// Bounds for the server's Retry-After on 429.
const (
	minRetryAfter     = 5 * time.Second
	maxRetryAfter     = 15 * time.Minute
	defaultRetryAfter = 30 * time.Second
)

// RateLimitedError is returned on HTTP 429. It is not retried by the transport backoff loop;
// the caller decides when to try again.
type RateLimitedError struct {
	RetryAfter time.Duration // clamped to [5 s, 15 min]
}

func (e *RateLimitedError) Error() string {
	return fmt.Sprintf("transport: rate limited by server (429), retry in %s", e.RetryAfter.Round(time.Second))
}

// parseRetryAfter reads delta-seconds or an HTTP date and clamps the result.
func parseRetryAfter(h string, now time.Time) time.Duration {
	d := defaultRetryAfter
	h = strings.TrimSpace(h)
	if secs, err := strconv.ParseInt(h, 10, 64); err == nil {
		switch {
		case secs < 0:
			d = minRetryAfter
		case secs > int64(maxRetryAfter/time.Second):
			d = maxRetryAfter
		default:
			d = time.Duration(secs) * time.Second
		}
	} else if t, err := http.ParseTime(h); err == nil {
		d = t.Sub(now)
	}
	return min(max(d, minRetryAfter), maxRetryAfter)
}

// Credentials are the per-agent credentials returned by enrollment.
type Credentials struct {
	AgentID  string `json:"agent_id"`
	AgentKey string `json:"agent_key"`
}

// Client talks to the Panoptes server.
type Client struct {
	BaseURL string
	Key     string // agent key; empty before enrollment

	HTTP *http.Client
	// AllowInsecureHTTP permits an http:// BaseURL (config allow_insecure_http).
	AllowInsecureHTTP bool
	InventoryTimeout  time.Duration
	RequestTimeout    time.Duration

	// MaxAttempts bounds attempts per call (0 = retry until ctx is done).
	MaxAttempts int
	BaseBackoff time.Duration
	MaxBackoff  time.Duration
	sleep       func(ctx context.Context, d time.Duration) error
}

// New creates a client with the contract defaults (30 s timeout, 5 min for inventory, backoff cap 5 min).
func New(baseURL, key string) *Client {
	baseURL = strings.TrimRight(baseURL, "/")
	return &Client{
		BaseURL:          baseURL,
		Key:              key,
		HTTP:             newHTTPClient(baseURL),
		InventoryTimeout: 5 * time.Minute,
		RequestTimeout:   30 * time.Second,
		BaseBackoff:      2 * time.Second,
		MaxBackoff:       5 * time.Minute,
		sleep:            sleepCtx,
	}
}

// NewWithHTTP creates a client that sends its requests through hc instead of a network
// transport (used by the server's built-in local agent: hc dispatches straight to the API
// handler in memory). Redirects are still never followed.
func NewWithHTTP(baseURL, key string, hc *http.Client) *Client {
	c := New(baseURL, key)
	cp := *hc
	cp.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	c.HTTP = &cp
	return c
}

// newHTTPClient builds a client that never follows redirects (a redirect could
// re-send the bearer key or the body elsewhere) and requires TLS 1.2+.
func newHTTPClient(baseURL string) *http.Client {
	var tr *http.Transport
	if dt, ok := http.DefaultTransport.(*http.Transport); ok {
		tr = dt.Clone()
	} else {
		tr = &http.Transport{Proxy: http.ProxyFromEnvironment}
	}
	if tr.TLSClientConfig == nil {
		tr.TLSClientConfig = &tls.Config{}
	}
	tr.TLSClientConfig.MinVersion = tls.VersionTLS12
	if req, err := http.NewRequest(http.MethodGet, baseURL, nil); err == nil && tr.Proxy != nil {
		if pu, err := tr.Proxy(req); err == nil && pu != nil {
			slog.Info("using proxy from environment", "proxy", redactURL(pu))
		}
	}
	return &http.Client{
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// redactURL renders a URL without userinfo, path or query.
func redactURL(u *url.URL) string {
	return (&url.URL{Scheme: u.Scheme, Host: u.Host}).String()
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Enroll registers the agent. When the client holds a previous agent key it is
// sent as the bearer token so the server can verify the host's identity.
func (c *Client) Enroll(ctx context.Context, req model.EnrollRequest) (model.EnrollResponse, error) {
	var resp model.EnrollResponse
	body, err := json.Marshal(req)
	if err != nil {
		return resp, err
	}
	err = c.do(ctx, "/api/v1/enroll", body, false, c.RequestTimeout, &resp)
	return resp, err
}

// Checkin sends the heartbeat.
func (c *Client) Checkin(ctx context.Context, req model.CheckinRequest) (model.CheckinResponse, error) {
	var resp model.CheckinResponse
	body, err := json.Marshal(req)
	if err != nil {
		return resp, err
	}
	err = c.do(ctx, "/api/v1/checkin", body, false, c.RequestTimeout, &resp)
	return resp, err
}

// UploadInventory sends the payload gzip-compressed.
func (c *Client) UploadInventory(ctx context.Context, p model.InventoryPayload) error {
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	return c.do(ctx, "/api/v1/inventory", buf.Bytes(), true, c.InventoryTimeout, nil)
}

// do POSTs body, retrying network errors and 5xx with backoff. Other failures return immediately.
func (c *Client) do(ctx context.Context, path string, body []byte, gz bool, timeout time.Duration, out any) error {
	for attempt := 0; ; attempt++ {
		err, retry := c.once(ctx, path, body, gz, timeout, out)
		if err == nil {
			return nil
		}
		if !retry || ctx.Err() != nil {
			return err
		}
		if c.MaxAttempts > 0 && attempt+1 >= c.MaxAttempts {
			return fmt.Errorf("giving up after %d attempts: %w", attempt+1, err)
		}
		if serr := c.sleep(ctx, c.backoff(attempt)); serr != nil {
			return fmt.Errorf("%w (last error: %v)", serr, err)
		}
	}
}

func (c *Client) backoff(attempt int) time.Duration {
	if attempt > 20 {
		attempt = 20
	}
	d := c.BaseBackoff << uint(attempt)
	if d <= 0 || d > c.MaxBackoff {
		d = c.MaxBackoff
	}
	// jitter in [d/2, d]
	return d/2 + time.Duration(rand.Int64N(int64(d/2)+1))
}

func (c *Client) once(ctx context.Context, path string, body []byte, gz bool, timeout time.Duration, out any) (error, bool) {
	if err := c.checkURL(); err != nil {
		return err, false
	}
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return err, false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if gz {
		req.Header.Set("Content-Encoding", "gzip")
	}
	if c.Key != "" {
		req.Header.Set("Authorization", "Bearer "+c.Key)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", path, err), true
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return fmt.Errorf("POST %s: read body: %w", path, err), true
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return ErrUnauthorized, false
	case resp.StatusCode == http.StatusTooManyRequests:
		return &RateLimitedError{RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"), time.Now())}, false
	case resp.StatusCode == http.StatusConflict && path == "/api/v1/enroll":
		return ErrEnrollConflict, false
	case resp.StatusCode >= 500:
		return fmt.Errorf("POST %s: server error %d: %s", path, resp.StatusCode, errMsg(data)), true
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return fmt.Errorf("POST %s: unexpected redirect (status %d) refused", path, resp.StatusCode), false
	case resp.StatusCode >= 300:
		return fmt.Errorf("POST %s: status %d: %s", path, resp.StatusCode, errMsg(data)), false
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("POST %s: decode response: %w", path, err), false
		}
	}
	return nil, false
}

// checkURL enforces https (unless allowed) and rejects credentials in the URL.
func (c *Client) checkURL() error {
	u, err := url.Parse(c.BaseURL)
	if err != nil || u.Host == "" {
		return fmt.Errorf("transport: invalid server URL")
	}
	if u.User != nil {
		return errors.New("transport: server URL must not contain credentials")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !c.AllowInsecureHTTP {
			return errors.New("transport: http:// server URL refused (set allow_insecure_http to override)")
		}
	default:
		return fmt.Errorf("transport: unsupported scheme %q", u.Scheme)
	}
	return nil
}

func errMsg(data []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(data, &e) == nil && e.Error != "" {
		return e.Error
	}
	s := strings.TrimSpace(string(data))
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

const credentialsFile = "credentials.json"

// CredentialsPath is the credentials file inside state_dir.
func CredentialsPath(stateDir string) string { return filepath.Join(stateDir, credentialsFile) }

// LoadCredentials reads state_dir/credentials.json. The error wraps os.ErrNotExist if absent.
func LoadCredentials(stateDir string) (Credentials, error) {
	var c Credentials
	data, err := os.ReadFile(filepath.Join(stateDir, credentialsFile))
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return c, fmt.Errorf("parse credentials: %w", err)
	}
	if c.AgentID == "" || c.AgentKey == "" {
		return c, fmt.Errorf("credentials file incomplete")
	}
	return c, nil
}

// SaveCredentials writes state_dir/credentials.json (0600, dir 0700) atomically.
func SaveCredentials(stateDir string, c Credentials) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(stateDir, ".credentials-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(stateDir, credentialsFile))
}
