// Package transport is the agent's HTTP client for the server API (docs/contracts.md §1).
package transport

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"panoptes/internal/model"
)

// ErrUnauthorized is returned when the server answers 401.
var ErrUnauthorized = errors.New("transport: unauthorized (401)")

// Credentials are the per-agent credentials returned by enrollment.
type Credentials struct {
	AgentID  string `json:"agent_id"`
	AgentKey string `json:"agent_key"`
}

// Client talks to the Panoptes server.
type Client struct {
	BaseURL string
	Key     string // agent key; empty before enrollment

	HTTP             *http.Client
	InventoryTimeout time.Duration
	RequestTimeout   time.Duration

	// MaxAttempts bounds attempts per call (0 = retry until ctx is done).
	MaxAttempts int
	BaseBackoff time.Duration
	MaxBackoff  time.Duration
	sleep       func(ctx context.Context, d time.Duration) error
}

// New creates a client with the contract defaults (30 s timeout, 5 min for inventory, backoff cap 5 min).
func New(baseURL, key string) *Client {
	return &Client{
		BaseURL:          strings.TrimRight(baseURL, "/"),
		Key:              key,
		HTTP:             &http.Client{},
		InventoryTimeout: 5 * time.Minute,
		RequestTimeout:   30 * time.Second,
		BaseBackoff:      2 * time.Second,
		MaxBackoff:       5 * time.Minute,
		sleep:            sleepCtx,
	}
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

// Enroll registers the agent. It does not send the bearer key.
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
	if c.Key != "" && path != "/api/v1/enroll" {
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
	case resp.StatusCode >= 500:
		return fmt.Errorf("POST %s: server error %d: %s", path, resp.StatusCode, errMsg(data)), true
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
