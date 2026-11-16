// Package notify delivers Panoptes events to Matrix rooms (docs/contracts.md §5, §6).
package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"panoptes/internal/model"
	"panoptes/internal/server/core"
)

// Config is the matrix section of the server configuration. AccessToken is already
// resolved from its environment variable by the caller.
type Config struct {
	Homeserver   string
	AccessToken  string
	DefaultRooms []string // used when no label route matches
	Routes       []Route  // from the config file
}

// Route maps a host label to Matrix room IDs.
type Route struct {
	Label string
	Rooms []string
}

// RouteSource supplies routes edited in the web UI (stored in the DB). May be nil.
type RouteSource interface {
	MatrixRoutes(ctx context.Context) ([]Route, error)
}

const (
	burstThreshold  = 15               // more messages than this for one room triggers burst mode
	burstKeep       = 10               // individual messages sent in burst mode
	summaryMaxLines = 50               // VulnID@host lines in the burst summary
	maxAttempts     = 4                // per message, including the first try
	maxRetryWait    = 30 * time.Second // cap for retry_after_ms from the homeserver
	defaultBackoff  = 500 * time.Millisecond
	maxRespBody     = 64 << 10
)

// Matrix implements core.Notifier by sending m.room.message events to Matrix rooms.
type Matrix struct {
	homeserver string
	token      string
	defaults   []string
	cfgRoutes  []Route
	routes     RouteSource
	client     *http.Client
	backoff    time.Duration // base for exponential backoff between attempts
	txnSeq     atomic.Uint64
}

var _ core.Notifier = (*Matrix)(nil)

// NewMatrix validates cfg and returns a notifier. routes may be nil; httpClient may be nil
// (a client with a 30 s timeout is used then).
func NewMatrix(cfg Config, routes RouteSource, httpClient *http.Client) (*Matrix, error) {
	hs := strings.TrimRight(strings.TrimSpace(cfg.Homeserver), "/")
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
	if cfg.AccessToken == "" {
		return nil, errors.New("notify: matrix access token is empty")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	var cfgRoutes []Route
	for _, r := range cfg.Routes {
		cfgRoutes = append(cfgRoutes, Route{Label: r.Label, Rooms: slices.Clone(r.Rooms)})
	}
	return &Matrix{
		homeserver: hs,
		token:      cfg.AccessToken,
		defaults:   appendUnique(nil, cfg.DefaultRooms...),
		cfgRoutes:  cfgRoutes,
		routes:     routes,
		client:     httpClient,
		backoff:    defaultBackoff,
	}, nil
}

// DeliveryError is returned by Notify when delivery was incomplete or had permanent errors.
// Failed holds the indexes (into the events passed to Notify) of events that must be retried;
// every other event was either delivered or hit a permanent error (HTTP 4xx other than 429) that
// retrying cannot fix, which is logged at ERROR and reported in Err but is not retried.
type DeliveryError struct {
	Failed []int
	Err    error
}

func (e *DeliveryError) Error() string {
	return fmt.Sprintf("matrix delivery: %d event(s) to retry: %v", len(e.Failed), e.Err)
}

func (e *DeliveryError) Unwrap() error { return e.Err }

// permanentError marks a failure that retrying cannot fix.
type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

// Notify routes each event to its rooms and sends it. A failing group or room never stops the
// rest. The returned error, if any, is a *DeliveryError.
func (m *Matrix) Notify(ctx context.Context, events []model.Event) error {
	if len(events) == 0 {
		return nil
	}
	var errs []error
	routes, err := m.effectiveRoutes(ctx)
	if err != nil {
		slog.Warn("matrix: loading DB routes failed, using config routes only", "err", err)
		errs = append(errs, fmt.Errorf("matrix: load routes: %w", err))
	}

	// Group before routing and burst counting: one message per (kind, host, vuln, target).
	byRoom := map[string][]group{}
	var order []string
	for _, g := range groupEvents(events) {
		ev := g.first()
		rooms := m.roomsFor(ev, routes)
		if len(rooms) == 0 {
			slog.Warn("matrix: no room for event, skipping",
				"kind", ev.Kind, "vuln", ev.Finding.VulnID, "host", ev.Host.Hostname)
			continue
		}
		for _, r := range rooms {
			if _, ok := byRoom[r]; !ok {
				order = append(order, r)
			}
			byRoom[r] = append(byRoom[r], g)
		}
	}

	failed := map[int]bool{}
	for ri, room := range order {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			for _, r := range order[ri:] {
				for _, g := range byRoom[r] {
					for _, i := range g.idx {
						failed[i] = true
					}
				}
			}
			break
		}
		bad, err := m.sendRoom(ctx, room, byRoom[room])
		for _, g := range bad {
			for _, i := range g.idx {
				failed[i] = true
			}
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("room %s: %w", room, err))
		}
	}
	if len(errs) == 0 {
		return nil
	}
	de := &DeliveryError{Err: errors.Join(errs...)}
	for i := range failed {
		de.Failed = append(de.Failed, i)
	}
	slices.Sort(de.Failed)
	return de
}

// effectiveRoutes merges config routes and DB routes by label, rooms deduplicated.
// A DB error is returned alongside the config-only routes.
func (m *Matrix) effectiveRoutes(ctx context.Context) (map[string][]string, error) {
	merged := map[string][]string{}
	add := func(rs []Route) {
		for _, r := range rs {
			if r.Label == "" {
				continue
			}
			merged[r.Label] = appendUnique(merged[r.Label], r.Rooms...)
		}
	}
	add(m.cfgRoutes)
	if m.routes == nil {
		return merged, nil
	}
	db, err := m.routes.MatrixRoutes(ctx)
	add(db)
	return merged, err
}

// roomsFor returns the union of rooms for all labels of the event's host, falling back to
// the default rooms when no label matches.
func (m *Matrix) roomsFor(ev model.Event, routes map[string][]string) []string {
	var out []string
	for _, l := range ev.Host.Labels {
		out = appendUnique(out, routes[l]...)
	}
	if len(out) == 0 {
		out = appendUnique(out, m.defaults...)
	}
	return out
}

// sendRoom sends the groups of one room and continues past failures. It returns the groups that
// must be retried (retryable failures) and the joined errors of all failures. Permanent errors
// are logged at ERROR and returned in err but their groups are not in the retry list.
func (m *Matrix) sendRoom(ctx context.Context, room string, groups []group) (retry []group, err error) {
	var errs []error
	record := func(g []group, e error) {
		if e == nil {
			return
		}
		errs = append(errs, e)
		var pe *permanentError
		if errors.As(e, &pe) {
			slog.Error("matrix: permanent delivery error, event will not be retried", "room", room, "err", e)
			return
		}
		retry = append(retry, g...)
	}
	if len(groups) <= burstThreshold {
		for _, g := range groups {
			record([]group{g}, m.sendGroup(ctx, room, g))
		}
		return retry, errors.Join(errs...)
	}

	// Burst: send the most important groups individually, then one summary of the rest.
	sorted := slices.Clone(groups)
	slices.SortStableFunc(sorted, compareGroups)
	for _, g := range sorted[:burstKeep] {
		record([]group{g}, m.sendGroup(ctx, room, g))
	}
	link := ""
	for _, g := range sorted {
		if link = findingsURL(g.first().WebURL); link != "" {
			break
		}
	}
	record(sorted[burstKeep:], m.send(ctx, room, renderSummary(sorted[burstKeep:], link)))
	return retry, errors.Join(errs...)
}

func (m *Matrix) sendGroup(ctx context.Context, room string, g group) error {
	plain, h := renderGroup(g.evs)
	return m.send(ctx, room, newMessage(g.first(), plain, h))
}

// message is the content of an m.room.message event.
type message struct {
	MsgType       string `json:"msgtype"`
	Body          string `json:"body"`
	Format        string `json:"format"`
	FormattedBody string `json:"formatted_body"`
}

func newMessage(ev model.Event, plain, h string) message {
	mt := "m.text"
	if ev.Kind == model.EventResolved {
		mt = "m.notice"
	}
	return message{MsgType: mt, Body: plain, Format: "org.matrix.custom.html", FormattedBody: h}
}

// send PUTs one message, retrying 429 (per retry_after_ms), 5xx and network errors.
// The transaction ID is fixed across attempts so the homeserver can deduplicate.
func (m *Matrix) send(ctx context.Context, room string, msg message) error {
	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("encode message: %w", err)
	}
	endpoint := m.homeserver + "/_matrix/client/v3/rooms/" + url.PathEscape(room) +
		"/send/m.room.message/" + url.PathEscape(m.newTxnID())

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		wait, retry, err := m.attempt(ctx, endpoint, body)
		if err == nil {
			return nil
		}
		if !retry {
			return err
		}
		lastErr = err
		if attempt == maxAttempts {
			break
		}
		if wait <= 0 {
			wait = m.backoff * time.Duration(1<<(attempt-1))
		}
		if err := sleepCtx(ctx, wait); err != nil {
			return err
		}
	}
	return fmt.Errorf("giving up after %d attempts: %w", maxAttempts, lastErr)
}

// attempt performs one PUT. retry reports whether the failure is worth retrying; wait is
// the server-requested delay (0 when none).
func (m *Matrix) attempt(ctx context.Context, endpoint string, body []byte) (wait time.Duration, retry bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, false, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+m.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return 0, false, ctx.Err()
		}
		return 0, true, fmt.Errorf("network: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, maxRespBody))

	switch code := resp.StatusCode; {
	case code >= 200 && code < 300:
		return 0, false, nil
	case code == http.StatusTooManyRequests:
		return retryAfter(data), true, errors.New("rate limited (429)")
	case code >= 500:
		return 0, true, fmt.Errorf("server error %d", code)
	default:
		return 0, false, &permanentError{fmt.Errorf("matrix responded %d: %s", code, snippet(data))}
	}
}

// retryAfter extracts retry_after_ms from a Matrix error body, capped at maxRetryWait.
func retryAfter(body []byte) time.Duration {
	var e struct {
		RetryAfterMS int64 `json:"retry_after_ms"`
	}
	if json.Unmarshal(body, &e) != nil || e.RetryAfterMS <= 0 {
		return 0
	}
	return min(time.Duration(e.RetryAfterMS)*time.Millisecond, maxRetryWait)
}

func (m *Matrix) newTxnID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("panoptes-%d-%d-%s", time.Now().UnixNano(), m.txnSeq.Add(1), hex.EncodeToString(b[:]))
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

func snippet(b []byte) string {
	const limit = 200
	if len(b) > limit {
		return string(b[:limit]) + "..."
	}
	return string(b)
}

// appendUnique appends the non-empty values of src that are not yet in dst.
func appendUnique(dst []string, src ...string) []string {
	for _, s := range src {
		if s == "" || slices.Contains(dst, s) {
			continue
		}
		dst = append(dst, s)
	}
	return dst
}
