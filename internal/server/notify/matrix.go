// Package notify delivers Panoptes events to Matrix rooms (docs/contracts.md §5, §6).
package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
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
	"sync"
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
	OpsRooms     []string // server-level events (feed, pipeline, aggregated silence); empty: DefaultRooms
	Routes       []Route  // from the config file

	// OnDeliveryProblem, when set, is told about delivery failures: a Matrix error status for a room
	// (status 0: network error; room "": no room resolved for an event), the event kind and whether
	// the failure is permanent (HTTP 4xx other than 429, or no room). It is called at most once per
	// 10 minutes for the same (room, status) and must not block for long.
	OnDeliveryProblem func(room string, status int, kind model.EventKind, permanent bool)
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

	problemEvery   = 10 * time.Minute // log / callback at most this often per (room, status)
	partialTTL     = time.Hour        // remember rooms an event already reached while another room failed
	partialMax     = 4096
	maxTrackedProb = 512
)

// critical reports whether losing an event of this kind silently is unacceptable: a permanent
// delivery failure is then reported as failed (retried on later runs) instead of "delivered".
func critical(k model.EventKind) bool {
	switch k {
	case model.EventExploitable, model.EventUnknownCritical, model.EventAgentSilent, model.EventFeedStale:
		return true
	}
	return false
}

// Matrix implements core.Notifier by sending m.room.message events to Matrix rooms.
type Matrix struct {
	homeserver string
	token      string
	defaults   []string
	ops        []string
	cfgRoutes  []Route
	routes     RouteSource
	client     *http.Client
	backoff    time.Duration // base for exponential backoff between attempts
	txnSeq     atomic.Uint64
	onProblem  func(room string, status int, kind model.EventKind, permanent bool)
	now        func() time.Time

	pmu     sync.Mutex
	seen    map[string]time.Time // (room,status) -> last time it was logged / reported
	partial map[string]time.Time // room|body hash of messages that reached this room while another failed
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
		ops:        appendUnique(nil, cfg.OpsRooms...),
		cfgRoutes:  cfgRoutes,
		routes:     routes,
		client:     httpClient,
		backoff:    defaultBackoff,
		onProblem:  cfg.OnDeliveryProblem,
		now:        time.Now,
		seen:       map[string]time.Time{},
		partial:    map[string]time.Time{},
	}, nil
}

// DeliveryError is returned by Notify when delivery was incomplete or had permanent errors.
// Failed holds the indexes (into the events passed to Notify) of events that must be retried;
// every other event was either delivered or is of a kind that is not worth retrying forever after a
// permanent error (HTTP 4xx other than 429: resolved, agent_back, feed_ok, pipeline_error, ...); that is
// logged at ERROR and reported in Err but not retried. For exploitable, unknown_critical, agent_silent
// and feed_stale events a permanent error counts as failed, so the caller retries them on later runs,
// and it is surfaced through Config.OnDeliveryProblem.
type DeliveryError struct {
	Failed []int
	Err    error
}

func (e *DeliveryError) Error() string {
	return fmt.Sprintf("matrix delivery: %d event(s) to retry: %v", len(e.Failed), e.Err)
}

func (e *DeliveryError) Unwrap() error { return e.Err }

// statusError is a failed request with its HTTP status (0: network error). permanent marks a
// failure that retrying the same request cannot fix (4xx other than 429).
type statusError struct {
	status    int
	permanent bool
	err       error
}

func (e *statusError) Error() string { return e.err.Error() }
func (e *statusError) Unwrap() error { return e.err }

// reportProblem logs a delivery problem and calls OnDeliveryProblem, at most once per
// problemEvery for the same (room, status). It returns whether it was reported.
func (m *Matrix) reportProblem(room string, status int, kind model.EventKind, permanent bool, err error) {
	key := room + "|" + fmt.Sprint(status)
	m.pmu.Lock()
	now := m.now()
	if t, ok := m.seen[key]; ok && now.Sub(t) < problemEvery {
		m.pmu.Unlock()
		return
	}
	if len(m.seen) >= maxTrackedProb {
		for k, t := range m.seen {
			if now.Sub(t) >= problemEvery {
				delete(m.seen, k)
			}
		}
		if len(m.seen) >= maxTrackedProb {
			clear(m.seen)
		}
	}
	m.seen[key] = now
	m.pmu.Unlock()
	level := slog.LevelWarn
	if permanent {
		level = slog.LevelError
	}
	slog.Log(context.Background(), level, "matrix: delivery problem (further identical problems are not logged for 10 min)",
		"room", room, "status", status, "kind", kind, "permanent", permanent, "err", err)
	if m.onProblem != nil {
		m.onProblem(room, status, kind, permanent)
	}
}

func (m *Matrix) wasDelivered(room, h string) bool {
	m.pmu.Lock()
	defer m.pmu.Unlock()
	t, ok := m.partial[room+"|"+h]
	return ok && m.now().Sub(t) < partialTTL
}

// rememberPartial notes that these messages reached their room although the event failed elsewhere,
// so a retry of the event does not post them there again.
func (m *Matrix) rememberPartial(keys []string) {
	m.pmu.Lock()
	defer m.pmu.Unlock()
	now := m.now()
	if len(m.partial)+len(keys) > partialMax {
		for k, t := range m.partial {
			if now.Sub(t) >= partialTTL {
				delete(m.partial, k)
			}
		}
		if len(m.partial)+len(keys) > partialMax {
			clear(m.partial)
		}
	}
	for _, k := range keys {
		m.partial[k] = now
	}
}

func bodyHash(msg message) string {
	h := sha256.Sum256([]byte(msg.Body + "\x00" + msg.FormattedBody))
	return hex.EncodeToString(h[:12])
}

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
	failed := map[int]bool{}
	for _, g := range groupEvents(events) {
		ev := g.first()
		rooms := m.roomsFor(ev, routes)
		if len(rooms) == 0 {
			// Not a silent success: report it, and keep retrying the events that must not be lost.
			noRoom := errors.New("no Matrix room resolved for event")
			errs = append(errs, fmt.Errorf("%s %s: %w", ev.Kind, cl(ev.Finding.VulnID), noRoom))
			m.reportProblem("", 0, ev.Kind, true, noRoom)
			if critical(ev.Kind) {
				for _, i := range g.idx {
					failed[i] = true
				}
			}
			continue
		}
		for _, r := range rooms {
			if _, ok := byRoom[r]; !ok {
				order = append(order, r)
			}
			byRoom[r] = append(byRoom[r], g)
		}
	}

	var okRecs []okRec
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
		bad, oks, err := m.sendRoom(ctx, room, byRoom[room])
		okRecs = append(okRecs, oks...)
		for _, g := range bad {
			for _, i := range g.idx {
				failed[i] = true
			}
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("room %s: %w", room, err))
		}
	}
	// Messages that reached their room while the same event failed elsewhere must not be posted
	// again when the event is retried.
	var keep []string
	for _, o := range okRecs {
		for _, i := range o.g.idx {
			if failed[i] {
				keep = append(keep, o.key)
				break
			}
		}
	}
	if len(keep) > 0 {
		m.rememberPartial(keep)
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
	if ev.ServerLevel() {
		if len(m.ops) > 0 {
			return slices.Clone(m.ops)
		}
		return slices.Clone(m.defaults)
	}
	for _, l := range ev.Host.Labels {
		out = appendUnique(out, routes[l]...)
	}
	if len(out) == 0 {
		out = appendUnique(out, m.defaults...)
	}
	return out
}

// okRec is a single-group message that was delivered to a room.
type okRec struct {
	g   group
	key string // room|body hash
}

// sendRoom sends the groups of one room and continues past failures. It returns the groups that
// must be retried (retryable failures, and permanent failures of critical event kinds), the groups
// that were delivered individually and the joined errors of all failures.
func (m *Matrix) sendRoom(ctx context.Context, room string, groups []group) (retry []group, oks []okRec, err error) {
	var errs []error
	record := func(g []group, e error) {
		if e == nil {
			return
		}
		errs = append(errs, e)
		var se *statusError
		isStatus := errors.As(e, &se)
		if isStatus && se.permanent {
			for _, gg := range g {
				if critical(gg.first().Kind) {
					retry = append(retry, gg)
				}
			}
			m.reportProblem(room, se.status, g[0].first().Kind, true, e)
			return
		}
		retry = append(retry, g...)
		if isStatus {
			m.reportProblem(room, se.status, g[0].first().Kind, false, e)
		}
	}
	send1 := func(g group) {
		plain, h := renderGroup(g.evs)
		msg := newMessage(g.first(), plain, h)
		key := room + "|" + bodyHash(msg)
		if m.wasDelivered(room, bodyHash(msg)) {
			return
		}
		e := m.send(ctx, room, msg)
		if e == nil {
			oks = append(oks, okRec{g, key})
		}
		record([]group{g}, e)
	}
	// Health events are never part of a burst: send them first, individually.
	var health []group
	groups = slices.DeleteFunc(slices.Clone(groups), func(g group) bool {
		if g.first().Kind.IsHealth() {
			health = append(health, g)
			return true
		}
		return false
	})
	for _, g := range health {
		send1(g)
	}
	if len(groups) <= burstThreshold {
		for _, g := range groups {
			send1(g)
		}
		return retry, oks, errors.Join(errs...)
	}

	// Burst: send the most important groups individually, then one summary of the rest.
	sorted := slices.Clone(groups)
	slices.SortStableFunc(sorted, compareGroups)
	for _, g := range sorted[:burstKeep] {
		send1(g)
	}
	link := ""
	for _, g := range sorted {
		if link = findingsURL(g.first().WebURL); link != "" {
			break
		}
	}
	record(sorted[burstKeep:], m.send(ctx, room, renderSummary(sorted[burstKeep:], link)))
	return retry, oks, errors.Join(errs...)
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

func newMessage(ev model.Event, plain, h string) message {
	mt := "m.text"
	if ev.Kind == model.EventResolved || ev.Kind == model.EventAgentBack || ev.Kind == model.EventFeedOK {
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
		return 0, true, &statusError{err: fmt.Errorf("network: %w", err)}
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, maxRespBody))

	switch code := resp.StatusCode; {
	case code >= 200 && code < 300:
		return 0, false, nil
	case code == http.StatusTooManyRequests:
		return retryAfter(data), true, &statusError{status: code, err: errors.New("rate limited (429)")}
	case code >= 500:
		return 0, true, &statusError{status: code, err: fmt.Errorf("server error %d", code)}
	default:
		return 0, false, &statusError{status: code, permanent: true, err: fmt.Errorf("matrix responded %d: %s", code, snippet(data))}
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
