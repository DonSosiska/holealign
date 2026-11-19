// Package notify delivers Holealign events to chat channels: Matrix rooms, Slack channels,
// Telegram chats (docs/contracts.md §5, §6, docs/notifications.md).
//
// A Notifier groups events, resolves destinations per event (label routes, default, ops) and fans
// the neutral Message out to Channels. A destination is a string "scheme:target"; one without a known
// scheme is a Matrix room ID or alias.
package notify

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DonSosiska/holealign/internal/model"
	"github.com/DonSosiska/holealign/internal/server/core"
)

// Config is the routing part of the notification configuration. Destinations are validated and
// canonicalised by New. Channel credentials live in the channels themselves.
type Config struct {
	Default []string // used when no label route matches
	Ops     []string // server-level events (feed, pipeline, aggregated silence); empty: Default
	Routes  []Route  // from the config file

	// OnDeliveryProblem, when set, is told about delivery failures: an error status for a destination
	// (status 0: network error; destination "": none resolved for an event), the event kind and whether
	// the failure is permanent (HTTP 4xx other than 429, an API answer that retrying cannot fix, or no
	// destination). It is called at most once per 10 minutes for the same (destination, status) and
	// must not block for long.
	OnDeliveryProblem func(dest string, status int, kind model.EventKind, permanent bool)
}

// Route maps a host label to destinations.
type Route struct {
	Label string
	To    []string
}

// RouteSource supplies routes edited in the web UI (stored in the DB). May be nil.
type RouteSource interface {
	Routes(ctx context.Context) ([]Route, error)
}

const (
	burstThreshold  = 15               // more messages than this for one destination triggers burst mode
	burstKeep       = 10               // individual messages sent in burst mode
	summaryMaxLines = 50               // VulnID@host lines in the burst summary
	maxAttempts     = 4                // per message, including the first try
	maxRetryWait    = 30 * time.Second // cap for the retry delay a service asks for
	defaultBackoff  = 500 * time.Millisecond
	maxRespBody     = 64 << 10

	problemEvery   = 10 * time.Minute // log / callback at most this often per (destination, status)
	partialTTL     = time.Hour        // remember destinations an event already reached while another failed
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

// Notifier implements core.Notifier by fanning events out to channels.
type Notifier struct {
	channels  map[string]Channel // by scheme
	defaults  []string
	ops       []string
	cfgRoutes []Route
	routes    RouteSource
	backoff   time.Duration // base for exponential backoff between attempts
	idSeq     atomic.Uint64
	onProblem func(dest string, status int, kind model.EventKind, permanent bool)
	now       func() time.Time

	pmu     sync.Mutex
	seen    map[string]time.Time // (destination,status) -> last time it was logged / reported
	partial map[string]time.Time // destination|content hash of messages that reached it while another failed
}

var _ core.Notifier = (*Notifier)(nil)

// New validates cfg and returns a notifier over channels (at least one). routes may be nil.
func New(cfg Config, routes RouteSource, channels ...Channel) (*Notifier, error) {
	if len(channels) == 0 {
		return nil, errors.New("notify: no channel configured")
	}
	n := &Notifier{
		channels:  map[string]Channel{},
		routes:    routes,
		backoff:   defaultBackoff,
		onProblem: cfg.OnDeliveryProblem,
		now:       time.Now,
		seen:      map[string]time.Time{},
		partial:   map[string]time.Time{},
	}
	for _, c := range channels {
		if _, dup := n.channels[c.Scheme()]; dup {
			return nil, fmt.Errorf("notify: channel %q registered twice", c.Scheme())
		}
		n.channels[c.Scheme()] = c
	}
	var err error
	if n.defaults, err = canonAll(cfg.Default); err != nil {
		return nil, fmt.Errorf("notify: default: %w", err)
	}
	if n.ops, err = canonAll(cfg.Ops); err != nil {
		return nil, fmt.Errorf("notify: ops: %w", err)
	}
	for _, r := range cfg.Routes {
		to, err := canonAll(r.To)
		if err != nil {
			return nil, fmt.Errorf("notify: route %q: %w", r.Label, err)
		}
		n.cfgRoutes = append(n.cfgRoutes, Route{Label: r.Label, To: to})
	}
	return n, nil
}

func canonAll(in []string) ([]string, error) {
	var out []string
	for _, d := range in {
		c, err := CanonicalDestination(d)
		if err != nil {
			return nil, err
		}
		out = appendUnique(out, c)
	}
	return out, nil
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
	return fmt.Sprintf("notification delivery: %d event(s) to retry: %v", len(e.Failed), e.Err)
}

func (e *DeliveryError) Unwrap() error { return e.Err }

// reportProblem logs a delivery problem and calls OnDeliveryProblem, at most once per
// problemEvery for the same (destination, status).
func (n *Notifier) reportProblem(dest string, status int, kind model.EventKind, permanent bool, err error) {
	key := dest + "|" + fmt.Sprint(status)
	n.pmu.Lock()
	now := n.now()
	if t, ok := n.seen[key]; ok && now.Sub(t) < problemEvery {
		n.pmu.Unlock()
		return
	}
	if len(n.seen) >= maxTrackedProb {
		for k, t := range n.seen {
			if now.Sub(t) >= problemEvery {
				delete(n.seen, k)
			}
		}
		if len(n.seen) >= maxTrackedProb {
			clear(n.seen)
		}
	}
	n.seen[key] = now
	n.pmu.Unlock()
	level := slog.LevelWarn
	if permanent {
		level = slog.LevelError
	}
	slog.Log(context.Background(), level, "notify: delivery problem (further identical problems are not logged for 10 min)",
		"destination", dest, "status", status, "kind", kind, "permanent", permanent, "err", err)
	if n.onProblem != nil {
		n.onProblem(dest, status, kind, permanent)
	}
}

func (n *Notifier) wasDelivered(dest, h string) bool {
	n.pmu.Lock()
	defer n.pmu.Unlock()
	t, ok := n.partial[dest+"|"+h]
	return ok && n.now().Sub(t) < partialTTL
}

// rememberPartial notes that these messages reached their destination although the event failed
// elsewhere, so a retry of the event does not post them there again.
func (n *Notifier) rememberPartial(keys []string) {
	n.pmu.Lock()
	defer n.pmu.Unlock()
	now := n.now()
	if len(n.partial)+len(keys) > partialMax {
		for k, t := range n.partial {
			if now.Sub(t) >= partialTTL {
				delete(n.partial, k)
			}
		}
		if len(n.partial)+len(keys) > partialMax {
			clear(n.partial)
		}
	}
	for _, k := range keys {
		n.partial[k] = now
	}
}

// Notify routes each event to its destinations and sends it. A failing group or destination never
// stops the rest. The returned error, if any, is a *DeliveryError.
func (n *Notifier) Notify(ctx context.Context, events []model.Event) error {
	if len(events) == 0 {
		return nil
	}
	var errs []error
	routes, err := n.effectiveRoutes(ctx)
	if err != nil {
		slog.Warn("notify: loading DB routes failed, using config routes only", "err", err)
		errs = append(errs, fmt.Errorf("notify: load routes: %w", err))
	}

	// Group before routing and burst counting: one message per (kind, host, vuln, target).
	byDest := map[string][]group{}
	var order []string
	failed := map[int]bool{}
	for _, g := range groupEvents(events) {
		ev := g.first()
		dests := n.destsFor(ev, routes)
		if len(dests) == 0 {
			// Not a silent success: report it, and keep retrying the events that must not be lost.
			noDest := errors.New("no notification destination resolved for event")
			errs = append(errs, fmt.Errorf("%s %s: %w", ev.Kind, cl(ev.Finding.VulnID), noDest))
			n.reportProblem("", 0, ev.Kind, true, noDest)
			if critical(ev.Kind) {
				for _, i := range g.idx {
					failed[i] = true
				}
			}
			continue
		}
		for _, d := range dests {
			if _, ok := byDest[d]; !ok {
				order = append(order, d)
			}
			byDest[d] = append(byDest[d], g)
		}
	}

	var okRecs []okRec
	for di, dest := range order {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			for _, d := range order[di:] {
				for _, g := range byDest[d] {
					for _, i := range g.idx {
						failed[i] = true
					}
				}
			}
			break
		}
		bad, oks, err := n.sendDest(ctx, dest, byDest[dest])
		okRecs = append(okRecs, oks...)
		for _, g := range bad {
			for _, i := range g.idx {
				failed[i] = true
			}
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("destination %s: %w", dest, err))
		}
	}
	// Messages that reached their destination while the same event failed elsewhere must not be
	// posted again when the event is retried.
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
		n.rememberPartial(keep)
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

// effectiveRoutes merges config routes and DB routes by label, destinations deduplicated.
// A DB error is returned alongside the config-only routes.
func (n *Notifier) effectiveRoutes(ctx context.Context) (map[string][]string, error) {
	merged := map[string][]string{}
	add := func(rs []Route, stored bool) {
		for _, r := range rs {
			if r.Label == "" {
				continue
			}
			for _, d := range r.To {
				c, err := CanonicalDestination(d)
				if err != nil {
					// config routes were validated by New; stored ones may predate stricter rules
					slog.Warn("notify: ignoring invalid destination in route", "label", r.Label, "stored", stored, "err", err)
					continue
				}
				merged[r.Label] = appendUnique(merged[r.Label], c)
			}
		}
	}
	add(n.cfgRoutes, false)
	if n.routes == nil {
		return merged, nil
	}
	db, err := n.routes.Routes(ctx)
	add(db, true)
	return merged, err
}

// destsFor returns the union of destinations for all labels of the event's host, falling back to
// the default destinations when no label matches.
func (n *Notifier) destsFor(ev model.Event, routes map[string][]string) []string {
	var out []string
	if ev.ServerLevel() {
		if len(n.ops) > 0 {
			return slices.Clone(n.ops)
		}
		return slices.Clone(n.defaults)
	}
	for _, l := range ev.Host.Labels {
		out = appendUnique(out, routes[l]...)
	}
	if len(out) == 0 {
		out = appendUnique(out, n.defaults...)
	}
	return out
}

// okRec is a single-group message that was delivered to a destination.
type okRec struct {
	g   group
	key string // destination|content hash
}

// sendDest sends the groups of one destination and continues past failures. It returns the groups
// that must be retried (retryable failures, and permanent failures of critical event kinds), the
// groups that were delivered individually and the joined errors of all failures.
func (n *Notifier) sendDest(ctx context.Context, dest string, groups []group) (retry []group, oks []okRec, err error) {
	scheme, target := ParseDestination(dest)
	ch := n.channels[scheme]
	var errs []error
	record := func(g []group, e error) {
		if e == nil {
			return
		}
		errs = append(errs, e)
		var se *SendError
		isStatus := errors.As(e, &se)
		if isStatus && se.Permanent {
			for _, gg := range g {
				if critical(gg.first().Kind) {
					retry = append(retry, gg)
				}
			}
			n.reportProblem(dest, se.Status, g[0].first().Kind, true, e)
			return
		}
		retry = append(retry, g...)
		if isStatus {
			n.reportProblem(dest, se.Status, g[0].first().Kind, false, e)
		}
	}
	send := func(msg Message) error {
		if ch == nil {
			return &SendError{Permanent: true, Err: fmt.Errorf("the %s channel is not configured (destination %s)", scheme, dest)}
		}
		return n.send(ctx, ch, target, msg)
	}
	send1 := func(g group) {
		msg := buildGroup(g.evs)
		h := msg.fingerprint()
		if n.wasDelivered(dest, h) {
			return
		}
		e := send(msg)
		if e == nil {
			oks = append(oks, okRec{g, dest + "|" + h})
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

	// Burst: fair-share interleave across hosts (each host's own groups ordered by importance),
	// so one noisy or compromised host cannot crowd out other hosts' alerts from burstKeep or the
	// burst summary. For a single host this preserves compareGroups order exactly.
	sorted := interleaveByHost(groups)
	for _, g := range sorted[:burstKeep] {
		send1(g)
	}
	link := ""
	for _, g := range sorted {
		if link = findingsURL(g.first().WebURL); link != "" {
			break
		}
	}
	record(sorted[burstKeep:], send(summaryMessage(sorted[burstKeep:], link)))
	return retry, oks, errors.Join(errs...)
}

// interleaveByHost orders groups per host by compareGroups, orders hosts by their most important
// group, and then round-robins across hosts. A single host yields the exact compareGroups order.
func interleaveByHost(groups []group) []group {
	byHost := map[string][]group{}
	var hosts []string
	for _, g := range groups {
		hid := g.first().Host.ID
		if _, ok := byHost[hid]; !ok {
			hosts = append(hosts, hid)
		}
		byHost[hid] = append(byHost[hid], g)
	}
	for _, h := range hosts {
		slices.SortStableFunc(byHost[h], compareGroups)
	}
	slices.SortStableFunc(hosts, func(a, b string) int {
		if c := compareGroups(byHost[a][0], byHost[b][0]); c != 0 {
			return c
		}
		return strings.Compare(a, b)
	})
	out := make([]group, 0, len(groups))
	for round := 0; len(out) < len(groups); round++ {
		for _, h := range hosts {
			if round < len(byHost[h]) {
				out = append(out, byHost[h][round])
			}
		}
	}
	return out
}

// send delivers msg through ch, retrying transient failures (429, 5xx, network errors) with
// exponential backoff or the delay the service asked for.
func (n *Notifier) send(ctx context.Context, ch Channel, target string, msg Message) error {
	msg.ID = n.newID()
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err := ch.Send(ctx, target, msg)
		if err == nil {
			return nil
		}
		var se *SendError
		if !errors.As(err, &se) || se.Permanent {
			return err
		}
		lastErr = err
		if attempt == maxAttempts {
			break
		}
		wait := min(se.RetryAfter, maxRetryWait)
		if wait <= 0 {
			wait = n.backoff * time.Duration(1<<(attempt-1))
		}
		if err := sleepCtx(ctx, wait); err != nil {
			return err
		}
	}
	return fmt.Errorf("giving up after %d attempts: %w", maxAttempts, lastErr)
}

func (n *Notifier) newID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("holealign-%d-%d-%s", time.Now().UnixNano(), n.idSeq.Add(1), hex.EncodeToString(b[:]))
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

// newHTTPClient returns the default client of the HTTP channels.
func newHTTPClient() *http.Client { return &http.Client{Timeout: 30 * time.Second} }

// stripSecret removes every occurrence of secret from s (error texts must never leak tokens).
func stripSecret(s, secret string) string {
	if secret == "" {
		return s
	}
	return strings.ReplaceAll(s, secret, "***")
}
