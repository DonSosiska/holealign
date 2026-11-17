// Package health raises "silence" alerts: agents that stopped checking in, a stale or failing
// vulnerability feed, and hosts whose pipeline keeps failing. An attacker who kills an agent, or a
// broken feed, must not go unnoticed. The Monitor is polled (Check) once a minute; every alert is
// deduplicated through the store's notifications_sent table (or kv) so a restart does not repeat it.
package health

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/DonSosiska/panoptes/internal/model"
	"github.com/DonSosiska/panoptes/internal/server/core"
	"github.com/DonSosiska/panoptes/internal/server/feeds"
	"github.com/DonSosiska/panoptes/internal/server/notify"
	"github.com/DonSosiska/panoptes/internal/server/store"
)

// kv keys published for the web UI banner (empty value = healthy).
const (
	KVFeedStale      = "health.feed_stale"      // detail text while the feed alert is active
	KVPipelineErrors = "health.pipeline_errors" // one "host: detail" line per affected host
	kvPipelineAlert  = "health.pipeline_alert." // + host id: RFC 3339 time of the last alert
)

const (
	// FailuresBeforeAlert is the number of consecutive failed pipeline runs that raises an alert.
	FailuresBeforeAlert = 3
	// PipelineAlertEvery limits pipeline_error alerts to once per host per this period.
	PipelineAlertEvery = 24 * time.Hour
	// feedErrorChecks: the feed alert fires when last_error stays set for more than this many checks.
	feedErrorChecks = 2
	// maxListed hostnames in an aggregated pipeline message.
	maxListed = 20
	// maxSilentListed hosts named in each message of a mass silence (ops room and one per label).
	maxSilentListed = 50
	// errLogEvery limits the log line for an unchanged failing check.
	errLogEvery = 10 * time.Minute
	// minAggregate: more than this many simultaneous hosts (or 30% of the fleet) are aggregated.
	minAggregate = 5
)

// Options configure a Monitor.
type Options struct {
	AgentSilentAfter time.Duration // 0 disables agent_silent / agent_back
	FeedStaleAfter   time.Duration // 0 disables feed_stale / feed_ok
	// CheckinInterval is the agents' check-in period (default 20s); alerts are held back for
	// 2 x CheckinInterval after the monitor started so a server restart does not look like silence.
	CheckinInterval time.Duration
	// FeedBuilt returns the build time of the loaded vulnerability DB (zero if unknown). Optional.
	FeedBuilt func() time.Time
	PublicURL string
	Now       func() time.Time
	Logger    *slog.Logger
}

// Monitor evaluates health conditions and sends events through a core.Notifier.
type Monitor struct {
	st    store.Store
	n     core.Notifier
	opts  Options
	log   *slog.Logger
	start time.Time

	mu       sync.Mutex
	failures map[string]int       // consecutive failed runs per host
	lastErr  map[string]string    // last error per failing host
	poisoned map[string]poisonRec // hosts with a poisoned target
	pending  map[string]bool      // hosts whose pipeline alert is due
	feedErrN int                  // consecutive checks with a feed error

	lastErrMsg string // last logged check error and when, so a failing check does not flood the log
	lastErrAt  time.Time
}

type poisonRec struct {
	target string
	at     time.Time
}

// New builds a Monitor. n may be nil (events are then only logged).
func New(st store.Store, n core.Notifier, opts Options) *Monitor {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.CheckinInterval <= 0 {
		opts.CheckinInterval = 20 * time.Second
	}
	if n == nil {
		n = core.NoopNotifier{}
	}
	return &Monitor{
		st: st, n: n, opts: opts, log: opts.Logger, start: opts.Now(),
		failures: map[string]int{}, lastErr: map[string]string{},
		poisoned: map[string]poisonRec{}, pending: map[string]bool{},
	}
}

// ReportRun records the outcome of a pipeline run (wire to pipeline.Options.OnRun).
func (m *Monitor) ReportRun(hostID string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err == nil {
		delete(m.failures, hostID)
		delete(m.lastErr, hostID)
		delete(m.pending, hostID)
		return
	}
	m.failures[hostID]++
	m.lastErr[hostID] = oneLine(err.Error(), 300)
	if m.failures[hostID] >= FailuresBeforeAlert {
		m.pending[hostID] = true
	}
}

// ReportPoison records a poisoned target (wire to pipeline.Options.OnPoison).
func (m *Monitor) ReportPoison(hostID, target string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.poisoned[hostID] = poisonRec{target: oneLine(target, 100), at: m.opts.Now()}
	m.pending[hostID] = true
}

// ForgetHost drops everything held in memory about a deleted host. (Check also prunes hosts that
// are no longer in the store, so a delete done by another process is covered as well.)
func (m *Monitor) ForgetHost(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.forgetLocked(id)
}

func (m *Monitor) forgetLocked(id string) bool {
	_, a := m.failures[id]
	_, b := m.lastErr[id]
	_, c := m.poisoned[id]
	_, d := m.pending[id]
	delete(m.failures, id)
	delete(m.lastErr, id)
	delete(m.poisoned, id)
	delete(m.pending, id)
	return a || b || c || d
}

// pruneMissing forgets hosts that no longer exist in the store.
func (m *Monitor) pruneMissing(ctx context.Context) {
	hosts, err := m.st.ListHosts(ctx)
	if err != nil {
		return
	}
	live := make(map[string]struct{}, len(hosts))
	for _, h := range hosts {
		live[h.ID] = struct{}{}
	}
	m.mu.Lock()
	var gone []string
	for id := range m.failures {
		if _, ok := live[id]; !ok {
			gone = append(gone, id)
		}
	}
	for id := range m.lastErr {
		if _, ok := live[id]; !ok {
			gone = append(gone, id)
		}
	}
	for id := range m.poisoned {
		if _, ok := live[id]; !ok {
			gone = append(gone, id)
		}
	}
	for id := range m.pending {
		if _, ok := live[id]; !ok {
			gone = append(gone, id)
		}
	}
	for _, id := range gone {
		m.forgetLocked(id)
	}
	m.mu.Unlock()
	for _, id := range gone { // the 24 h pipeline-alert marker of a deleted host
		m.setKV(ctx, kvPipelineAlert+id, "")
	}
}

// Start runs Check every interval (default 1 min) until ctx is done. The returned channel is
// closed when the loop has stopped.
func (m *Monitor) Start(ctx context.Context, every time.Duration) <-chan struct{} {
	if every <= 0 {
		every = time.Minute
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.safeCheck(ctx)
			}
		}
	}()
	return done
}

func (m *Monitor) safeCheck(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			m.log.Error("health check panicked", "panic", r, "stack", string(debug.Stack()))
		}
	}()
	if err := m.Check(ctx); err != nil && ctx.Err() == nil {
		now := m.opts.Now()
		if msg := err.Error(); msg != m.lastErrMsg || now.Sub(m.lastErrAt) >= errLogEvery {
			m.lastErrMsg, m.lastErrAt = msg, now
			m.log.Error("health check failed (the same failure is logged at most every 10 min)", "err", err)
		}
	}
}

// Check runs one pass over all conditions. The first error does not stop the other checks.
func (m *Monitor) Check(ctx context.Context) error {
	var errs []error
	m.pruneMissing(ctx)
	for _, f := range []func(context.Context) error{m.checkAgents, m.checkFeed, m.checkPipeline} {
		if err := f(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// --- delivery ---------------------------------------------------------------

type outEvent struct {
	ev        model.Event
	findingK  string // finding key recorded after delivery ("" = nothing recorded)
	dedupK    string
	alsoRecs  []recKey // aggregated events record one entry per host
	onSuccess func()
}

type recKey struct{ finding, dedup string }

// deliver sends the events and records those delivered; failed events are retried on the next pass.
func (m *Monitor) deliver(ctx context.Context, out []outEvent) error {
	if len(out) == 0 {
		return nil
	}
	evs := make([]model.Event, len(out))
	for i, o := range out {
		evs[i] = o.ev
	}
	nerr := m.n.Notify(ctx, evs)
	failed := map[int]bool{}
	if nerr != nil {
		var de *notify.DeliveryError
		if !errors.As(nerr, &de) {
			return fmt.Errorf("notify: %w", nerr)
		}
		for _, i := range de.Failed {
			failed[i] = true
		}
	}
	now := m.opts.Now()
	for i, o := range out {
		if failed[i] {
			continue
		}
		recs := o.alsoRecs
		if o.findingK != "" {
			recs = append(recs, recKey{o.findingK, o.dedupK})
		}
		for _, r := range recs {
			if err := m.st.RecordNotification(ctx, r.finding, r.dedup, o.ev.Kind, now); err != nil {
				return fmt.Errorf("record notification: %w", err)
			}
		}
		if o.onSuccess != nil {
			o.onSuccess()
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("notify: %d of %d health events not delivered: %w", len(failed), len(evs), nerr)
	}
	return nil
}

// --- agents -----------------------------------------------------------------

func hostFindingKey(id string) string                  { return "host|" + id }
func hostDedupKey(id string, k model.EventKind) string { return "host|" + id + "|" + string(k) }

func (m *Monitor) checkAgents(ctx context.Context) error {
	after := m.opts.AgentSilentAfter
	if after <= 0 {
		return nil
	}
	now := m.opts.Now()
	if now.Sub(m.start) < 2*m.opts.CheckinInterval {
		return nil // just started: agents have not had a chance to check in
	}
	hosts, err := m.st.ListHosts(ctx)
	if err != nil {
		return fmt.Errorf("list hosts: %w", err)
	}
	var silent, back []model.Host
	fleet := 0
	for _, h := range hosts {
		if h.LastCheckin.IsZero() {
			continue // never checked in: nothing to be silent about
		}
		fleet++
		silentNow := now.Sub(h.LastCheckin) > after
		sent, err := m.st.NotificationSent(ctx, hostDedupKey(h.ID, model.EventAgentSilent))
		if err != nil {
			return err
		}
		switch {
		case silentNow && !sent:
			silent = append(silent, h)
		case !silentNow && sent:
			back = append(back, h)
		}
	}
	var errs []error
	if err := m.deliver(ctx, m.hostEvents(model.EventAgentSilent, silent, fleet, now)); err != nil {
		errs = append(errs, err)
	}
	if err := m.deliver(ctx, m.hostEvents(model.EventAgentBack, back, fleet, now)); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// hostEvents builds one event per host, or, when more than max(5, 30% of the fleet) hosts changed
// state in the same pass, a mass-silence set of events (see aggregateEvents).
func (m *Monitor) hostEvents(kind model.EventKind, hosts []model.Host, fleet int, now time.Time) []outEvent {
	if len(hosts) == 0 {
		return nil
	}
	// most recent check-in first: the hosts that went quiet last are the ones to look at first
	sort.Slice(hosts, func(i, j int) bool {
		if !hosts[i].LastCheckin.Equal(hosts[j].LastCheckin) {
			return hosts[i].LastCheckin.After(hosts[j].LastCheckin)
		}
		return hosts[i].ID < hosts[j].ID
	})
	if limit := max(minAggregate, fleet*30/100); len(hosts) > limit {
		return m.aggregateEvents(kind, hosts, now)
	}
	out := make([]outEvent, 0, len(hosts))
	for _, h := range hosts {
		ev := model.Event{Kind: kind, Host: h, WebURL: m.hostURL(h.ID)}
		last := h.LastCheckin.UTC().Format("2006-01-02 15:04 UTC")
		if kind == model.EventAgentSilent {
			ev.Detail = fmt.Sprintf("no check-in for %s (last: %s)", HumanDuration(now.Sub(h.LastCheckin)), last)
		} else {
			ev.Detail = "checking in again (last: " + last + ")"
		}
		out = append(out, outEvent{ev: ev, findingK: hostFindingKey(h.ID), dedupK: hostDedupKey(h.ID, kind)})
	}
	return out
}

const groupHostPrefix = "group:"

// aggregateEvents handles a mass silence (or mass return). The ops rooms get ONE overview with the
// total and the first maxSilentListed hosts (newest check-in first) plus a link to the hosts page,
// but the hosts are still announced where their owners look: for every label, one message to that
// label's rooms lists the affected hosts carrying it (up to maxSilentListed), and hosts without a
// label go to the default rooms. Hosts with different label sets are never folded into one
// ops-only message. A host is recorded as notified only through an event that names it, so hosts
// beyond the listing limits are announced again on the next pass. hosts must be sorted.
func (m *Monitor) aggregateEvents(kind model.EventKind, hosts []model.Host, now time.Time) []outEvent {
	line := func(h model.Host) string {
		return "• " + oneLine(h.Hostname, 48) + " (" + oneLine(h.ID, 40) + ") last " + h.LastCheckin.UTC().Format("01-02 15:04")
	}
	verb := "silent"
	if kind == model.EventAgentBack {
		verb = "checking in again"
	}
	build := func(group []model.Host, head string, ev model.Event) outEvent {
		listed := group[:min(len(group), maxSilentListed)]
		lines := []string{head}
		var recs []recKey
		for _, h := range listed {
			lines = append(lines, line(h))
			recs = append(recs, recKey{hostFindingKey(h.ID), hostDedupKey(h.ID, kind)})
		}
		if len(group) > len(listed) {
			lines = append(lines, fmt.Sprintf("…and %d more not listed (they are announced again on the next check)", len(group)-len(listed)))
		}
		ev.Kind, ev.Detail = kind, strings.Join(lines, "\n")
		return outEvent{ev: ev, alsoRecs: recs}
	}

	var out []outEvent
	head := fmt.Sprintf("%d agents silent — server/network problem?", len(hosts))
	if kind == model.EventAgentBack {
		head = fmt.Sprintf("%d agents are checking in again", len(hosts))
	}
	out = append(out, build(hosts, head+"\nnewest check-in first:", model.Event{WebURL: m.hostsURL()}))

	byLabel := map[string][]model.Host{}
	var unlabelled []model.Host
	for _, h := range hosts {
		if len(h.Labels) == 0 {
			unlabelled = append(unlabelled, h)
		}
		for _, l := range h.Labels {
			byLabel[l] = append(byLabel[l], h)
		}
	}
	labels := make([]string, 0, len(byLabel))
	for l := range byLabel {
		labels = append(labels, l)
	}
	sort.Strings(labels)
	for _, l := range labels {
		g := byLabel[l]
		out = append(out, build(g,
			fmt.Sprintf("%d hosts labelled %s %s (part of a mass silence of %d hosts); newest check-in first:", len(g), oneLine(l, 64), verb, len(hosts)),
			model.Event{Host: model.Host{ID: groupHostPrefix + l, Hostname: fmt.Sprintf("%d hosts labelled %s", len(g), oneLine(l, 64)), Labels: []string{l}},
				WebURL: m.hostsURL()}))
	}
	if len(unlabelled) > 0 {
		out = append(out, build(unlabelled,
			fmt.Sprintf("%d hosts without label %s (part of a mass silence of %d hosts); newest check-in first:", len(unlabelled), verb, len(hosts)),
			model.Event{Host: model.Host{ID: groupHostPrefix, Hostname: fmt.Sprintf("%d hosts without label", len(unlabelled))}, WebURL: m.hostsURL()}))
	}
	return out
}

func (m *Monitor) hostURL(id string) string {
	if m.opts.PublicURL == "" {
		return ""
	}
	return strings.TrimRight(m.opts.PublicURL, "/") + "/hosts/" + id
}

func (m *Monitor) hostsURL() string {
	if m.opts.PublicURL == "" {
		return ""
	}
	return strings.TrimRight(m.opts.PublicURL, "/") + "/hosts"
}

// --- feed -------------------------------------------------------------------

const feedKey = "server|feed"

func (m *Monitor) checkFeed(ctx context.Context) error {
	if m.opts.FeedStaleAfter <= 0 {
		return nil
	}
	now := m.opts.Now()
	get := func(k string) string {
		v, err := m.st.KVGet(ctx, k)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			m.log.Warn("health: kv get", "key", k, "err", err)
		}
		return v
	}
	var updated time.Time
	if v := get(feeds.KVUpdatedAt); v != "" {
		updated, _ = time.Parse(time.RFC3339, v)
	}
	if m.opts.FeedBuilt != nil {
		if b := m.opts.FeedBuilt(); b.After(updated) {
			updated = b
		}
	}
	lastErr := strings.TrimSpace(get(feeds.KVLastError))
	if lastErr != "" {
		m.feedErrN++
	} else {
		m.feedErrN = 0
	}
	tooOld := !updated.IsZero() && now.Sub(updated) > m.opts.FeedStaleAfter
	failing := m.feedErrN > feedErrorChecks
	stale := tooOld || failing

	sent, err := m.st.NotificationSent(ctx, feedKey+"|"+string(model.EventFeedStale))
	if err != nil {
		return err
	}
	switch {
	case stale:
		detail := "vulnerability DB "
		if updated.IsZero() {
			detail += "has not been updated"
		} else {
			detail += "last updated " + HumanDuration(now.Sub(updated)) + " ago"
		}
		if lastErr != "" {
			detail += " — " + oneLine(lastErr, 200)
		}
		m.setKV(ctx, KVFeedStale, detail)
		if sent {
			return nil
		}
		return m.deliver(ctx, []outEvent{{
			ev:       model.Event{Kind: model.EventFeedStale, Detail: detail},
			findingK: feedKey, dedupK: feedKey + "|" + string(model.EventFeedStale),
		}})
	case sent: // recovered
		m.setKV(ctx, KVFeedStale, "")
		return m.deliver(ctx, []outEvent{{
			ev:       model.Event{Kind: model.EventFeedOK, Detail: "vulnerability DB is up to date again"},
			findingK: feedKey, dedupK: feedKey + "|" + string(model.EventFeedOK),
		}})
	default:
		m.setKV(ctx, KVFeedStale, "")
	}
	return nil
}

// setKV writes v unless it is already stored.
func (m *Monitor) setKV(ctx context.Context, k, v string) {
	if cur, err := m.st.KVGet(ctx, k); err == nil && cur == v {
		return
	}
	if err := m.st.KVSet(ctx, k, v, m.opts.Now()); err != nil {
		m.log.Warn("health: kv set", "key", k, "err", err)
	}
}

// --- pipeline ---------------------------------------------------------------

func (m *Monitor) checkPipeline(ctx context.Context) error {
	now := m.opts.Now()
	type item struct {
		id, detail string
	}
	m.mu.Lock()
	for id, p := range m.poisoned { // poison flags are shown for 24 h
		if now.Sub(p.at) > PipelineAlertEvery {
			delete(m.poisoned, id)
		}
	}
	active := map[string]string{}
	for id, n := range m.failures {
		if n >= FailuresBeforeAlert {
			active[id] = fmt.Sprintf("pipeline failed %d times in a row: %s", n, m.lastErr[id])
		}
	}
	for id, p := range m.poisoned {
		d := "matching a target crashed; target skipped until a new inventory arrives: " + p.target
		if cur, ok := active[id]; ok {
			d = cur + "; " + d
		}
		active[id] = d
	}
	var due []item
	for id := range m.pending {
		due = append(due, item{id, active[id]})
	}
	m.mu.Unlock()

	// banner state for the web UI
	ids := make([]string, 0, len(active))
	for id := range active {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var lines []string
	for _, id := range ids {
		name := id
		if h, err := m.st.GetHost(ctx, id); err == nil {
			name = h.Hostname
		}
		lines = append(lines, oneLine(name, 64)+": "+oneLine(active[id], 300))
	}
	m.setKV(ctx, KVPipelineErrors, strings.Join(lines, "\n"))

	var out []outEvent
	sort.Slice(due, func(i, j int) bool { return due[i].id < due[j].id })
	var hosts []model.Host
	details := map[string]string{}
	for _, d := range due {
		if last, err := m.st.KVGet(ctx, kvPipelineAlert+d.id); err == nil && last != "" {
			if t, perr := time.Parse(time.RFC3339, last); perr == nil && now.Sub(t) < PipelineAlertEvery {
				m.clearPending(d.id)
				continue
			}
		}
		h, err := m.st.GetHost(ctx, d.id)
		if err != nil {
			m.clearPending(d.id) // host was deleted
			continue
		}
		hosts = append(hosts, h)
		details[h.ID] = oneLine(d.detail, 400)
	}
	mark := func(ids ...string) func() {
		return func() {
			for _, id := range ids {
				m.setKV(ctx, kvPipelineAlert+id, now.UTC().Format(time.RFC3339))
				m.clearPending(id)
			}
		}
	}
	if len(hosts) > minAggregate {
		var names, ids []string
		for i, h := range hosts {
			ids = append(ids, h.ID)
			if i < maxListed {
				names = append(names, "• "+oneLine(h.Hostname, 64))
			}
		}
		if len(hosts) > maxListed {
			names = append(names, fmt.Sprintf("…and %d more", len(hosts)-maxListed))
		}
		out = append(out, outEvent{
			ev: model.Event{Kind: model.EventPipelineError,
				Detail: fmt.Sprintf("%d hosts fail vulnerability matching — check the server log", len(hosts)) + "\n" + strings.Join(names, "\n")},
			onSuccess: mark(ids...),
		})
	} else {
		for _, h := range hosts {
			out = append(out, outEvent{
				ev:        model.Event{Kind: model.EventPipelineError, Host: h, Detail: details[h.ID], WebURL: m.hostURL(h.ID)},
				onSuccess: mark(h.ID),
			})
		}
	}
	return m.deliver(ctx, out)
}

func (m *Monitor) clearPending(id string) {
	m.mu.Lock()
	delete(m.pending, id)
	m.mu.Unlock()
}

// --- helpers ----------------------------------------------------------------

// HumanDuration formats d coarsely: 47m, 3h5m, 2d4h.
func HumanDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		h := int(d.Hours())
		if m := int(d.Minutes()) % 60; m > 0 && h < 10 {
			return fmt.Sprintf("%dh%dm", h, m)
		}
		return fmt.Sprintf("%dh", h)
	}
	days := int(d.Hours()) / 24
	if h := int(d.Hours()) % 24; h > 0 && days < 10 {
		return fmt.Sprintf("%dd%dh", days, h)
	}
	return fmt.Sprintf("%dd", days)
}

// oneLine removes control characters and cuts s to max runes.
func oneLine(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if unicode.IsControl(r) {
			r = ' '
		}
		if n++; n > max {
			b.WriteString("…")
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}
