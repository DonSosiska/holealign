package rulesfeed

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DonSosiska/holealign/internal/model"
	"github.com/DonSosiska/holealign/internal/server/store"
)

// kv keys written by the feed (RFC 3339 values, except seq and failures).
const (
	KVSeq       = "rulesfeed.seq"
	KVUpdatedAt = "rulesfeed.updated_at" // last time a bundle was installed
	KVCheckedAt = "rulesfeed.checked_at" // last successful poll (the feed answered with a valid pointer)
	KVLastError = "rulesfeed.last_error" // last failure, empty when ok
	KVFailures  = "rulesfeed.failures"   // consecutive failed polls
)

const (
	httpTimeout   = 30 * time.Second
	diskSyncEvery = time.Minute
)

// KV is the part of the store the feed needs.
type KV interface {
	KVGet(ctx context.Context, key string) (string, error)
	KVSet(ctx context.Context, key, value string, now time.Time) error
}

// Applier is the rule engine: the feed hands it the accepted rules as the feed layer.
type Applier interface {
	SetFeed(seq uint64, rs []model.Rule)
	Reload(ctx context.Context) error
}

// Options configure a Feed.
type Options struct {
	// URL of latest.json (https:// or file://). Empty: no polling, only imported bundles are used.
	URL      string
	Interval time.Duration
	Keys     []ed25519.PublicKey // trusted keys
	Dir      string              // data_dir/rules-feed
	KV       KV                  // optional
	Engine   Applier
	// OnUpdated runs after a newer bundle became active (typically: re-run the pipeline).
	OnUpdated func(ctx context.Context)
	// ServerVersion is compared with a bundle's min_server_version.
	ServerVersion string
	// RequireSignedPointer refuses unsigned latest.json pointers. Even when false, once a
	// validly signed pointer has been seen on this feed, unsigned pointers are refused
	// (anti-downgrade latch persisted in state.json).
	RequireSignedPointer bool
	Log                  *slog.Logger
	Now                  func() time.Time
	// Client overrides the HTTP client (tests). Timeout and redirect policy are always enforced.
	Client *http.Client
}

// Feed polls the rules feed and installs accepted bundles.
type Feed struct {
	o     Options
	mu    sync.Mutex
	seq   uint64
	floor uint64
}

// New builds a Feed.
func New(o Options) *Feed {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Interval <= 0 {
		o.Interval = 6 * time.Hour
	}
	return &Feed{o: o}
}

// Seq is the sequence number of the active bundle (0: none).
func (f *Feed) Seq() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.seq
}

// LoadPersisted activates the newest valid persisted bundle (signature, hashes, rules and tests
// are verified again). Invalid or untrusted files are logged and skipped.
func (f *Feed) LoadPersisted(ctx context.Context) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loadPersistedLocked(ctx)
}

// seqFloorLocked returns the highest sequence number this server has ever accepted (active, in
// state.json, or mirrored in KV), latching f.floor monotonically upwards. Caller holds f.mu.
func (f *Feed) seqFloorLocked(ctx context.Context) uint64 {
	if f.seq > f.floor {
		f.floor = f.seq
	}
	if st := ReadState(f.o.Dir); st.Seq > f.floor {
		f.floor = st.Seq
	}
	if f.o.KV != nil {
		if raw, err := f.o.KV.KVGet(ctx, KVSeq); err == nil {
			if n, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 64); err == nil && n > f.floor {
				f.floor = n
			}
		}
	}
	return f.floor
}

func (f *Feed) loadPersistedLocked(ctx context.Context) bool {
	seqs := persistedSeqs(f.o.Dir)
	if len(seqs) == 0 || seqs[0] <= f.seq {
		return false
	}
	floor := f.seqFloorLocked(ctx)
	if seqs[0] < floor {
		f.o.Log.Warn("rules feed: refusing persisted bundle older than recorded floor",
			"disk_seq", seqs[0], "floor_seq", floor)
		return false
	}
	inst, skipped := LoadInstalled(f.o.Dir, f.o.Keys, f.o.ServerVersion)
	for _, err := range skipped {
		f.o.Log.Warn("rules feed: ignoring persisted bundle", "err", err)
	}
	if inst == nil || inst.Bundle.Index.Seq <= f.seq {
		return false
	}
	if inst.Bundle.Index.Seq < floor {
		f.o.Log.Warn("rules feed: refusing persisted bundle older than recorded floor",
			"disk_seq", inst.Bundle.Index.Seq, "floor_seq", floor)
		return false
	}
	f.activate(ctx, inst.Bundle)
	f.o.Log.Info("rules feed: loaded persisted bundle", "seq", inst.Bundle.Index.Seq, "rules", len(inst.Bundle.Rules))
	return true
}

// activate hands the rules to the engine and mirrors the state. Caller holds f.mu.
func (f *Feed) activate(ctx context.Context, b *Bundle) {
	f.seq = b.Index.Seq
	if b.Index.Seq > f.floor {
		f.floor = b.Index.Seq
	}
	if f.o.Engine != nil {
		f.o.Engine.SetFeed(b.Index.Seq, b.Rules)
		if err := f.o.Engine.Reload(ctx); err != nil {
			f.o.Log.Warn("rules feed: reload engine", "err", err)
		}
	}
	f.kv(ctx, KVSeq, strconv.FormatUint(b.Index.Seq, 10))
}

// Run loads the persisted bundle, polls once, then every Interval; the persisted directory is
// also re-checked every minute so an imported bundle (`rules import`) becomes active quickly.
// It blocks until ctx is done.
func (f *Feed) Run(ctx context.Context) {
	f.LoadPersisted(ctx)
	last := time.Time{}
	t := time.NewTicker(diskSyncEvery)
	defer t.Stop()
	for {
		f.guard("tick", func() {
			if f.o.URL != "" && (last.IsZero() || f.o.Now().Sub(last) >= f.o.Interval) {
				last = f.o.Now()
				if err := f.Poll(ctx); err != nil && ctx.Err() == nil {
					f.o.Log.Warn("rules feed: poll failed; keeping the installed rules", "err", err)
				}
				return
			}
			f.syncFromDisk(ctx)
		})
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (f *Feed) syncFromDisk(ctx context.Context) {
	f.mu.Lock()
	changed := f.loadPersistedLocked(ctx)
	f.mu.Unlock()
	if changed && f.o.OnUpdated != nil {
		f.o.OnUpdated(ctx)
	}
}

// Poll fetches latest.json and installs a newer bundle. The returned error is also recorded in
// rulesfeed.last_error; a pointer that is not newer than the installed bundle is not an error.
func (f *Feed) Poll(ctx context.Context) error {
	if f.o.URL == "" {
		return errors.New("rules.feed.url is not set")
	}
	f.mu.Lock()
	st := ReadState(f.o.Dir)
	b, sawSigned, err := f.poll(ctx, st.SignedPointerSeen)
	if f.seq > st.Seq {
		st.Seq = f.seq
	}
	now := f.o.Now().UTC().Format(time.RFC3339)
	if err != nil {
		st.Failures++
		st.LastError = oneLine(err.Error())
		f.kv(ctx, KVLastError, st.LastError)
	} else {
		if sawSigned {
			st.SignedPointerSeen = true
		}
		st.Failures, st.LastError, st.CheckedAt = 0, "", now
		f.kv(ctx, KVCheckedAt, now)
		f.kv(ctx, KVLastError, "")
		if b != nil {
			st.UpdatedAt = now
			f.kv(ctx, KVUpdatedAt, now)
		}
	}
	f.kv(ctx, KVFailures, strconv.Itoa(st.Failures))
	if werr := writeState(f.o.Dir, st); werr != nil {
		f.o.Log.Warn("rules feed: write state", "err", werr)
	}
	f.mu.Unlock()
	if b != nil && f.o.OnUpdated != nil {
		f.o.OnUpdated(ctx)
	}
	return err
}

// poll runs one poll cycle; it returns the newly activated bundle (if any) and whether the
// pointer carried a valid signature. Caller holds f.mu.
func (f *Feed) poll(ctx context.Context, signedSeen bool) (*Bundle, bool, error) {
	base, err := url.Parse(f.o.URL)
	if err != nil {
		return nil, false, fmt.Errorf("rules.feed.url: %w", err)
	}
	raw, err := f.fetch(ctx, base, MaxPointerBytes)
	if err != nil {
		return nil, false, fmt.Errorf("latest.json: %w", err)
	}
	var ptr Pointer
	if err := json.Unmarshal(raw, &ptr); err != nil {
		return nil, false, fmt.Errorf("latest.json: %w", err)
	}
	if ptr.Seq == 0 {
		return nil, false, errors.New("latest.json: seq is missing")
	}
	// Verify pointer signature and freshness BEFORE the ptr.Seq == f.seq short-circuit so a
	// frozen/expired or tampered pointer is detected even when seq has not advanced.
	sawSigned := false
	if ptr.PointerSig != nil || ptr.SignedAt != "" || ptr.ExpiresAt != "" {
		if err := VerifyPointer(ptr, f.o.Keys, f.o.Now()); err != nil {
			return nil, false, fmt.Errorf("latest.json: %w", err)
		}
		sawSigned = true
	} else {
		if f.o.RequireSignedPointer {
			return nil, false, errors.New("latest.json: unsigned pointer refused (rules.feed.require_signed_pointer is enabled)")
		}
		if signedSeen {
			return nil, false, errors.New("latest.json: unsigned pointer refused (downgrade from a previously signed feed)")
		}
	}
	floor := f.seqFloorLocked(ctx)
	switch {
	case ptr.Seq < floor:
		f.o.Log.Warn("rules feed: refusing a pointer to an older bundle (rollback attempt or publisher mistake)",
			"pointer_seq", ptr.Seq, "installed_seq", floor)
		return nil, false, fmt.Errorf("latest.json: rollback refused: pointer seq %d is older than installed seq %d", ptr.Seq, floor)
	case ptr.Seq == f.seq && f.seq > 0:
		return nil, sawSigned, nil
	}
	ref, err := url.Parse(ptr.URL)
	if err != nil || ptr.URL == "" {
		return nil, false, errors.New("latest.json: url is missing or invalid")
	}
	target := base.ResolveReference(ref)
	if target.Scheme != base.Scheme {
		return nil, false, fmt.Errorf("latest.json: bundle url scheme %q differs from the pointer's %q", target.Scheme, base.Scheme)
	}
	if hostPort(target) != hostPort(base) || target.User != nil {
		// keep the bundle fetch pinned to the pointer's own origin
		return nil, false, fmt.Errorf("latest.json: bundle url host %q differs from the pointer's %q", hostPort(target), hostPort(base))
	}
	tb, err := f.fetch(ctx, target, MaxBundleBytes)
	if err != nil {
		return nil, false, fmt.Errorf("bundle %d: %w", ptr.Seq, err)
	}
	if got := sha256Hex(tb); got != ptr.SHA256 {
		return nil, false, fmt.Errorf("bundle %d: sha256 %s does not match the pointer (%s)", ptr.Seq, got, ptr.SHA256)
	}
	if err := VerifySig(tb, ptr.Sig, f.o.Keys); err != nil {
		return nil, false, fmt.Errorf("bundle %d: %w", ptr.Seq, err)
	}
	b, err := Open(tb, f.o.ServerVersion)
	if err != nil {
		return nil, false, err
	}
	// A replayed old (validly signed) bundle must not be installed under a newer sequence number.
	if b.Index.Seq != ptr.Seq {
		return nil, false, fmt.Errorf("bundle %d: index.json says seq %d", ptr.Seq, b.Index.Seq)
	}
	if err := persist(f.o.Dir, b.Index.Seq, tb, ptr.Sig); err != nil {
		return nil, false, fmt.Errorf("persist bundle %d: %w", ptr.Seq, err)
	}
	f.activate(ctx, b)
	f.o.Log.Info("rules feed: installed bundle", "seq", b.Index.Seq, "rules", len(b.Rules), "tests", len(b.Tests))
	return b, sawSigned, nil
}

// hostPort is the lower-case host and effective port of u (the scheme's default port when none is given).
func hostPort(u *url.URL) string {
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return strings.ToLower(u.Hostname()) + ":" + port
}

// fetch reads at most max bytes from an https:// or file:// URL (no redirects, 30 s timeout).
func (f *Feed) fetch(ctx context.Context, u *url.URL, max int64) ([]byte, error) {
	switch u.Scheme {
	case "file":
		if u.Host != "" && u.Host != "localhost" {
			return nil, errors.New("file:// URL must not name a host")
		}
		return readLimited(u.Path, max)
	case "https":
	default:
		return nil, fmt.Errorf("unsupported URL scheme %q (want https or file)", u.Scheme)
	}
	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "holealign-server")
	var c http.Client
	if f.o.Client != nil {
		c = *f.o.Client
	}
	c.Timeout = httpTimeout
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d (redirects are not followed)", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("response is larger than %d bytes", max)
	}
	return b, nil
}

func (f *Feed) kv(ctx context.Context, k, v string) {
	if f.o.KV == nil {
		return
	}
	if err := f.o.KV.KVSet(ctx, k, v, f.o.Now()); err != nil {
		f.o.Log.Warn("rules feed: write kv", "key", k, "err", err)
	}
}

func (f *Feed) guard(what string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			f.o.Log.Error("rules feed panicked; continuing", "where", what, "panic", r, "stack", string(debug.Stack()))
		}
	}()
	fn()
}

func oneLine(s string) string {
	b := []rune(s)
	if len(b) > 500 {
		b = append(b[:500], '…')
	}
	for i, r := range b {
		if r < 0x20 {
			b[i] = ' '
		}
	}
	return string(b)
}

// Compile-time check that the real store satisfies KV.
var _ KV = store.Store(nil)
