// Package feeds keeps the vulnerability data fresh. Grype DB v6 already bundles CISA KEV and
// FIRST EPSS, so one DB refresh covers all three feeds; timestamps go to the store's kv table.
package feeds

import (
	"context"
	"log/slog"
	"time"

	"panoptes/internal/server/store"
)

// kv keys written by the updater (RFC 3339 values).
const (
	KVCheckedAt = "feeds.grype.checked_at" // last successful load/update attempt
	KVUpdatedAt = "feeds.grype.updated_at" // last time a newer DB was installed
	KVLastError = "feeds.grype.last_error" // last failure, empty when ok
)

// DB is the vulnerability DB being kept fresh (implemented by match.Grype).
type DB interface {
	// Reload loads the DB from disk; with update it tries to download a newer one first.
	// It reports whether the DB in use changed.
	Reload(ctx context.Context, update bool) (changed bool, err error)
	Ready() bool
}

// Updater refreshes the DB on start and every Interval.
type Updater struct {
	DB       DB
	Store    store.Store
	Interval time.Duration
	Update   bool // false: never touch the network, only load what is on disk
	// OnUpdated is called after a new DB became active (and once after the initial load),
	// typically to re-run the pipeline for all hosts.
	OnUpdated func(ctx context.Context)
	Log       *slog.Logger
	Now       func() time.Time
	// RetryInterval is how soon to retry while no DB is available at all (default 5m).
	RetryInterval time.Duration
}

// Run blocks until ctx is done (or returns right after the initial load when updates are disabled).
func (u *Updater) Run(ctx context.Context) {
	if u.Log == nil {
		u.Log = slog.Default()
	}
	if u.Now == nil {
		u.Now = time.Now
	}
	if u.RetryInterval <= 0 {
		u.RetryInterval = 5 * time.Minute
	}

	// Serve from the on-disk DB immediately so matching works while a download is running.
	if changed, err := u.DB.Reload(ctx, false); err != nil {
		u.Log.Warn("no local grype db yet", "err", err)
	} else if changed && u.OnUpdated != nil {
		u.OnUpdated(ctx)
	}
	if !u.Update {
		u.Log.Info("feed updates disabled (feeds.update=false)")
		return
	}
	for {
		u.once(ctx)
		wait := u.Interval
		if !u.DB.Ready() && u.RetryInterval < wait {
			wait = u.RetryInterval
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func (u *Updater) once(ctx context.Context) {
	now := u.Now().UTC().Format(time.RFC3339)
	changed, err := u.DB.Reload(ctx, true)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		u.Log.Warn("grype db update failed; keeping previous db", "err", err)
		u.kv(ctx, KVLastError, err.Error())
		return
	}
	u.kv(ctx, KVCheckedAt, now)
	u.kv(ctx, KVLastError, "")
	if changed {
		u.kv(ctx, KVUpdatedAt, now)
		if u.OnUpdated != nil {
			u.OnUpdated(ctx)
		}
	}
}

func (u *Updater) kv(ctx context.Context, k, v string) {
	if err := u.Store.KVSet(ctx, k, v, u.Now()); err != nil {
		u.Log.Warn("write feed timestamp", "key", k, "err", err)
	}
}
