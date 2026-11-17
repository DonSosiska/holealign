package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/DonSosiska/panoptes/internal/server/config"
	"github.com/DonSosiska/panoptes/internal/server/store"
)

// pruneInterval is how often the retention job runs (and once at start).
const pruneInterval = 24 * time.Hour

// pruneOnce deletes resolved findings and notification dedup rows older than the configured
// retention (0 = keep forever).
func pruneOnce(ctx context.Context, st store.Store, cfg *config.Config, now time.Time, log *slog.Logger) {
	if d := cfg.Retention.ResolvedFindings.Std(); d > 0 {
		n, err := st.PruneResolvedFindings(ctx, now.Add(-d))
		switch {
		case err != nil:
			log.Error("retention: prune resolved findings", "err", err)
		case n > 0:
			log.Info("retention: pruned resolved findings", "deleted", n, "older_than", d)
		}
	}
	if d := cfg.Retention.Notifications.Std(); d > 0 {
		n, err := st.PruneNotifications(ctx, now.Add(-d))
		switch {
		case err != nil:
			log.Error("retention: prune notifications", "err", err)
		case n > 0:
			log.Info("retention: pruned notification records", "deleted", n, "older_than", d)
		}
	}
}

// startRetention runs pruneOnce at start and then daily until ctx is done. The returned channel
// is closed when the job has stopped.
func startRetention(ctx context.Context, st store.Store, cfg *config.Config, log *slog.Logger) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer recoverLog(log, "retention")
		pruneOnce(ctx, st, cfg, time.Now(), log)
		t := time.NewTicker(pruneInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				func() {
					defer recoverLog(log, "retention pass")
					pruneOnce(ctx, st, cfg, now, log)
				}()
			}
		}
	}()
	return done
}
