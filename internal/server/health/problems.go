package health

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/DonSosiska/holealign/internal/model"
	"github.com/DonSosiska/holealign/internal/server/store"
)

// KVNotifyErrors holds the last notifier delivery problems as a JSON array of NotifyProblem
// (oldest first); the web dashboard shows them as a banner.
const KVNotifyErrors = "health.notify_errors"

// maxNotifyProblems is how many distinct problems are kept.
const maxNotifyProblems = 20

// NotifyProblem is one entry of KVNotifyErrors. Room holds the destination ("!id:server",
// "slack:C...", "telegram:..."; the JSON key stays "room" for stored rows). Status 0 is a network
// error; an empty Room means no destination was resolved for the event.
type NotifyProblem struct {
	At        time.Time `json:"at"`
	Room      string    `json:"room"`
	Status    int       `json:"status"`
	Kind      string    `json:"kind"`
	Permanent bool      `json:"permanent"`
}

// NewProblemRecorder returns a callback for notify.Config.OnDeliveryProblem that stores the last
// maxNotifyProblems distinct problems (destination, status, kind) in the kv table with cleaned values.
func NewProblemRecorder(st store.Store, log *slog.Logger) func(room string, status int, kind model.EventKind, permanent bool) {
	if log == nil {
		log = slog.Default()
	}
	var mu sync.Mutex
	return func(room string, status int, kind model.EventKind, permanent bool) {
		mu.Lock()
		defer mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		now := time.Now()
		var list []NotifyProblem
		if raw, err := st.KVGet(ctx, KVNotifyErrors); err == nil && raw != "" {
			_ = json.Unmarshal([]byte(raw), &list) // a corrupt value is replaced
		} else if err != nil && !errors.Is(err, store.ErrNotFound) {
			log.Warn("health: read notify problems", "err", err)
		}
		p := NotifyProblem{At: now.UTC(), Room: oneLine(room, 100), Status: status, Kind: oneLine(string(kind), 32), Permanent: permanent}
		kept := list[:0]
		for _, q := range list {
			if q.Room != p.Room || q.Status != p.Status || q.Kind != p.Kind {
				q.Room, q.Kind = oneLine(q.Room, 100), oneLine(q.Kind, 32)
				kept = append(kept, q)
			}
		}
		kept = append(kept, p)
		if len(kept) > maxNotifyProblems {
			kept = kept[len(kept)-maxNotifyProblems:]
		}
		b, err := json.Marshal(kept)
		if err != nil {
			return
		}
		if err := st.KVSet(ctx, KVNotifyErrors, string(b), now); err != nil {
			log.Warn("health: store notify problems", "err", err)
		}
	}
}
