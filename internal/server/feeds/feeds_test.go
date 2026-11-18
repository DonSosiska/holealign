package feeds

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/DonSosiska/holealign/internal/server/store"
)

type fakeDB struct {
	mu      sync.Mutex
	ready   bool
	updates int
	loads   int
	err     error
	changed bool
}

func (f *fakeDB) Reload(_ context.Context, update bool) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if update {
		f.updates++
	} else {
		f.loads++
	}
	if f.err != nil && update {
		return false, f.err
	}
	f.ready = true
	return f.changed, nil
}
func (f *fakeDB) Ready() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.ready }

func newStore(t *testing.T) *store.SQLite {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func waitKV(st store.Store, key string) {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if v, err := st.KVGet(context.Background(), key); err == nil && v != "" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestUpdateDisabledNeverUsesNetwork(t *testing.T) {
	db := &fakeDB{changed: true}
	called := 0
	u := &Updater{DB: db, Store: newStore(t), Interval: time.Hour, Update: false, OnUpdated: func(context.Context) { called++ }}
	u.Run(context.Background()) // must return by itself
	if db.updates != 0 || db.loads != 1 || called != 1 {
		t.Fatalf("updates=%d loads=%d called=%d", db.updates, db.loads, called)
	}
}

func TestUpdateRecordsTimestampsAndTriggers(t *testing.T) {
	db := &fakeDB{changed: true}
	st := newStore(t)
	var mu sync.Mutex
	called := 0
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	u := &Updater{DB: db, Store: st, Interval: time.Hour, Update: true, OnUpdated: func(context.Context) { mu.Lock(); called++; mu.Unlock() }}
	go func() { u.Run(ctx); close(done) }()
	waitKV(st, KVUpdatedAt)
	cancel()
	<-done
	for _, k := range []string{KVCheckedAt, KVUpdatedAt} {
		if v, err := st.KVGet(context.Background(), k); err != nil || v == "" {
			t.Fatalf("%s: %q %v", k, v, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if called < 2 { // initial load + update
		t.Fatalf("OnUpdated called %d times", called)
	}
}

func TestOfflineKeepsRunning(t *testing.T) {
	db := &fakeDB{err: errors.New("network down"), ready: true}
	st := newStore(t)
	u := &Updater{DB: db, Store: st, Interval: time.Hour, Update: true}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { u.Run(ctx); close(done) }()
	waitKV(st, KVLastError)
	cancel()
	<-done
	if v, _ := st.KVGet(context.Background(), KVLastError); v != "network down" {
		t.Fatalf("last_error=%q", v)
	}
	if _, err := st.KVGet(context.Background(), KVCheckedAt); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("checked_at must not be set on failure")
	}
}

type panicDB struct{ fakeDB }

func (p *panicDB) Reload(_ context.Context, update bool) (bool, error) {
	if update {
		panic("boom")
	}
	return false, nil
}

func TestUpdaterSurvivesPanic(t *testing.T) {
	st := newStore(t)
	u := &Updater{DB: &panicDB{}, Store: st, Interval: 10 * time.Millisecond, Update: true}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() { u.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("updater did not stop")
	}
}

// A DB that becomes usable on the initial load must trigger the re-run even when Reload does not
// report a change, with and without updates (hosts postponed for lack of a DB wait for it).
func TestInitialLoadTriggersRerun(t *testing.T) {
	for _, update := range []bool{false, true} {
		db := &fakeDB{changed: false}
		var mu sync.Mutex
		called := 0
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		u := &Updater{DB: db, Store: newStore(t), Interval: time.Hour, Update: update,
			OnUpdated: func(context.Context) { mu.Lock(); called++; mu.Unlock() }}
		go func() { u.Run(ctx); close(done) }()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			mu.Lock()
			n := called
			mu.Unlock()
			if n > 0 {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		cancel()
		<-done
		mu.Lock()
		if called == 0 {
			t.Fatalf("update=%v: OnUpdated not called after the initial load", update)
		}
		mu.Unlock()
	}
}
