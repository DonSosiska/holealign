package api

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// ipLimiter is a per-key token bucket (burst = perMinute, refill perMinute/min).
type ipLimiter struct {
	mu        sync.Mutex
	perMinute float64
	buckets   map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newIPLimiter(perMinute int) *ipLimiter {
	return &ipLimiter{perMinute: float64(perMinute), buckets: map[string]*bucket{}}
}

// allow takes one token for key; false when the bucket is empty. A nil limiter allows everything.
func (l *ipLimiter) allow(key string, now time.Time) bool {
	if l == nil || l.perMinute <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	if b == nil {
		if len(l.buckets) > 10000 { // bound memory: drop idle buckets
			for k, o := range l.buckets {
				if now.Sub(o.last) > 10*time.Minute {
					delete(l.buckets, k)
				}
			}
			if len(l.buckets) > 10000 {
				return false
			}
		}
		b = &bucket{tokens: l.perMinute, last: now}
		l.buckets[key] = b
	}
	b.tokens = min(l.perMinute, b.tokens+now.Sub(b.last).Seconds()*l.perMinute/60)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// intervalLimiter enforces a minimum interval between accepted events per key.
type intervalLimiter struct {
	mu   sync.Mutex
	last map[string]time.Time
}

func newIntervalLimiter() *intervalLimiter { return &intervalLimiter{last: map[string]time.Time{}} }

// take returns 0 and records now when the event is allowed, else the time left to wait.
func (l *intervalLimiter) take(key string, every time.Duration, now time.Time) time.Duration {
	if every <= 0 {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if t, ok := l.last[key]; ok {
		if wait := every - now.Sub(t); wait > 0 {
			return wait
		}
	}
	l.last[key] = now
	return 0
}

func (l *intervalLimiter) forget(key string) {
	l.mu.Lock()
	delete(l.last, key)
	l.mu.Unlock()
}

func tooMany(w http.ResponseWriter, wait time.Duration, msg string) {
	secs := int((wait + time.Second - 1) / time.Second)
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeErr(w, http.StatusTooManyRequests, msg)
}

func remoteIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}
