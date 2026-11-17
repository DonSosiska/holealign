package api

import (
	"math"
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

// tokenBucketLimiter is a per-key token bucket: up to burst events at once, refilled at one
// token per interval. A non-positive interval disables the limiter.
type tokenBucketLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	burst    float64
	buckets  map[string]*tokenBucket
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

func newTokenBucketLimiter(interval time.Duration, burst int) *tokenBucketLimiter {
	return &tokenBucketLimiter{interval: interval, burst: float64(burst), buckets: map[string]*tokenBucket{}}
}

// take spends one token for key. It returns 0 when the event is allowed, else the time until
// the next token is available. Nothing is spent when the event is refused.
func (l *tokenBucketLimiter) take(key string, now time.Time) time.Duration {
	if l.interval <= 0 {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	if b == nil {
		b = &tokenBucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	if el := now.Sub(b.last); el > 0 {
		b.tokens = math.Min(l.burst, b.tokens+float64(el)/float64(l.interval))
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return 0
	}
	return time.Duration(math.Ceil((1 - b.tokens) * float64(l.interval)))
}

// refund gives back one token for key (an accepted event that failed after the check).
func (l *tokenBucketLimiter) refund(key string) {
	if l.interval <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if b := l.buckets[key]; b != nil {
		b.tokens = math.Min(l.burst, b.tokens+1)
	}
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
