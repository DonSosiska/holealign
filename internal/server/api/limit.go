package api

import (
	"container/list"
	"math"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// maxIPKeys bounds the per-client limiter maps; beyond it the least recently used key is evicted
// (an attacker can reset only buckets, never lock other clients out).
const maxIPKeys = 10000

// ipLimiter is a per-key token bucket (burst = perMinute, refill perMinute/min) over a bounded
// LRU map.
type ipLimiter struct {
	mu        sync.Mutex
	perMinute float64
	max       int
	ll        *list.List // front = most recently used
	idx       map[string]*list.Element
}

type ipEntry struct {
	key    string
	tokens float64
	last   time.Time
}

func newIPLimiter(perMinute int) *ipLimiter {
	return &ipLimiter{perMinute: float64(perMinute), max: maxIPKeys, ll: list.New(), idx: map[string]*list.Element{}}
}

// limitKey normalises a client address into a limiter key: IPv4 by address, IPv6 by /64 (one
// customer typically owns a whole /64, so per-address keys would be free to mint), zones stripped.
func limitKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.WithZone("").Unmap()
	if a.Is4() {
		return a.String()
	}
	return netip.PrefixFrom(a, 64).Masked().String()
}

// allow takes one token for the client; false when its bucket is empty. A nil limiter allows everything.
func (l *ipLimiter) allow(client string, now time.Time) bool {
	if l == nil || l.perMinute <= 0 {
		return true
	}
	key := limitKey(client)
	l.mu.Lock()
	defer l.mu.Unlock()
	var e *ipEntry
	if el := l.idx[key]; el != nil {
		l.ll.MoveToFront(el)
		e = el.Value.(*ipEntry)
	} else {
		for l.ll.Len() >= l.max {
			old := l.ll.Back()
			l.ll.Remove(old)
			delete(l.idx, old.Value.(*ipEntry).key)
		}
		e = &ipEntry{key: key, tokens: l.perMinute, last: now}
		l.idx[key] = l.ll.PushFront(e)
	}
	e.tokens = min(l.perMinute, e.tokens+now.Sub(e.last).Seconds()*l.perMinute/60)
	e.last = now
	if e.tokens < 1 {
		return false
	}
	e.tokens--
	return true
}

func (l *ipLimiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.ll.Len()
}

// tokenBucketLimiter is a per-key token bucket: up to burst events at once, refilled at one
// token per interval. A non-positive interval disables the limiter. Buckets that are full and idle
// are dropped, so state of deleted hosts disappears on its own.
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

const sweepAbove = 1024

// sweepLocked drops buckets that have refilled completely.
func (l *tokenBucketLimiter) sweepLocked(now time.Time) {
	full := time.Duration(l.burst+1) * l.interval
	for k, b := range l.buckets {
		if now.Sub(b.last) > full {
			delete(l.buckets, k)
		}
	}
}

func (l *tokenBucketLimiter) refillLocked(b *tokenBucket, now time.Time) {
	if el := now.Sub(b.last); el > 0 {
		b.tokens = math.Min(l.burst, b.tokens+float64(el)/float64(l.interval))
		b.last = now
	}
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
		if len(l.buckets) >= sweepAbove {
			l.sweepLocked(now)
		}
		b = &tokenBucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	l.refillLocked(b, now)
	if b.tokens >= 1 {
		b.tokens--
		return 0
	}
	return time.Duration(math.Ceil((1 - b.tokens) * float64(l.interval)))
}

// peek is take without spending: 0 when an event would be allowed now.
func (l *tokenBucketLimiter) peek(key string, now time.Time) time.Duration {
	if l.interval <= 0 {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	if b == nil {
		return 0
	}
	l.refillLocked(b, now)
	if b.tokens >= 1 {
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

func (l *tokenBucketLimiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
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
