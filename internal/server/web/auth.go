package web

import (
	"container/list"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/DonSosiska/panoptes/internal/server/store"
)

const (
	maxFailures = 5
	failWindow  = 5 * time.Minute

	maxIPFailures = 20
	ipFailWindow  = 5 * time.Minute

	// Per-username progressive delay (never a lock-out: the correct password always works).
	nameFailWindow   = 15 * time.Minute
	nameDelayAfter   = 5 // recent failures before attempts start to wait
	nameBaseDelay    = 250 * time.Millisecond
	nameMaxDelay     = 5 * time.Second
	nameMaxWaiters   = 4  // concurrent delayed attempts per name; more get 429
	nameMaxInflight  = 16 // concurrent attempts per name without a delay
	nameMaxQueueSkew = 3 * nameMaxDelay

	// Re-authentication: failures per session before that session is logged out.
	maxReauthFailures = 5
	reauthWindow      = time.Hour

	limiterCap     = 50000
	bcryptParallel = 4
	bcryptMaxQueue = 32              // goroutines allowed to wait for a bcrypt slot
	bcryptMaxWait  = 5 * time.Second // longest wait for a bcrypt slot -> 503

	maxUsernameLen = 64
	deviceCookie   = "panoptes_device"
	deviceTTL      = 30 * 24 * time.Hour
	maxDevices     = 10   // known devices kept per user
	maxDeviceUsers = 5000 // users tracked
	trustCap       = 10000
)

var errBusy = errors.New("web: too many concurrent password checks")

type limEntry struct {
	key      string
	fails    []time.Time
	until    time.Time // lock expiry (zero when no lock)
	inflight int       // attempts between acquire and release
}

// limiter counts failed attempts per key within a sliding window. It is a bounded LRU: when over
// capacity it evicts expired entries first and then the least recently touched ones, preferring
// entries that are not currently blocking anyone (a flood of junk keys cannot reset a lockout).
type limiter struct {
	mu        sync.Mutex
	now       func() time.Time
	max       int
	window    time.Duration
	lockFor   time.Duration // >0: reaching max locks the key for this long
	cap       int
	items     map[string]*list.Element
	order     *list.List // front = most recently touched
	lastSweep time.Time
}

func newLimiterCfg(now func() time.Time, max int, window, lockFor time.Duration, capacity int) *limiter {
	return &limiter{now: now, max: max, window: window, lockFor: lockFor, cap: capacity,
		items: map[string]*list.Element{}, order: list.New()}
}

func newLimiter(now func() time.Time) *limiter {
	return newLimiterCfg(now, maxFailures, failWindow, 0, limiterCap)
}

func (l *limiter) prune(e *limEntry) {
	cut := l.now().Add(-l.window)
	keep := e.fails[:0]
	for _, t := range e.fails {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	e.fails = keep
}

func (l *limiter) isBlocked(e *limEntry) bool {
	return l.now().Before(e.until) || len(e.fails) >= l.max
}

func (l *limiter) expired(e *limEntry) bool {
	l.prune(e)
	return len(e.fails) == 0 && e.inflight == 0 && !l.now().Before(e.until)
}

// acquire registers an in-flight attempt: it refuses when the key is blocked or when the recorded
// failures plus the attempts already running reach the maximum (so N parallel requests cannot all
// slip past the check before any failure is counted). Every true result must be released.
func (l *limiter) acquire(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	el, ok := l.items[key]
	if !ok {
		el = l.order.PushFront(&limEntry{key: key})
		l.items[key] = el
		l.evict()
	} else {
		l.order.MoveToFront(el)
	}
	e := el.Value.(*limEntry)
	l.prune(e)
	if l.isBlocked(e) || len(e.fails)+e.inflight >= l.max {
		return false
	}
	e.inflight++
	return true
}

func (l *limiter) release(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if el, ok := l.items[key]; ok {
		if e := el.Value.(*limEntry); e.inflight > 0 {
			e.inflight--
		}
	}
}

func (l *limiter) blocked(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	el, ok := l.items[key]
	if !ok {
		return false
	}
	e := el.Value.(*limEntry)
	l.prune(e)
	if l.isBlocked(e) {
		return true
	}
	if len(e.fails) == 0 && e.inflight == 0 && !l.now().Before(e.until) {
		l.order.Remove(el)
		delete(l.items, key)
	}
	return false
}

// fail records a failure and reports whether this failure newly locked the key (lockFor > 0).
func (l *limiter) fail(key string) (locked bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	el, ok := l.items[key]
	if !ok {
		el = l.order.PushFront(&limEntry{key: key})
		l.items[key] = el
	} else {
		l.order.MoveToFront(el)
	}
	e := el.Value.(*limEntry)
	l.prune(e)
	now := l.now()
	e.fails = append(e.fails, now)
	if l.lockFor > 0 && len(e.fails) >= l.max && !now.Before(e.until) {
		e.until = now.Add(l.lockFor)
		e.fails = e.fails[:0]
		locked = true
	}
	l.evict()
	return locked
}

func (l *limiter) evict() {
	if len(l.items) <= l.cap {
		return
	}
	if now := l.now(); now.Sub(l.lastSweep) >= time.Minute {
		l.lastSweep = now
		for el := l.order.Back(); el != nil; {
			prev := el.Prev()
			if e := el.Value.(*limEntry); l.expired(e) {
				l.order.Remove(el)
				delete(l.items, e.key)
			}
			el = prev
		}
	}
	for len(l.items) > l.cap {
		victim := l.order.Back()
		for el := victim; el != nil; el = el.Prev() { // prefer an entry that is not blocking anyone
			if !l.isBlocked(el.Value.(*limEntry)) {
				victim = el
				break
			}
		}
		l.order.Remove(victim)
		delete(l.items, victim.Value.(*limEntry).key)
	}
}

func (l *limiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if el, ok := l.items[key]; ok {
		l.order.Remove(el)
		delete(l.items, key)
	}
}

// ---------------------------------------------------------------------------
// keys
// ---------------------------------------------------------------------------

// ipKey is the limiter key of a client address: IPv6 clients share a /64 (one subscriber owns it).
func ipKey(ip string) string {
	a := net.ParseIP(ip)
	if a == nil {
		if len(ip) > maxUsernameLen {
			return "h:" + sha256hex(ip)[:32]
		}
		return ip
	}
	if v4 := a.To4(); v4 != nil {
		return v4.String()
	}
	return a.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// userKey is the limiter key of a (lower-cased) username; long values are hashed.
func userKey(u string) string {
	if len(u) > maxUsernameLen {
		return "h:" + sha256hex(u)[:32]
	}
	return u
}

// trunc64 shortens an untrusted value for logging.
func trunc64(s string) string {
	if len(s) > maxUsernameLen {
		s = s[:maxUsernameLen]
		for !utf8.ValidString(s) && len(s) > 0 {
			s = s[:len(s)-1]
		}
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, s)
}

func validUsername(u string) bool { return len(u) <= maxUsernameLen && nameRe.MatchString(u) }

// ---------------------------------------------------------------------------
// per-username progressive delay
// ---------------------------------------------------------------------------

type nameState struct {
	fails    []time.Time
	nextSlot time.Time
	waiters  int
}

// nameGate slows guessing of one username without ever locking it: after nameDelayAfter recent
// failures every further attempt waits min(250ms * 2^k, 5s), and the waits are serialised through
// time slots so parallel connections do not multiply the guess rate (<= ~12 attempts/min).
type nameGate struct {
	mu  sync.Mutex
	now func() time.Time
	m   map[string]*nameState
}

func newNameGate(now func() time.Time) *nameGate {
	return &nameGate{now: now, m: map[string]*nameState{}}
}

func (g *nameGate) prune(st *nameState) {
	cut := g.now().Add(-nameFailWindow)
	keep := st.fails[:0]
	for _, t := range st.fails {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	st.fails = keep
}

// enter reserves a slot. It returns the time to wait before the password check and false when too
// many attempts for this name are already waiting. Every true result must be followed by exit.
func (g *nameGate) enter(name string) (time.Duration, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	st := g.m[name]
	if st == nil {
		if len(g.m) >= limiterCap {
			g.sweep()
		}
		st = &nameState{}
		g.m[name] = st
	}
	g.prune(st)
	n := len(st.fails)
	if n < nameDelayAfter {
		if st.waiters >= nameMaxInflight {
			return 0, false
		}
		st.waiters++
		return 0, true
	}
	if st.waiters >= nameMaxWaiters {
		return 0, false
	}
	k := min(n-nameDelayAfter, 8)
	d := min(nameBaseDelay<<uint(k), nameMaxDelay)
	now := g.now()
	begin := st.nextSlot
	if begin.Before(now) {
		begin = now
	}
	if limit := now.Add(nameMaxQueueSkew); begin.After(limit) {
		begin = limit
	}
	st.nextSlot = begin.Add(d)
	st.waiters++
	return begin.Sub(now) + d, true
}

func (g *nameGate) exit(name string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if st := g.m[name]; st != nil && st.waiters > 0 {
		st.waiters--
	}
}

func (g *nameGate) fail(name string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	st := g.m[name]
	if st == nil {
		st = &nameState{}
		g.m[name] = st
	}
	g.prune(st)
	st.fails = append(st.fails, g.now())
}

func (g *nameGate) reset(name string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if st := g.m[name]; st != nil {
		st.fails, st.nextSlot = nil, time.Time{}
	}
}

// sweep drops idle names (caller holds mu).
func (g *nameGate) sweep() {
	for k, st := range g.m {
		g.prune(st)
		if len(st.fails) == 0 && st.waiters == 0 {
			delete(g.m, k)
		}
	}
	for k, st := range g.m { // still full: drop arbitrary idle names rather than grow
		if len(g.m) < limiterCap {
			break
		}
		if st.waiters == 0 {
			delete(g.m, k)
		}
	}
}

// ---------------------------------------------------------------------------
// trusted sources: valid session from this IP, known-device cookie
// ---------------------------------------------------------------------------

type trustSet struct {
	mu  sync.Mutex
	now func() time.Time
	m   map[string]time.Time // ipKey|user -> last seen with a valid session
}

func (t *trustSet) mark(ik, user string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	k := ik + "|" + user
	now := t.now()
	if at, ok := t.m[k]; ok && now.Sub(at) < time.Minute {
		return
	}
	if len(t.m) >= trustCap {
		for kk, at := range t.m {
			if now.Sub(at) > sessionIdle {
				delete(t.m, kk)
			}
		}
		if _, ok := t.m[k]; !ok && len(t.m) >= trustCap {
			return
		}
	}
	t.m[k] = now
}

func (t *trustSet) has(ik, user string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	at, ok := t.m[ik+"|"+user]
	return ok && t.now().Sub(at) <= sessionIdle
}

// deviceStore remembers "known device" cookies per user (only their SHA-256 is kept, in memory).
type deviceStore struct {
	mu  sync.Mutex
	now func() time.Time
	m   map[string]map[string]time.Time // user -> sha256(token) -> expiry
}

func (d *deviceStore) issue(user string) (string, bool) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", false
	}
	tok := hex.EncodeToString(b)
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	set := d.m[user]
	if set == nil {
		if len(d.m) >= maxDeviceUsers {
			return "", false
		}
		set = map[string]time.Time{}
		d.m[user] = set
	}
	for h, exp := range set {
		if !exp.After(now) {
			delete(set, h)
		}
	}
	for len(set) >= maxDevices { // drop the device that expires first
		var oldest string
		var oe time.Time
		for h, exp := range set {
			if oldest == "" || exp.Before(oe) {
				oldest, oe = h, exp
			}
		}
		delete(set, oldest)
	}
	set[sha256hex(tok)] = now.Add(deviceTTL)
	return tok, true
}

func (d *deviceStore) valid(user, tok string) bool {
	if tok == "" || len(tok) > 128 {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	exp, ok := d.m[user][sha256hex(tok)]
	return ok && exp.After(d.now())
}

// trustedAttempt reports whether a login attempt comes from an address with a valid session for
// the user or from a browser holding one of the user's known-device cookies; those skip the delay.
func (s *Server) trustedAttempt(r *http.Request, ik, lu string) bool {
	if s.trust.has(ik, lu) {
		return true
	}
	if c, err := r.Cookie(s.devName); err == nil {
		return s.devices.valid(lu, c.Value)
	}
	return false
}

// ---------------------------------------------------------------------------
// password checks
// ---------------------------------------------------------------------------

// loginFailed records a failed attempt in the per-(IP,user) and per-IP limiters and, for attempts
// that did not come from a trusted source, in the per-username delay.
func (s *Server) loginFailed(ik, uk string, trusted bool) {
	s.limIP.fail(ik)
	s.lim.fail(ik + "|" + uk)
	if !trusted {
		s.names.fail(uk)
	}
}

// checkPassword runs a bcrypt comparison under a small concurrency limit so floods cannot exhaust
// CPU. At most bcryptMaxQueue goroutines wait for a slot, each for at most bcryptMaxWait (errBusy).
func (s *Server) checkPassword(ctx context.Context, hash, pw string) (bool, error) {
	select {
	case s.bcryptSem <- struct{}{}:
	default:
		if s.bcryptWaiting.Add(1) > bcryptMaxQueue {
			s.bcryptWaiting.Add(-1)
			return false, errBusy
		}
		t := time.NewTimer(bcryptMaxWait)
		defer t.Stop()
		select {
		case s.bcryptSem <- struct{}{}:
			s.bcryptWaiting.Add(-1)
		case <-t.C:
			s.bcryptWaiting.Add(-1)
			return false, errBusy
		case <-ctx.Done():
			s.bcryptWaiting.Add(-1)
			return false, ctx.Err()
		}
	}
	defer func() { <-s.bcryptSem }()
	return store.CheckPassword(hash, pw), nil
}

func remoteIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

func randHex() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Server) cookie(name, value string, expires time.Time) *http.Cookie {
	c := &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: s.secure}
	if value == "" {
		c.MaxAge = -1
	} else {
		c.Expires = expires
	}
	return c
}

// loginForm renders the login page and sets a pre-session CSRF cookie (double submit).
func (s *Server) loginForm(w http.ResponseWriter, r *http.Request, status int, errMsg, username string) {
	tok := randHex()
	http.SetCookie(w, s.cookie(s.loginName, tok, s.now().Add(time.Hour)))
	s.render(w, r, nil, status, "login", map[string]any{"CSRF": tok, "Error": errMsg, "Username": username})
}

func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	s.secHeaders(w)
	if !s.hostOK(r) {
		s.badHost(w)
		return
	}
	if s.sessionFrom(r) != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.loginForm(w, r, http.StatusOK, "", "")
}

// dummyHash equalises timing for unknown users.
var dummyHash, _ = store.HashPassword("panoptes-dummy-password")

const loginFailMsg = "Invalid username or password."

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	s.secHeaders(w)
	if !s.hostOK(r) || !s.sameOrigin(r) {
		s.fail(w, r, nil, http.StatusForbidden, "Cross-origin request rejected.", nil)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	if err := r.ParseForm(); err != nil {
		s.fail(w, r, nil, http.StatusBadRequest, "Bad form submission.", err)
		return
	}
	c, err := r.Cookie(s.loginName)
	if err != nil || c.Value == "" || subtle.ConstantTimeCompare([]byte(c.Value), []byte(r.PostFormValue("csrf"))) != 1 {
		s.fail(w, r, nil, http.StatusForbidden, "Invalid or missing CSRF token. Reload the login page and try again.", nil)
		return
	}
	user := strings.TrimSpace(r.PostFormValue("username"))
	pw := r.PostFormValue("password")
	// Reject malformed usernames before they reach a limiter key or a log line.
	if !validUsername(user) {
		s.loginForm(w, r, http.StatusUnauthorized, loginFailMsg, "")
		return
	}
	ip := s.ipOf(r)
	ik, lu := ipKey(ip), strings.ToLower(user)
	uk := userKey(lu)

	// Count this attempt as in flight before the (slow) password check: parallel requests cannot
	// all pass a "fewer than N failures" check made before any of them has failed.
	tooMany := func() {
		s.log.Warn("web: login rate limited", "user", trunc64(user), "ip", ip)
		s.loginForm(w, r, http.StatusTooManyRequests, "Too many failed attempts. Try again in a few minutes.", user)
	}
	if !s.limIP.acquire(ik) {
		tooMany()
		return
	}
	defer s.limIP.release(ik)
	if !s.lim.acquire(ik + "|" + uk) {
		tooMany()
		return
	}
	defer s.lim.release(ik + "|" + uk)

	trusted := s.trustedAttempt(r, ik, lu)
	if !trusted {
		wait, ok := s.names.enter(uk)
		if !ok {
			tooMany()
			return
		}
		defer s.names.exit(uk)
		if wait > 0 {
			if err := s.sleep(r.Context(), wait); err != nil {
				s.fail(w, r, nil, http.StatusServiceUnavailable, "Request cancelled.", nil)
				return
			}
		}
	}

	u, err := s.d.Store.GetUser(r.Context(), user)
	hash := dummyHash
	if err == nil {
		hash = u.PasswordHash
	} else if !errors.Is(err, store.ErrNotFound) {
		s.fail(w, r, nil, http.StatusInternalServerError, "Internal error; see server log.", err)
		return
	}
	ok, cerr := s.checkPassword(r.Context(), hash, pw)
	if cerr != nil {
		s.fail(w, r, nil, http.StatusServiceUnavailable, "The server is busy or the request was cancelled. Try again.", nil)
		return
	}
	if !ok || err != nil {
		s.loginFailed(ik, uk, trusted)
		s.log.Warn("web: login failed", "user", trunc64(user), "ip", ip)
		s.loginForm(w, r, http.StatusUnauthorized, loginFailMsg, user)
		return
	}
	s.lim.reset(ik + "|" + uk)
	s.names.reset(uk)
	token, th, err := store.NewSecret("ps_")
	if err != nil {
		s.fail(w, r, nil, http.StatusInternalServerError, "Internal error; see server log.", err)
		return
	}
	now := s.now()
	exp := now.Add(sessionIdle) // idle expiry; refreshed on use up to sessionTTL from creation
	if err := s.d.Store.CreateSession(r.Context(), store.Session{TokenHash: th, Username: u.Username, CreatedAt: now, ExpiresAt: exp}); err != nil {
		s.fail(w, r, nil, http.StatusInternalServerError, "Internal error; see server log.", err)
		return
	}
	_ = s.d.Store.DeleteExpiredSessions(r.Context(), now)
	http.SetCookie(w, s.cookie(s.sessName, token, now.Add(sessionTTL)))
	http.SetCookie(w, s.cookie(s.loginName, "", time.Time{}))
	if dc, err := r.Cookie(s.devName); err != nil || !s.devices.valid(lu, dc.Value) {
		if tok, ok := s.devices.issue(lu); ok {
			c := s.cookie(s.devName, tok, now.Add(deviceTTL))
			c.MaxAge = int(deviceTTL / time.Second)
			http.SetCookie(w, c)
		}
	}
	s.trust.mark(ik, lu)
	s.audit(r, u.Username, "login", u.Username)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, sess *session) {
	if err := s.d.Store.DeleteSession(r.Context(), store.HashSecret(sess.token)); err != nil {
		s.log.Error("web: delete session", "err", err)
	}
	http.SetCookie(w, s.cookie(s.sessName, "", time.Time{}))
	s.audit(r, sess.Username, "logout", sess.Username)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// audit writes a structured audit entry for a security-relevant action.
func (s *Server) audit(r *http.Request, actor, action, target string, extra ...any) {
	args := append([]any{"actor", actor, "action", action, "target", target, "ip", s.ipOf(r)}, extra...)
	s.log.Info("audit", args...)
}

func sha256hex(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}

// reauth requires the acting user's current password (field current_password). It deliberately
// does not consult or feed the login limiters: a third party's failed logins can never block an
// admin's re-authentication, and a stolen session cannot lock the real admin out of logging in.
// Failures are counted per session; the maxReauthFailures-th one logs that session out.
// On failure it writes the response and returns false.
func (s *Server) reauth(w http.ResponseWriter, r *http.Request, sess *session) bool {
	const msg = "Your current password is required and was missing or incorrect. Nothing was changed."
	pw := r.PostFormValue("current_password")
	if pw == "" {
		s.fail(w, r, sess, http.StatusForbidden, msg, nil)
		return false
	}
	key := sha256hex(sess.token)
	if !s.reauthLim.acquire(key) {
		s.fail(w, r, sess, http.StatusTooManyRequests, "Too many failed password checks. Try again later.", nil)
		return false
	}
	defer s.reauthLim.release(key)
	u, err := s.d.Store.GetUser(r.Context(), sess.Username)
	hash := dummyHash
	if err == nil {
		hash = u.PasswordHash
	}
	ok, cerr := s.checkPassword(r.Context(), hash, pw)
	if cerr != nil {
		s.fail(w, r, sess, http.StatusServiceUnavailable, "The server is busy or the request was cancelled. Try again.", nil)
		return false
	}
	if ok && err == nil {
		s.reauthLim.reset(key)
		return true
	}
	s.reauthLim.fail(key)
	s.log.Warn("web: re-authentication failed", "user", trunc64(sess.Username), "ip", s.ipOf(r), "path", r.URL.Path)
	if s.reauthLim.blocked(key) {
		if err := s.d.Store.DeleteSession(r.Context(), store.HashSecret(sess.token)); err != nil {
			s.log.Error("web: delete session", "err", err)
		}
		http.SetCookie(w, s.cookie(s.sessName, "", time.Time{}))
		s.audit(r, sess.Username, "session_revoked_reauth_failures", sess.Username)
		s.fail(w, r, nil, http.StatusForbidden, "Too many wrong passwords: you have been logged out. Nothing was changed.", nil)
		return false
	}
	s.fail(w, r, sess, http.StatusForbidden, msg, nil)
	return false
}
