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

	"panoptes/internal/server/store"
)

const (
	maxFailures = 5
	failWindow  = 5 * time.Minute

	maxIPFailures   = 20
	ipFailWindow    = 5 * time.Minute
	maxUserFailures = 10
	userFailWindow  = 15 * time.Minute
	userLockFor     = 15 * time.Minute

	limiterCap     = 50000
	bcryptParallel = 4
)

type limEntry struct {
	key   string
	fails []time.Time
	until time.Time // lock expiry (zero when no lock)
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
	return len(e.fails) == 0 && !l.now().Before(e.until)
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
	if len(e.fails) == 0 && !l.now().Before(e.until) {
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

// loginBlocked reports whether any of the three limiters blocks this attempt.
func (s *Server) loginBlocked(ip, user string) bool {
	return s.limIP.blocked(ip) || s.limUser.blocked(user) || s.lim.blocked(ip+"|"+user)
}

// loginFailed records a failure in all three limiters.
func (s *Server) loginFailed(ip, user string) {
	s.limIP.fail(ip)
	s.lim.fail(ip + "|" + user)
	if s.limUser.fail(user) {
		s.log.Warn("web: username locked after repeated failures", "user", user, "ip", ip, "lock", userLockFor.String())
	}
}

// checkPassword runs a bcrypt comparison under a small concurrency limit so floods cannot exhaust CPU.
func (s *Server) checkPassword(ctx context.Context, hash, pw string) (bool, error) {
	select {
	case s.bcryptSem <- struct{}{}:
		defer func() { <-s.bcryptSem }()
	case <-ctx.Done():
		return false, ctx.Err()
	}
	return store.CheckPassword(hash, pw), nil
}

func clientIP(r *http.Request) string {
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
	if s.sessionFrom(r) != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.loginForm(w, r, http.StatusOK, "", "")
}

// dummyHash equalises timing for unknown users.
var dummyHash, _ = store.HashPassword("panoptes-dummy-password")

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	s.secHeaders(w)
	if !sameOrigin(r) {
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
	ip := clientIP(r)
	lu := strings.ToLower(user)
	if s.loginBlocked(ip, lu) {
		s.log.Warn("web: login rate limited", "user", user, "ip", ip)
		s.loginForm(w, r, http.StatusTooManyRequests, "Too many failed attempts. Try again in a few minutes.", user)
		return
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
		s.fail(w, r, nil, http.StatusServiceUnavailable, "Request cancelled.", nil)
		return
	}
	if !ok || err != nil {
		s.loginFailed(ip, lu)
		s.log.Warn("web: login failed", "user", user, "ip", ip)
		s.loginForm(w, r, http.StatusUnauthorized, "Invalid username or password.", user)
		return
	}
	s.lim.reset(ip + "|" + lu)
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
	args := append([]any{"actor", actor, "action", action, "target", target, "ip", clientIP(r)}, extra...)
	s.log.Info("audit", args...)
}

func sha256hex(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}

// reauth requires the acting user's current password (field current_password). On failure it writes
// the response (403, or 429 when locked) and returns false. Failures count toward the limiters.
func (s *Server) reauth(w http.ResponseWriter, r *http.Request, sess *session) bool {
	ip := clientIP(r)
	lu := strings.ToLower(sess.Username)
	if s.limIP.blocked(ip) || s.limUser.blocked(lu) {
		s.fail(w, r, sess, http.StatusTooManyRequests, "Too many failed password checks. Try again later.", nil)
		return false
	}
	pw := r.PostFormValue("current_password")
	u, err := s.d.Store.GetUser(r.Context(), sess.Username)
	hash := dummyHash
	if err == nil {
		hash = u.PasswordHash
	}
	ok := false
	if pw != "" {
		var cerr error
		ok, cerr = s.checkPassword(r.Context(), hash, pw)
		if cerr != nil {
			s.fail(w, r, sess, http.StatusServiceUnavailable, "Request cancelled.", nil)
			return false
		}
	}
	if !ok || err != nil {
		s.loginFailed(ip, lu)
		s.log.Warn("web: re-authentication failed", "user", sess.Username, "ip", ip, "path", r.URL.Path)
		s.fail(w, r, sess, http.StatusForbidden, "Your current password is required and was missing or incorrect. Nothing was changed.", nil)
		return false
	}
	return true
}
