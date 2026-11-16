package web

import (
	"crypto/rand"
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
)

// limiter counts failed logins per key within a sliding window.
type limiter struct {
	mu    sync.Mutex
	now   func() time.Time
	fails map[string][]time.Time
}

func newLimiter(now func() time.Time) *limiter {
	return &limiter{now: now, fails: map[string][]time.Time{}}
}

func (l *limiter) prune(key string) []time.Time {
	cut := l.now().Add(-failWindow)
	var keep []time.Time
	for _, t := range l.fails[key] {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		delete(l.fails, key)
	} else {
		l.fails[key] = keep
	}
	return keep
}

func (l *limiter) blocked(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.prune(key)) >= maxFailures
}

func (l *limiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.fails) > 10000 { // bound memory under a flood of distinct keys
		l.fails = map[string][]time.Time{}
	}
	l.fails[key] = append(l.prune(key), l.now())
}

func (l *limiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, key)
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
	http.SetCookie(w, s.cookie(loginCSRFName, tok, s.now().Add(time.Hour)))
	s.render(w, r, nil, status, "login", map[string]any{"CSRF": tok, "Error": errMsg, "Username": username})
}

func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	secHeaders(w)
	if s.sessionFrom(r) != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.loginForm(w, r, http.StatusOK, "", "")
}

// dummyHash equalises timing for unknown users.
var dummyHash, _ = store.HashPassword("panoptes-dummy-password")

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	secHeaders(w)
	if !sameOrigin(r) {
		s.fail(w, r, nil, http.StatusForbidden, "Cross-origin request rejected.", nil)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	if err := r.ParseForm(); err != nil {
		s.fail(w, r, nil, http.StatusBadRequest, "Bad form submission.", err)
		return
	}
	c, err := r.Cookie(loginCSRFName)
	if err != nil || c.Value == "" || subtle.ConstantTimeCompare([]byte(c.Value), []byte(r.PostFormValue("csrf"))) != 1 {
		s.fail(w, r, nil, http.StatusForbidden, "Invalid or missing CSRF token. Reload the login page and try again.", nil)
		return
	}
	user := strings.TrimSpace(r.PostFormValue("username"))
	pw := r.PostFormValue("password")
	key := clientIP(r) + "|" + strings.ToLower(user)
	if s.lim.blocked(key) {
		s.log.Warn("web: login rate limited", "user", user, "ip", clientIP(r))
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
	if !store.CheckPassword(hash, pw) || err != nil {
		s.lim.fail(key)
		s.log.Warn("web: login failed", "user", user, "ip", clientIP(r))
		s.loginForm(w, r, http.StatusUnauthorized, "Invalid username or password.", user)
		return
	}
	s.lim.reset(key)
	token, th, err := store.NewSecret("ps_")
	if err != nil {
		s.fail(w, r, nil, http.StatusInternalServerError, "Internal error; see server log.", err)
		return
	}
	now := s.now()
	exp := now.Add(sessionTTL)
	if err := s.d.Store.CreateSession(r.Context(), store.Session{TokenHash: th, Username: u.Username, CreatedAt: now, ExpiresAt: exp}); err != nil {
		s.fail(w, r, nil, http.StatusInternalServerError, "Internal error; see server log.", err)
		return
	}
	_ = s.d.Store.DeleteExpiredSessions(r.Context(), now)
	http.SetCookie(w, s.cookie(cookieName, token, exp))
	http.SetCookie(w, s.cookie(loginCSRFName, "", time.Time{}))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, sess *session) {
	if err := s.d.Store.DeleteSession(r.Context(), store.HashSecret(sess.token)); err != nil {
		s.log.Error("web: delete session", "err", err)
	}
	http.SetCookie(w, s.cookie(cookieName, "", time.Time{}))
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
