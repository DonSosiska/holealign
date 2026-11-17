// Package web implements the Panoptes admin UI: server-rendered pages, sessions, CSRF protection.
// Everything (templates, CSS, JS) is embedded; no external resources are loaded.
package web

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/DonSosiska/panoptes/internal/model"
	"github.com/DonSosiska/panoptes/internal/server/config"
	"github.com/DonSosiska/panoptes/internal/server/pipeline"
	"github.com/DonSosiska/panoptes/internal/server/store"
)

//go:embed templates/*.html static/*
var assets embed.FS

// RulesService is implemented by internal/server/rules.
type RulesService interface {
	Rules() []model.Rule // effective rules (files + DB)
	Validate(r model.Rule) error
	Reload(ctx context.Context) error
}

// RuleSourcer is optionally implemented by the RulesService: it names the layer each rule comes
// from ("builtin", "feed:<seq>" or "db").
type RuleSourcer interface{ Sources() map[string]string }

// sourceBadge turns an engine source into the UI label and the badge CSS class.
func sourceBadge(src string) (label, class string) {
	switch {
	case src == "builtin":
		return "built-in", "src-builtin"
	case strings.HasPrefix(src, "feed:"):
		return "feed #" + strings.TrimPrefix(src, "feed:"), "src-feed"
	}
	return "local", "src-local"
}

// ruleSources maps rule ID to its raw engine source; empty without an engine.
func (s *Server) ruleSources() map[string]string {
	if rs, ok := s.d.Rules.(RuleSourcer); ok && rs != nil {
		return rs.Sources()
	}
	return nil
}

// Triggerer re-runs the pipeline for all hosts (after rule changes).
type Triggerer interface{ TriggerAll() }

// Deps are the collaborators of the web UI. Rules and Pipeline may be nil.
type Deps struct {
	Store    store.Store
	Rules    RulesService
	Pipeline Triggerer
	Config   *config.Config
	Logger   *slog.Logger
	Now      func() time.Time
	// ClientIP derives the client address (e.g. from X-Forwarded-For behind a trusted proxy). nil: the TCP peer.
	ClientIP func(*http.Request) string
}

// Server serves the UI.
type Server struct {
	d       Deps
	log     *slog.Logger
	now     func() time.Time
	cfg     *config.Config
	pages   map[string]*template.Template
	csrfKey []byte
	lim     *limiter // ip|user
	limIP   *limiter // per client IP, any username
	names   *nameGate
	// reauthLim counts failed re-authentications per session; it is independent of the login limiters.
	reauthLim *limiter
	trust     *trustSet
	devices   *deviceStore
	secure    bool
	ipOf      func(*http.Request) string
	sleep     func(ctx context.Context, d time.Duration) error // injectable for tests

	sessName, loginName, devName string
	bcryptSem                    chan struct{}
	bcryptWaiting                atomic.Int32
	pubURL                       *url.URL // parsed PublicURL, nil when empty or invalid
}

const (
	cookieName     = "panoptes_session"
	loginCSRFName  = "panoptes_login"
	sessionTTL     = 12 * time.Hour // absolute session lifetime
	sessionIdle    = time.Hour      // idle timeout
	sessionRefresh = 5 * time.Minute
	minPasswordLen = 12
	pageSize       = 50
	staleAfter     = 30 * time.Minute
)

// New builds the UI server and parses the embedded templates.
func New(d Deps) (*Server, error) {
	if d.Store == nil {
		return nil, errors.New("web: Store is required")
	}
	s := &Server{d: d, log: d.Logger, now: d.Now, cfg: d.Config}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.cfg == nil {
		c := config.Default()
		s.cfg = &c
	}
	s.ipOf = d.ClientIP
	if s.ipOf == nil {
		s.ipOf = remoteIP
	}
	s.secure = strings.HasPrefix(strings.ToLower(s.cfg.PublicURL), "https")
	s.csrfKey = make([]byte, 32)
	if _, err := rand.Read(s.csrfKey); err != nil {
		return nil, err
	}
	s.lim = newLimiter(s.now)
	s.limIP = newLimiterCfg(s.now, maxIPFailures, ipFailWindow, 0, limiterCap)
	s.names = newNameGate(s.now)
	s.reauthLim = newLimiterCfg(s.now, maxReauthFailures, reauthWindow, 0, limiterCap)
	s.trust = &trustSet{now: s.now, m: map[string]time.Time{}}
	s.devices = &deviceStore{now: s.now, m: map[string]map[string]time.Time{}}
	s.sleep = sleepCtx
	s.bcryptSem = make(chan struct{}, bcryptParallel)
	if u, err := url.Parse(strings.TrimSpace(s.cfg.PublicURL)); err == nil && u.Host != "" && (u.Scheme == "http" || u.Scheme == "https") {
		s.pubURL = u
	}
	s.sessName, s.loginName, s.devName = cookieName, loginCSRFName, deviceCookie
	if s.secure {
		s.sessName, s.loginName, s.devName = "__Host-"+cookieName, "__Host-"+loginCSRFName, "__Host-"+deviceCookie
	} else if !isLoopbackURL(s.cfg.PublicURL) {
		s.log.Warn("web: public_url is plain http and not loopback; credentials and session cookies cross the network unencrypted. Serve the UI over https.", "public_url", s.cfg.PublicURL)
	}
	if err := s.parseTemplates(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Server) parseTemplates() error {
	funcs := template.FuncMap{
		"age": func(t time.Time) string {
			if t.IsZero() {
				return "never"
			}
			return humanAge(s.now().Sub(t))
		},
		"ts": func(t time.Time) string {
			if t.IsZero() {
				return "-"
			}
			return t.UTC().Format("2006-01-02 15:04 UTC")
		},
		"vlabel":  verdictLabel,
		"vclass":  verdictClass,
		"join":    strings.Join,
		"json":    prettyJSON,
		"nvd":     func(id string) string { return "https://nvd.nist.gov/vuln/detail/" + url.PathEscape(id) },
		"osv":     func(id string) string { return "https://osv.dev/vulnerability/" + url.PathEscape(id) },
		"isCVE":   func(id string) bool { return strings.HasPrefix(strings.ToUpper(id), "CVE-") },
		"fixcmd":  pipeline.FixCmd,
		"safeRef": safeRef,
		"clip":    clip,
		"add":     func(a, b int) int { return a + b },
		"pct":     func(f float64) string { return fmt.Sprintf("%.1f%%", f*100) },
		"score":   func(f float64) string { return fmt.Sprintf("%.1f", f) },
		"tbl": func(f []model.Finding, names map[string]string, showHost bool) findingsTbl {
			return findingsTbl{f, names, showHost}
		},
		"gtbl": func(g []store.FindingGroup, names map[string]string, showHost bool) groupsTbl {
			return groupsTbl{g, names, showHost}
		},
		"lbody": func(l listing, names map[string]string, showHost bool) listBody {
			return listBody{l, names, showHost}
		},
		"gfix":         groupFix,
		"srclabel":     func(src string) string { l, _ := sourceBadge(src); return l },
		"srcclass":     func(src string) string { _, c := sourceBadge(src); return c },
		"isfeed":       func(src string) bool { return strings.HasPrefix(src, "feed:") },
		"rclass":       func(st model.RuleStatus) string { return "st-" + string(st) },
		"rstatus":      func(st model.RuleStatus) string { return string(st) },
		"tokenExpired": func(t store.EnrollTokenInfo) bool { return !t.ExpiresAt.IsZero() && s.now().After(t.ExpiresAt) },
		"tokenFull":    func(t store.EnrollTokenInfo) bool { return t.MaxHosts > 0 && t.Hosts >= t.MaxHosts },
	}
	s.pages = map[string]*template.Template{}
	entries, err := fs.Glob(assets, "templates/*.html")
	if err != nil {
		return err
	}
	for _, e := range entries {
		name := strings.TrimSuffix(strings.TrimPrefix(e, "templates/"), ".html")
		if name == "layout" || name == "partials" {
			continue
		}
		t, err := template.New(name).Funcs(funcs).ParseFS(assets, "templates/layout.html", "templates/partials.html", e)
		if err != nil {
			return fmt.Errorf("web: parse %s: %w", e, err)
		}
		s.pages[name] = t
	}
	return nil
}

type listBody struct {
	L         listing
	HostNames map[string]string
	ShowHost  bool
}

type groupsTbl struct {
	Groups    []store.FindingGroup
	HostNames map[string]string
	ShowHost  bool
}

// groupFix summarises the fix of a group: a fixed version when any package has one.
func groupFix(g store.FindingGroup) string {
	for _, f := range g.Findings {
		if len(f.FixedVersions) > 0 {
			return "fix available"
		}
	}
	if len(g.Findings) > 0 && g.Findings[0].FixState != "" {
		return g.Findings[0].FixState
	}
	return ""
}

type findingsTbl struct {
	Findings  []model.Finding
	HostNames map[string]string
	ShowHost  bool
}

// Mount registers all UI routes on mux.
func (s *Server) Mount(mux *http.ServeMux) {
	static, _ := fs.Sub(assets, "static")
	fsrv := http.StripPrefix("/static/", http.FileServer(http.FS(static)))
	mux.HandleFunc("GET /static/", func(w http.ResponseWriter, r *http.Request) {
		s.secHeaders(w)
		name := strings.TrimPrefix(r.URL.Path, "/static/")
		if fi, err := fs.Stat(static, name); name == "" || strings.HasSuffix(name, "/") || err != nil || fi.IsDir() {
			http.NotFound(w, r) // no directory listings
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=3600")
		fsrv.ServeHTTP(w, r)
	})
	mux.HandleFunc("GET /login", s.handleLoginForm)
	mux.HandleFunc("POST /login", s.handleLogin)
	mux.HandleFunc("POST /logout", s.post(s.handleLogout))

	mux.HandleFunc("GET /{$}", s.get(s.handleDashboard))
	mux.HandleFunc("GET /hosts", s.get(s.handleHosts))
	mux.HandleFunc("GET /hosts/{id}", s.get(s.handleHost))
	mux.HandleFunc("GET /findings", s.get(s.handleFindings))
	mux.HandleFunc("GET /findings/{id}", s.get(s.handleFinding))
	mux.HandleFunc("GET /vulns/{id}", s.get(s.handleVuln))
	mux.HandleFunc("GET /rules", s.get(s.handleRules))
	mux.HandleFunc("GET /rules/{id}", s.get(s.handleRule))
	mux.HandleFunc("POST /rules/{id}/edit", s.post(s.handleRuleEdit))
	mux.HandleFunc("POST /rules/{id}/approve", s.post(s.handleRuleSetStatus(model.RuleReviewed)))
	mux.HandleFunc("POST /rules/{id}/reject", s.post(s.handleRuleSetStatus(model.RuleRejected)))
	mux.HandleFunc("GET /settings", s.get(s.handleSettings))
	mux.HandleFunc("POST /settings/matrix", s.post(s.handleMatrixSave))
	mux.HandleFunc("POST /settings/tokens", s.post(s.handleTokenCreate))
	mux.HandleFunc("POST /settings/tokens/{name}/revoke", s.post(s.handleTokenRevoke))
	mux.HandleFunc("POST /settings/users", s.post(s.handleUserAdd))
	mux.HandleFunc("POST /settings/users/{name}/password", s.post(s.handleUserPassword))
	mux.HandleFunc("POST /settings/users/{name}/delete", s.post(s.handleUserDelete))
	mux.HandleFunc("/", s.handleFallback)
}

// ---------------------------------------------------------------------------
// sessions, CSRF, wrappers
// ---------------------------------------------------------------------------

type session struct {
	Username string
	token    string
	CSRF     string
}

func (s *Server) csrfFor(token string) string {
	m := hmac.New(sha256.New, s.csrfKey)
	m.Write([]byte(token))
	return hex.EncodeToString(m.Sum(nil))
}

func (s *Server) sessionFrom(r *http.Request) *session {
	c, err := r.Cookie(s.sessName)
	if err != nil || c.Value == "" {
		return nil
	}
	sess, err := s.d.Store.GetSession(r.Context(), store.HashSecret(c.Value), s.now())
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.log.Error("web: get session", "err", err)
		}
		return nil
	}
	if exp, ok := nextExpiry(sess.CreatedAt, sess.ExpiresAt, s.now()); ok {
		if err := s.d.Store.ExtendSession(r.Context(), store.HashSecret(c.Value), exp, s.now()); err != nil && !errors.Is(err, store.ErrNotFound) {
			s.log.Error("web: extend session", "err", err)
		}
	}
	s.trust.mark(ipKey(s.ipOf(r)), strings.ToLower(sess.Username))
	return &session{Username: sess.Username, token: c.Value, CSRF: s.csrfFor(c.Value)}
}

func (s *Server) secHeaders(w http.ResponseWriter) {
	h := w.Header()
	if s.secure {
		h.Set("Strict-Transport-Security", "max-age=31536000")
	}
	h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "same-origin")
	h.Set("Cache-Control", "no-store")
}

type handler func(w http.ResponseWriter, r *http.Request, sess *session)

func (s *Server) get(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.secHeaders(w)
		if !s.hostOK(r) {
			s.badHost(w)
			return
		}
		sess := s.sessionFrom(r)
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		h(w, r, sess)
	}
}

// normHost lower-cases a host[:port] and drops the scheme's default port.
func normHost(host, scheme string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	if scheme == "https" {
		h = strings.TrimSuffix(h, ":443")
	} else {
		h = strings.TrimSuffix(h, ":80")
	}
	return h
}

// publicHostEnforced reports whether Host and Origin are pinned to PublicURL: it is set and not a
// loopback development address.
func (s *Server) publicHostEnforced() bool {
	return s.pubURL != nil && !isLoopbackURL(s.cfg.PublicURL)
}

// hostOK rejects requests whose Host header is not the configured public host (DNS rebinding,
// requests that reached the admin listener under another name).
func (s *Server) hostOK(r *http.Request) bool {
	if !s.publicHostEnforced() {
		return true
	}
	return normHost(r.Host, s.pubURL.Scheme) == normHost(s.pubURL.Host, s.pubURL.Scheme)
}

func (s *Server) badHost(w http.ResponseWriter) {
	http.Error(w, "unexpected Host header", http.StatusMisdirectedRequest)
}

// sameOrigin rejects cross-origin state-changing requests. With a public (non-loopback)
// PublicURL the Origin must be exactly that origin; otherwise (development) it must match Host.
func (s *Server) sameOrigin(r *http.Request) bool {
	if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" && sfs != "same-origin" && sfs != "none" {
		return false
	}
	if o := r.Header.Get("Origin"); o != "" {
		u, err := url.Parse(o)
		if err != nil || u.Host == "" {
			return false
		}
		if s.publicHostEnforced() {
			return u.Scheme == s.pubURL.Scheme && normHost(u.Host, u.Scheme) == normHost(s.pubURL.Host, s.pubURL.Scheme)
		}
		return u.Host == r.Host
	}
	return true
}

func (s *Server) post(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.secHeaders(w)
		if !s.hostOK(r) {
			s.badHost(w)
			return
		}
		if !s.sameOrigin(r) {
			s.fail(w, r, nil, http.StatusForbidden, "Cross-origin request rejected.", nil)
			return
		}
		sess := s.sessionFrom(r)
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if err := r.ParseForm(); err != nil {
			s.fail(w, r, sess, http.StatusBadRequest, "Bad form submission.", err)
			return
		}
		if !hmac.Equal([]byte(r.PostFormValue("csrf")), []byte(sess.CSRF)) {
			s.fail(w, r, sess, http.StatusForbidden, "Invalid or missing CSRF token. Reload the page and try again.", nil)
			return
		}
		h(w, r, sess)
	}
}

// ---------------------------------------------------------------------------
// rendering
// ---------------------------------------------------------------------------

var flashes = map[string]string{
	"saved":    "Saved.",
	"approved": "Rule approved.",
	"rejected": "Rule rejected.",
	"deleted":  "Deleted.",
	"revoked":  "Token revoked.",
	"created":  "Created.",
	"password": "Password changed.",
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, sess *session, status int, page string, data map[string]any) {
	t, ok := s.pages[page]
	if !ok {
		s.log.Error("web: unknown template", "page", page)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if data == nil {
		data = map[string]any{}
	}
	data["Nav"] = page
	if sess != nil {
		data["User"] = sess.Username
		data["CSRF"] = sess.CSRF
		data["Drafts"] = s.draftCount(r.Context())
	}
	if k := r.URL.Query().Get("ok"); k != "" {
		if m, ok := flashes[k]; ok {
			data["Flash"] = m
		}
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", data); err != nil {
		s.log.Error("web: render", "page", page, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, sess *session, code int, msg string, err error) {
	if err != nil {
		s.log.Error("web: request failed", "path", r.URL.Path, "status", code, "err", err)
	}
	s.secHeaders(w)
	s.render(w, r, sess, code, "error", map[string]any{"Code": code, "Status": http.StatusText(code), "Message": msg})
}

func (s *Server) notFound(w http.ResponseWriter, r *http.Request, sess *session) {
	s.fail(w, r, sess, http.StatusNotFound, "The page or object you asked for does not exist.", nil)
}

// storeErr maps a store error to a 404 or 500 response.
func (s *Server) storeErr(w http.ResponseWriter, r *http.Request, sess *session, err error) {
	if errors.Is(err, store.ErrNotFound) {
		s.notFound(w, r, sess)
		return
	}
	s.fail(w, r, sess, http.StatusInternalServerError, "Internal error; see server log.", err)
}

func (s *Server) handleFallback(w http.ResponseWriter, r *http.Request) {
	s.secHeaders(w)
	if strings.HasPrefix(r.URL.Path, "/api/") {
		http.NotFound(w, r)
		return
	}
	s.notFound(w, r, s.sessionFrom(r))
}

func (s *Server) redirectOK(w http.ResponseWriter, r *http.Request, path, flash string) {
	if flash != "" {
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		path += sep + "ok=" + flash
	}
	http.Redirect(w, r, path, http.StatusSeeOther)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func humanAge(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

func prettyJSON(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "(unprintable)"
	}
	return string(b)
}

func verdictLabel(v model.Verdict) string {
	switch v {
	case model.VerdictExploitable:
		return "exploitable"
	case model.VerdictNotExploitable:
		return "not exploitable"
	case model.VerdictConditionsUnknown:
		return "unknown"
	case model.VerdictNotAffected:
		return "not affected"
	case model.VerdictResolved:
		return "resolved"
	}
	return string(v)
}

func verdictClass(v model.Verdict) string {
	switch v {
	case model.VerdictExploitable:
		return "v-exploitable"
	case model.VerdictConditionsUnknown:
		return "v-unknown"
	case model.VerdictResolved:
		return "v-resolved"
	}
	return "v-neutral"
}

var allVerdicts = []model.Verdict{model.VerdictExploitable, model.VerdictConditionsUnknown,
	model.VerdictNotExploitable, model.VerdictNotAffected, model.VerdictResolved}

func validVerdict(v model.Verdict) bool {
	for _, x := range allVerdicts {
		if x == v {
			return true
		}
	}
	return false
}

func verdictRank(v model.Verdict) int {
	for i, x := range allVerdicts {
		if x == v {
			return i
		}
	}
	return len(allVerdicts)
}

func sortFindings(f []model.Finding) {
	sort.SliceStable(f, func(i, j int) bool {
		a, b := f[i], f[j]
		if ra, rb := verdictRank(a.Verdict), verdictRank(b.Verdict); ra != rb {
			return ra < rb
		}
		if a.KEV != b.KEV {
			return a.KEV
		}
		if a.CVSS != b.CVSS {
			return a.CVSS > b.CVSS
		}
		return a.VulnID < b.VulnID
	})
}

func (s *Server) hostNames(ctx context.Context) (map[string]string, []model.Host, error) {
	hosts, err := s.d.Store.ListHosts(ctx)
	if err != nil {
		return nil, nil, err
	}
	m := make(map[string]string, len(hosts))
	for _, h := range hosts {
		m[h.ID] = h.Hostname
	}
	return m, hosts, nil
}

// effectiveRules returns the engine's rules, or the DB rules when the engine is not wired.
func (s *Server) effectiveRules(ctx context.Context) []model.Rule {
	if s.d.Rules != nil {
		return s.d.Rules.Rules()
	}
	rs, err := s.d.Store.ListRules(ctx)
	if err != nil {
		s.log.Error("web: list rules", "err", err)
	}
	return rs
}

func (s *Server) draftCount(ctx context.Context) int {
	n := 0
	for _, r := range s.effectiveRules(ctx) {
		if r.Status == model.RuleDraft {
			n++
		}
	}
	return n
}

func (s *Server) findRule(ctx context.Context, id string) (model.Rule, bool) {
	for _, r := range s.effectiveRules(ctx) {
		if r.ID == id {
			return r, true
		}
	}
	if r, err := s.d.Store.GetRule(ctx, id); err == nil {
		return r, true
	}
	return model.Rule{}, false
}

// nextExpiry implements the idle timeout without a last_seen column. The stored expiry is always
// "last refresh + sessionIdle", so the last refresh is expires-sessionIdle. When that is more than
// sessionRefresh ago the expiry is pushed to now+sessionIdle, never past created+sessionTTL.
func nextExpiry(created, expires, now time.Time) (time.Time, bool) {
	if now.Sub(expires.Add(-sessionIdle)) <= sessionRefresh {
		return expires, false
	}
	exp := now.Add(sessionIdle)
	if limit := created.Add(sessionTTL); exp.After(limit) {
		exp = limit
	}
	return exp, exp.After(expires)
}

func isLoopbackURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	h := strings.ToLower(u.Hostname())
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

var refHosts = map[string]bool{
	"nvd.nist.gov": true, "www.cve.org": true, "cve.mitre.org": true, "osv.dev": true, "github.com": true,
	"security-tracker.debian.org": true, "ubuntu.com": true, "access.redhat.com": true, "www.openwall.com": true,
	"lists.debian.org": true, "www.qualys.com": true, "httpd.apache.org": true, "nginx.org": true, "www.openssh.com": true,
}

// safeRef reports whether a rule reference may be rendered as a link: https, allowlisted host,
// no credentials, default port.
func safeRef(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || u.Opaque != "" {
		return false
	}
	return refHosts[strings.ToLower(u.Hostname())]
}

// sleepCtx waits for d or until ctx is done.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
