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
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"panoptes/internal/model"
	"panoptes/internal/server/config"
	"panoptes/internal/server/pipeline"
	"panoptes/internal/server/store"
)

//go:embed templates/*.html static/*
var assets embed.FS

// RulesService is implemented by internal/server/rules.
type RulesService interface {
	Rules() []model.Rule // effective rules (files + DB)
	Validate(r model.Rule) error
	Reload(ctx context.Context) error
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
}

// Server serves the UI.
type Server struct {
	d       Deps
	log     *slog.Logger
	now     func() time.Time
	cfg     *config.Config
	pages   map[string]*template.Template
	csrfKey []byte
	lim     *limiter
	secure  bool
}

const (
	cookieName    = "panoptes_session"
	loginCSRFName = "panoptes_login"
	sessionTTL    = 12 * time.Hour
	pageSize      = 50
	staleAfter    = 30 * time.Minute
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
	s.secure = strings.HasPrefix(strings.ToLower(s.cfg.PublicURL), "https")
	s.csrfKey = make([]byte, 32)
	if _, err := rand.Read(s.csrfKey); err != nil {
		return nil, err
	}
	s.lim = newLimiter(s.now)
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
		"vlabel": verdictLabel,
		"vclass": verdictClass,
		"join":   strings.Join,
		"json":   prettyJSON,
		"nvd":    func(id string) string { return "https://nvd.nist.gov/vuln/detail/" + url.PathEscape(id) },
		"osv":    func(id string) string { return "https://osv.dev/vulnerability/" + url.PathEscape(id) },
		"isCVE":  func(id string) bool { return strings.HasPrefix(strings.ToUpper(id), "CVE-") },
		"fixcmd": pipeline.FixCmd,
		"add":    func(a, b int) int { return a + b },
		"pct":    func(f float64) string { return fmt.Sprintf("%.1f%%", f*100) },
		"score":  func(f float64) string { return fmt.Sprintf("%.1f", f) },
		"tbl": func(f []model.Finding, names map[string]string, showHost bool) findingsTbl {
			return findingsTbl{f, names, showHost}
		},
		"rclass":  func(st model.RuleStatus) string { return "st-" + string(st) },
		"rstatus": func(st model.RuleStatus) string { return string(st) },
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
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Header().Set("X-Content-Type-Options", "nosniff")
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
	c, err := r.Cookie(cookieName)
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
	return &session{Username: sess.Username, token: c.Value, CSRF: s.csrfFor(c.Value)}
}

func secHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "same-origin")
	h.Set("Cache-Control", "no-store")
}

type handler func(w http.ResponseWriter, r *http.Request, sess *session)

func (s *Server) get(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		secHeaders(w)
		sess := s.sessionFrom(r)
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		h(w, r, sess)
	}
}

// sameOrigin rejects cross-origin state-changing requests.
func sameOrigin(r *http.Request) bool {
	if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" && sfs != "same-origin" && sfs != "none" {
		return false
	}
	if o := r.Header.Get("Origin"); o != "" {
		u, err := url.Parse(o)
		if err != nil || u.Host != r.Host {
			return false
		}
	}
	return true
}

func (s *Server) post(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		secHeaders(w)
		if !sameOrigin(r) {
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
	secHeaders(w)
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
	secHeaders(w)
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
