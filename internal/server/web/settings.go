package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/DonSosiska/holealign/internal/server/api"
	"github.com/DonSosiska/holealign/internal/server/config"
	"github.com/DonSosiska/holealign/internal/server/store"
)

const matrixSettingKey = "matrix.routes"

const (
	maxRoutesBytes   = 16 << 10
	maxRoutes        = 200
	maxRoomsPerRoute = 20 // destinations per route
	maxRoomIDLen     = 255
)

var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`)

// parseRoutes parses lines of the form "label = dest, dest, ..." where a destination is
// "scheme:target" or a bare Matrix room ID (!room:server). valid checks one destination (syntax and
// that its channel is configured); it is the same check config load applies.
func parseRoutes(text string, valid func(dest string) error) ([]config.NotifyRoute, error) {
	if len(text) > maxRoutesBytes {
		return nil, fmt.Errorf("routes text is too long (max %d KiB)", maxRoutesBytes>>10)
	}
	routes := []config.NotifyRoute{}
	seen := map[string]bool{}
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		label, rest, ok := strings.Cut(line, "=")
		label = strings.TrimSpace(label)
		if !ok || label == "" {
			return nil, fmt.Errorf("line %d: expected \"label = destination, destination\" (e.g. prod = !room:server, slack:C0123456789)", i+1)
		}
		if err := api.ValidateLabels([]string{label}); err != nil {
			return nil, fmt.Errorf("line %d: %s", i+1, clip(err.Error(), 200))
		}
		if len(routes) >= maxRoutes {
			return nil, fmt.Errorf("line %d: too many routes (max %d)", i+1, maxRoutes)
		}
		if seen[label] {
			return nil, fmt.Errorf("line %d: label %q is listed twice", i+1, label)
		}
		seen[label] = true
		var dests []string
		for _, d := range strings.Split(rest, ",") {
			d = strings.TrimSpace(d)
			if d == "" {
				continue
			}
			if len(d) > maxRoomIDLen {
				return nil, fmt.Errorf("line %d: a destination is longer than %d characters", i+1, maxRoomIDLen)
			}
			if err := valid(d); err != nil {
				return nil, fmt.Errorf("line %d: %s", i+1, clip(err.Error(), 300))
			}
			dests = append(dests, d)
		}
		if len(dests) > maxRoomsPerRoute {
			return nil, fmt.Errorf("line %d: label %q has more than %d destinations", i+1, label, maxRoomsPerRoute)
		}
		if len(dests) == 0 {
			return nil, fmt.Errorf("line %d: no destinations given for label %q", i+1, label)
		}
		routes = append(routes, config.NotifyRoute{Label: label, To: dests})
	}
	return routes, nil
}

func routesText(rs []config.NotifyRoute) string {
	var b strings.Builder
	for _, r := range rs {
		b.WriteString(r.Label + " = " + strings.Join(r.To, ", ") + "\n")
	}
	return b.String()
}

func (s *Server) storedRoutes(r *http.Request) []config.NotifyRoute {
	raw, err := s.d.Store.GetSetting(r.Context(), matrixSettingKey)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.log.Error("web: get matrix routes", "err", err)
		}
		return nil
	}
	var rs []config.NotifyRoute
	if err := json.Unmarshal(raw, &rs); err != nil {
		s.log.Error("web: decode matrix routes", "err", err)
		return nil
	}
	return rs
}

// renderSettings renders the settings page; extra overrides/extends the data (errors, one-time token).
func (s *Server) renderSettings(w http.ResponseWriter, r *http.Request, sess *session, status int, extra map[string]any) {
	ctx := r.Context()
	tokens, err := s.d.Store.ListEnrollTokens(ctx)
	if err != nil {
		s.storeErr(w, r, sess, err)
		return
	}
	users, err := s.d.Store.ListUsers(ctx)
	if err != nil {
		s.storeErr(w, r, sess, err)
		return
	}
	data := map[string]any{
		"Tokens": tokens, "Users": users, "Me": sess.Username,
		"RoutesText": routesText(s.storedRoutes(r)),
		"CfgRoutes":  s.cfg.Notify.Routes,
		"CfgDefault": s.cfg.Notify.Default,
		"CfgOps":     s.cfg.Notify.Ops,
		"Channels":   s.channelNames(),
		"LLM":        s.cfg.LLM,
		"PublicURL":  s.cfg.PublicURL,
	}
	for k, v := range extra {
		data[k] = v
	}
	s.render(w, r, sess, status, "settings", data)
}

// channelNames lists the configured notification channels for the settings page.
func (s *Server) channelNames() []string {
	var out []string
	for _, name := range []string{"matrix", "slack", "telegram", "discord", "teams", "webhook", "email"} {
		if s.cfg.Channels()[name] {
			out = append(out, name)
		}
	}
	return out
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request, sess *session) {
	s.renderSettings(w, r, sess, http.StatusOK, nil)
}

func (s *Server) handleMatrixSave(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.reauth(w, r, sess) {
		return
	}
	text := r.PostFormValue("routes")
	routes, err := parseRoutes(text, s.cfg.ValidateDestination)
	if err != nil {
		s.renderSettings(w, r, sess, http.StatusUnprocessableEntity, map[string]any{"MatrixError": err.Error(), "RoutesText": text})
		return
	}
	oldN := len(s.storedRoutes(r))
	raw, _ := json.Marshal(routes)
	if err := s.d.Store.SetSetting(r.Context(), matrixSettingKey, raw, s.now()); err != nil {
		s.fail(w, r, sess, http.StatusInternalServerError, "Could not save routes; see server log.", err)
		return
	}
	s.audit(r, sess.Username, "matrix_routes_change", matrixSettingKey, "old_routes", oldN, "new_routes", len(routes))
	s.redirectOK(w, r, "/settings", "saved")
}

func (s *Server) handleTokenCreate(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.reauth(w, r, sess) {
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	if !nameRe.MatchString(name) {
		s.renderSettings(w, r, sess, http.StatusUnprocessableEntity, map[string]any{
			"TokenError": "Token name must be 1-64 characters: letters, digits, '.', '_', '-', '@'.", "TokenName": name})
		return
	}
	opts, msg := s.parseTokenOpts(r, name)
	if msg != "" {
		s.renderSettings(w, r, sess, http.StatusUnprocessableEntity, map[string]any{
			"TokenError": msg, "TokenName": name, "TokenMaxHosts": r.PostFormValue("max_hosts"),
			"TokenExpires": r.PostFormValue("expires"), "TokenLabels": r.PostFormValue("labels")})
		return
	}
	secret, hash, err := store.NewSecret("pt_")
	if err != nil {
		s.fail(w, r, sess, http.StatusInternalServerError, "Could not generate a token; see server log.", err)
		return
	}
	opts.Hash = hash
	if err := s.d.Store.CreateEnrollTokenOpts(r.Context(), opts); err != nil {
		if errors.Is(err, store.ErrExists) {
			s.renderSettings(w, r, sess, http.StatusConflict, map[string]any{"TokenError": "A token with this name already exists.", "TokenName": name})
			return
		}
		s.fail(w, r, sess, http.StatusInternalServerError, "Could not create the token; see server log.", err)
		return
	}
	s.audit(r, sess.Username, "token_create", name, "max_hosts", opts.MaxHosts, "expires", opts.ExpiresAt.UTC().Format(time.RFC3339), "labels", strings.Join(opts.Labels, ","))
	snippet := fmt.Sprintf("server_url: %s\nenroll_token: %q\nlabels: []\n", s.cfg.PublicURL, secret)
	s.renderSettings(w, r, sess, http.StatusOK, map[string]any{"NewTokenName": name, "NewToken": secret, "Snippet": snippet})
}

// parseTokenOpts reads the optional max_hosts, expires (duration, e.g. 72h or 7d) and labels
// (comma separated) form fields. On invalid input it returns a user-facing message.
func (s *Server) parseTokenOpts(r *http.Request, name string) (store.EnrollTokenOpts, string) {
	o := store.EnrollTokenOpts{Name: name}
	if v := strings.TrimSpace(r.PostFormValue("max_hosts")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 100000 {
			return o, "Max hosts must be a whole number (0 = unlimited)."
		}
		o.MaxHosts = n
	}
	if v := strings.TrimSpace(r.PostFormValue("expires")); v != "" {
		d, err := parseLifetime(v)
		if err != nil || d < 0 {
			return o, "Expires must be a duration such as 72h or 7d (empty = never)."
		}
		if d > 0 {
			o.ExpiresAt = s.now().Add(d)
		}
	}
	for _, l := range strings.Split(r.PostFormValue("labels"), ",") {
		if l = strings.TrimSpace(l); l != "" {
			o.Labels = append(o.Labels, l)
		}
	}
	if err := api.ValidateLabels(o.Labels); err != nil {
		return o, "Labels: " + err.Error()
	}
	return o, ""
}

// parseLifetime parses a Go duration, additionally accepting a "d" (days) suffix.
func parseLifetime(v string) (time.Duration, error) {
	if n, ok := strings.CutSuffix(v, "d"); ok {
		days, err := strconv.Atoi(n)
		if err != nil || days < 0 || days > 3650 {
			return 0, errors.New("invalid days")
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(v)
}

func (s *Server) handleTokenRevoke(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.reauth(w, r, sess) {
		return
	}
	if err := s.d.Store.RevokeEnrollToken(r.Context(), r.PathValue("name")); err != nil {
		s.storeErr(w, r, sess, err)
		return
	}
	s.audit(r, sess.Username, "token_revoke", r.PathValue("name"))
	s.redirectOK(w, r, "/settings", "revoked")
}

func (s *Server) handleUserAdd(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.reauth(w, r, sess) {
		return
	}
	name := strings.TrimSpace(r.PostFormValue("username"))
	pw := r.PostFormValue("password")
	msg := ""
	switch {
	case !nameRe.MatchString(name):
		msg = "Username must be 1-64 characters: letters, digits, '.', '_', '-', '@'."
	case len(pw) < minPasswordLen:
		msg = "Password must be at least 12 characters."
	case len(pw) > maxPasswordBytes:
		msg = "Password must be at most 72 bytes."
	}
	if msg != "" {
		s.renderSettings(w, r, sess, http.StatusUnprocessableEntity, map[string]any{"UserError": msg, "UserName": name})
		return
	}
	hash, err := store.HashPassword(pw)
	if err != nil {
		s.fail(w, r, sess, http.StatusInternalServerError, "Could not hash the password; see server log.", err)
		return
	}
	if err := s.d.Store.CreateUser(r.Context(), name, hash); err != nil {
		if errors.Is(err, store.ErrExists) {
			s.renderSettings(w, r, sess, http.StatusConflict, map[string]any{"UserError": "This user already exists.", "UserName": name})
			return
		}
		s.fail(w, r, sess, http.StatusInternalServerError, "Could not create the user; see server log.", err)
		return
	}
	s.audit(r, sess.Username, "user_add", name)
	s.redirectOK(w, r, "/settings", "created")
}

func (s *Server) handleUserPassword(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.reauth(w, r, sess) {
		return
	}
	name := r.PathValue("name")
	pw := r.PostFormValue("password")
	switch {
	case len(pw) < minPasswordLen:
		s.renderSettings(w, r, sess, http.StatusUnprocessableEntity, map[string]any{"UserError": "Password must be at least 12 characters."})
		return
	case len(pw) > maxPasswordBytes:
		s.renderSettings(w, r, sess, http.StatusUnprocessableEntity, map[string]any{"UserError": "Password must be at most 72 bytes."})
		return
	}
	hash, err := store.HashPassword(pw)
	if err != nil {
		s.fail(w, r, sess, http.StatusInternalServerError, "Could not hash the password; see server log.", err)
		return
	}
	if err := s.d.Store.SetUserPassword(r.Context(), name, hash); err != nil {
		s.storeErr(w, r, sess, err)
		return
	}
	lu := strings.ToLower(name)
	s.devices.revokeUser(lu)
	s.trust.revokeUser(lu)
	s.audit(r, sess.Username, "user_password_change", name)
	s.redirectOK(w, r, "/settings", "password")
}

func (s *Server) handleUserDelete(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.reauth(w, r, sess) {
		return
	}
	name := r.PathValue("name")
	if name == sess.Username {
		s.renderSettings(w, r, sess, http.StatusUnprocessableEntity, map[string]any{"UserError": "You cannot delete your own account."})
		return
	}
	if err := s.d.Store.DeleteUser(r.Context(), name); err != nil {
		s.storeErr(w, r, sess, err)
		return
	}
	lu := strings.ToLower(name)
	s.devices.revokeUser(lu)
	s.trust.revokeUser(lu)
	s.audit(r, sess.Username, "user_delete", name)
	s.redirectOK(w, r, "/settings", "deleted")
}
