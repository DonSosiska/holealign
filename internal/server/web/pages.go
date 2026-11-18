package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"

	"github.com/DonSosiska/panoptes/internal/model"
	"github.com/DonSosiska/panoptes/internal/server/store"
)

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request, sess *session) {
	ctx := r.Context()
	eps := s.cfg.Triage.EPSSThreshold
	counts, _, err := s.d.Store.CountByTier(ctx, eps)
	if err != nil {
		s.storeErr(w, r, sess, err)
		return
	}
	top, _, err := s.d.Store.ListFindingGroups(ctx, store.FindingFilter{Tier: store.TierAttention, EPSSThreshold: eps, Limit: 10})
	if err != nil {
		s.storeErr(w, r, sess, err)
		return
	}
	names, hosts, err := s.hostNames(ctx)
	if err != nil {
		s.storeErr(w, r, sess, err)
		return
	}
	var stale []model.Host
	now := s.now()
	limit := staleAfter
	if a := s.cfg.Alerts.AgentSilentAfter; a > 0 {
		limit = a
	}
	for _, h := range hosts {
		if h.LastCheckin.IsZero() || now.Sub(h.LastCheckin) > limit {
			stale = append(stale, h)
		}
	}
	kv := func(k string) string {
		v, err := s.d.Store.KVGet(ctx, k)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			s.log.Error("web: kv get", "key", k, "err", err)
		}
		return v
	}
	var pipeErrs []string
	for _, l := range strings.Split(kv("health.pipeline_errors"), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			pipeErrs = append(pipeErrs, l)
		}
	}
	s.render(w, r, sess, http.StatusOK, "dashboard", map[string]any{
		"FeedStale": kv("health.feed_stale"), "PipelineErrors": pipeErrs, "NotifyProblems": s.notifyProblems(kv(kvNotifyErrors)),
		"Counts": counts, "EPSSPct": epssPct(eps), "Top": top, "HostNames": names, "Stale": stale, "HostCount": len(hosts),
		"RulesFeedStale": kv("health.rules_feed_stale"), "RulesFeedOn": s.cfg.Rules.Feed.Enabled,
		"RulesFeedSeq": kv("rulesfeed.seq"), "RulesFeedUpdated": kv("rulesfeed.updated_at"),
		"RulesFeedChecked": kv("rulesfeed.checked_at"), "RulesFeedError": kv("rulesfeed.last_error"),
		"FeedChecked": kv("feeds.grype.checked_at"), "FeedUpdated": kv("feeds.grype.updated_at"), "FeedError": kv("feeds.grype.last_error"),
	})
}

func (s *Server) handleHosts(w http.ResponseWriter, r *http.Request, sess *session) {
	ctx := r.Context()
	hosts, err := s.d.Store.ListHosts(ctx)
	if err != nil {
		s.storeErr(w, r, sess, err)
		return
	}
	_, per, err := s.d.Store.CountByTier(ctx, s.cfg.Triage.EPSSThreshold)
	if err != nil {
		s.storeErr(w, r, sess, err)
		return
	}
	type row struct {
		model.Host
		Exploitable, Attention, Background int
		Local                              bool
	}
	localID := s.localHostID(ctx)
	rows := make([]row, 0, len(hosts))
	for _, h := range hosts {
		c := per[h.ID]
		rows = append(rows, row{Host: h, Exploitable: c.Exploitable, Attention: c.Attention, Background: c.Background,
			Local: localID != "" && h.ID == localID})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Exploitable != rows[j].Exploitable {
			return rows[i].Exploitable > rows[j].Exploitable
		}
		return rows[i].Hostname < rows[j].Hostname
	})
	s.render(w, r, sess, http.StatusOK, "hosts", map[string]any{"Rows": rows})
}

// localHostID is the id of the server's own (built-in agent) host, or "".
func (s *Server) localHostID(ctx context.Context) string {
	id, err := s.d.Store.KVGet(ctx, "local_host")
	if err != nil {
		return ""
	}
	return id
}

func (s *Server) handleHost(w http.ResponseWriter, r *http.Request, sess *session) {
	ctx := r.Context()
	h, err := s.d.Store.GetHost(ctx, r.PathValue("id"))
	if err != nil {
		s.storeErr(w, r, sess, err)
		return
	}
	targets, err := s.d.Store.ListTargets(ctx, h.ID)
	if err != nil {
		s.storeErr(w, r, sess, err)
		return
	}
	fs, err := s.d.Store.HostFindings(ctx, h.ID)
	if err != nil {
		s.storeErr(w, r, sess, err)
		return
	}
	q := r.URL.Query()
	all := q.Get("all") == "1"
	hidden := 0
	for _, f := range fs {
		if f.Verdict == model.VerdictResolved && !all {
			hidden++
		}
	}
	eq := url.Values{}
	for k, v := range q {
		if k != "host" && k != "q" && k != "all" && k != "label" {
			eq[k] = v
		}
	}
	if all {
		eq.Set("resolved", "1")
	}
	f, page := parseFilter(eq)
	f.HostID, f.EPSSThreshold = h.ID, s.cfg.Triage.EPSSThreshold
	lv, err := s.loadListing(ctx, "/hosts/"+url.PathEscape(h.ID), q, f, page)
	if err != nil {
		s.storeErr(w, r, sess, err)
		return
	}
	_, per, err := s.d.Store.CountByTier(ctx, f.EPSSThreshold)
	if err != nil {
		s.storeErr(w, r, sess, err)
		return
	}
	s.render(w, r, sess, http.StatusOK, "host", map[string]any{
		"Host": h, "Targets": targets, "L": lv, "Counts": per[h.ID], "Hidden": hidden, "All": all,
		"Local": s.localHostID(ctx) == h.ID,
		"Stale": h.LastCheckin.IsZero() || s.now().Sub(h.LastCheckin) > staleAfter,
	})
}

// parseFilter maps GET query parameters to a store filter and a 1-based page number.
func parseFilter(q url.Values) (store.FindingFilter, int) {
	f := store.FindingFilter{Limit: pageSize}
	if v := model.Verdict(q.Get("verdict")); validVerdict(v) {
		f.Verdict = v
	}
	f.IncludeResolved = q.Get("resolved") == "1"
	f.Label = strings.TrimSpace(q.Get("label"))
	f.HostID = strings.TrimSpace(q.Get("host"))
	f.VulnID = strings.TrimSpace(q.Get("q"))
	switch q.Get("kev") {
	case "1":
		t := true
		f.KEV = &t
	case "0":
		t := false
		f.KEV = &t
	}
	// Tier: explicit tier=attention|background|all wins. Otherwise the default is "attention",
	// unless the request names something specific (an ID search, a verdict, resolved findings or a
	// host), which switches the default to "all" so old links keep showing what they point at.
	switch q.Get("tier") {
	case store.TierAttention, store.TierBackground:
		f.Tier = q.Get("tier")
	case "all":
	default:
		if f.VulnID == "" && f.Verdict == "" && !f.IncludeResolved && f.HostID == "" {
			f.Tier = store.TierAttention
		}
	}
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	f.Offset = (page - 1) * pageSize
	return f, page
}

// listing is what the findings pages render: grouped rows (default) or per-package rows.
type listing struct {
	Groups             []store.FindingGroup
	Findings           []model.Finding
	Total, Page, Pages int
	PrevURL, NextURL   string
	Tier               string // effective: attention, background or all
	PerPackage         bool
	AllURL, AttnURL    string // tier switches
	BgURL              string
	GroupedURL         string // view switches
	PackageURL         string
}

// withParams copies q without "page", then sets (or, for "", removes) the key/value pairs.
func withParams(base string, q url.Values, kv ...string) string {
	v := url.Values{}
	for k, vs := range q {
		if k != "page" {
			v[k] = vs
		}
	}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == "" {
			v.Del(kv[i])
		} else {
			v.Set(kv[i], kv[i+1])
		}
	}
	if len(v) == 0 {
		return base
	}
	return base + "?" + v.Encode()
}

func (s *Server) loadListing(ctx context.Context, base string, q url.Values, f store.FindingFilter, page int) (listing, error) {
	lv := listing{Page: page, Tier: f.Tier, PerPackage: q.Get("view") == "package"}
	if lv.Tier == "" {
		lv.Tier = "all"
	}
	var err error
	if lv.PerPackage {
		lv.Findings, lv.Total, err = s.d.Store.ListFindings(ctx, f)
	} else {
		lv.Groups, lv.Total, err = s.d.Store.ListFindingGroups(ctx, f)
	}
	if err != nil {
		return lv, err
	}
	lv.Pages = (lv.Total + pageSize - 1) / pageSize
	if page > 1 {
		lv.PrevURL = withParams(base, q, "page", strconv.Itoa(page-1))
	}
	if page < lv.Pages {
		lv.NextURL = withParams(base, q, "page", strconv.Itoa(page+1))
	}
	lv.AllURL = withParams(base, q, "tier", "all")
	lv.AttnURL = withParams(base, q, "tier", store.TierAttention)
	lv.BgURL = withParams(base, q, "tier", store.TierBackground)
	lv.GroupedURL = withParams(base, q, "view", "")
	lv.PackageURL = withParams(base, q, "view", "package")
	return lv, nil
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request, sess *session) {
	ctx := r.Context()
	q := r.URL.Query()
	f, page := parseFilter(q)
	f.EPSSThreshold = s.cfg.Triage.EPSSThreshold
	lv, err := s.loadListing(ctx, "/findings", q, f, page)
	if err != nil {
		s.storeErr(w, r, sess, err)
		return
	}
	names, hosts, err := s.hostNames(ctx)
	if err != nil {
		s.storeErr(w, r, sess, err)
		return
	}
	labelSet := map[string]bool{}
	for _, h := range hosts {
		for _, l := range h.Labels {
			labelSet[l] = true
		}
	}
	var labels []string
	for l := range labelSet {
		labels = append(labels, l)
	}
	sort.Strings(labels)
	s.render(w, r, sess, http.StatusOK, "findings", map[string]any{
		"L": lv, "HostNames": names, "Hosts": hosts, "Labels": labels,
		"Verdicts": allVerdicts, "Q": q.Get("q"), "FVerdict": string(f.Verdict), "FLabel": f.Label, "FHost": f.HostID,
		"FKEV": q.Get("kev"), "FResolved": f.IncludeResolved, "FTier": q.Get("tier"),
	})
}

func (s *Server) handleFinding(w http.ResponseWriter, r *http.Request, sess *session) {
	ctx := r.Context()
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.notFound(w, r, sess)
		return
	}
	f, err := s.d.Store.GetFinding(ctx, id)
	if err != nil {
		s.storeErr(w, r, sess, err)
		return
	}
	data := map[string]any{"F": f}
	if h, err := s.d.Store.GetHost(ctx, f.HostID); err == nil {
		data["Host"] = h
	}
	if f.RuleID != "" {
		if rule, ok := s.findRule(ctx, f.RuleID); ok {
			data["Rule"] = rule
		}
	}
	s.render(w, r, sess, http.StatusOK, "finding", data)
}

func (s *Server) handleVuln(w http.ResponseWriter, r *http.Request, sess *session) {
	ctx := r.Context()
	id := r.PathValue("id")
	groups, total, err := s.d.Store.ListFindingGroups(ctx, store.FindingFilter{VulnID: id, IncludeResolved: true, Limit: 1000})
	if err != nil {
		s.storeErr(w, r, sess, err)
		return
	}
	if total == 0 {
		s.notFound(w, r, sess)
		return
	}
	hn, _, err := s.hostNames(ctx)
	if err != nil {
		s.storeErr(w, r, sess, err)
		return
	}
	pkgs := 0
	for _, g := range groups {
		pkgs += len(g.Findings)
	}
	s.render(w, r, sess, http.StatusOK, "vuln", map[string]any{"VulnID": id, "Groups": groups, "HostNames": hn, "Total": total, "Pkgs": pkgs})
}

// ---------------------------------------------------------------------------
// rules
// ---------------------------------------------------------------------------

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request, sess *session) {
	rules := append([]model.Rule(nil), s.effectiveRules(r.Context())...)
	filter := r.URL.Query().Get("status")
	counts := map[string]int{}
	var shown []model.Rule
	for _, ru := range rules {
		counts[string(ru.Status)]++
		if filter == "" || string(ru.Status) == filter {
			shown = append(shown, ru)
		}
	}
	rank := map[model.RuleStatus]int{model.RuleDraft: 0, model.RuleReviewed: 1, model.RuleRejected: 2}
	sort.SliceStable(shown, func(i, j int) bool {
		if rank[shown[i].Status] != rank[shown[j].Status] {
			return rank[shown[i].Status] < rank[shown[j].Status]
		}
		return shown[i].ID < shown[j].ID
	})
	s.render(w, r, sess, http.StatusOK, "rules", map[string]any{
		"Rules": shown, "Filter": filter, "Counts": counts, "Total": len(rules), "NoEngine": s.d.Rules == nil,
		"Sources": s.ruleSources(),
	})
}

func ruleYAML(r model.Rule) string {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(r); err != nil {
		return "# error: " + err.Error()
	}
	_ = enc.Close()
	return buf.String()
}

// ruleVersion identifies the stored state of a rule (SHA-256 of its JSON). Forms carry it so a rule
// that changed after it was displayed (LLM redraft, another admin) cannot be approved unseen.
func ruleVersion(r model.Rule) string {
	b, _ := json.Marshal(r)
	return sha256hex(string(b))
}

// Display limits for LLM-written draft text.
const (
	llmTitleMax       = 200
	llmExplanationMax = 600
	llmFixMax         = 300
	factCellMax       = 200
)

type factRow struct{ Name, Collector, Path, Pattern string }

func factRows(r model.Rule) []factRow {
	var out []factRow
	for _, fr := range r.FactRequests {
		out = append(out, factRow{Name: clip(fr.Name, factCellMax), Collector: clip(fr.Collector, 64),
			Path: clip(fr.Params["path"], factCellMax), Pattern: clip(fr.Params["pattern"], factCellMax)})
	}
	return out
}

func (s *Server) renderRule(w http.ResponseWriter, r *http.Request, sess *session, status int, rule model.Rule, yamlText, errMsg string) {
	var findings []model.Finding
	if len(rule.Vulns) > 0 {
		if list, _, err := s.d.Store.ListFindings(r.Context(), store.FindingFilter{VulnID: rule.Vulns[0], Limit: 20}); err == nil {
			findings = list
		}
	}
	names, _, _ := s.hostNames(r.Context())
	stored := rule
	if cur, ok := s.findRule(r.Context(), rule.ID); ok {
		stored = cur
	}
	var pkgs []string
	for _, p := range rule.Packages {
		n := clip(p.Name, 100)
		if p.Source != "" {
			n = "source " + clip(p.Source, 100)
		}
		if p.Type != "" {
			n += " (" + clip(p.Type, 32) + ")"
		}
		pkgs = append(pkgs, n)
	}
	s.render(w, r, sess, status, "rule", map[string]any{
		"Rule": rule, "YAML": yamlText, "Error": errMsg, "Findings": findings, "HostNames": names, "NoEngine": s.d.Rules == nil,
		"Version": ruleVersion(stored), "Draft": rule.Status == model.RuleDraft, "RuleSource": s.ruleSources()[rule.ID],
		"FactRows": factRows(rule), "Pkgs": pkgs,
		"LLMTitle": clip(rule.Title, llmTitleMax), "LLMExplanation": clip(rule.Explanation, llmExplanationMax),
		"ExploitableIf": newExprView(rule.ExploitableIf), "NotAffectedIf": newExprView(rule.NotAffectedIf),
		"LLMUpgrade": clip(rule.Fix.Upgrade, llmFixMax), "LLMMitigation": clip(rule.Fix.Mitigation, llmFixMax),
	})
}

const (
	exprShortMax = 300  // runes shown before "show all"
	exprFullMax  = 4000 // runes shown at most
)

// exprView is a rule expression prepared for read-only display on the approve panel.
type exprView struct {
	Short string
	Full  string
	Long  bool
}

func newExprView(e string) exprView {
	full := exprText(e, exprFullMax)
	if full == "" {
		return exprView{}
	}
	v := exprView{Short: full, Full: full}
	if r := []rune(full); len(r) > exprShortMax {
		v.Short, v.Long = string(r[:exprShortMax])+"…", true
	}
	return v
}

// exprText is clip that keeps line breaks and tabs, so multi-line expressions stay readable.
func exprText(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
		case r == '\r':
			continue
		case unicode.IsControl(r), r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069, r == 0x2028, r == 0x2029:
			continue
		}
		if n++; n > max {
			b.WriteString("…")
			break
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

// clip removes control and bidi characters from untrusted text and cuts it to max runes.
func clip(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t' || r == '\r':
			r = ' '
		case unicode.IsControl(r), r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069, r == 0x2028, r == 0x2029:
			continue
		}
		if n++; n > max {
			b.WriteString("…")
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// staleRule reports (and answers with 409) when the rule_version in the form differs from the
// stored rule: the admin approved/edited something other than what is stored now.
func (s *Server) staleRule(w http.ResponseWriter, r *http.Request, sess *session, cur model.Rule) bool {
	if v := r.PostFormValue("rule_version"); v != "" && v == ruleVersion(cur) {
		return false
	}
	s.fail(w, r, sess, http.StatusConflict,
		"This rule changed (or the form is out of date) since you opened it. Nothing was changed. Reload the rule page, review it again and retry.", nil)
	return true
}

func (s *Server) handleRule(w http.ResponseWriter, r *http.Request, sess *session) {
	rule, ok := s.findRule(r.Context(), r.PathValue("id"))
	if !ok {
		s.notFound(w, r, sess)
		return
	}
	s.renderRule(w, r, sess, http.StatusOK, rule, ruleYAML(rule), "")
}

// parseRuleYAML strictly decodes one rule document.
func parseRuleYAML(text string) (model.Rule, error) {
	var rule model.Rule
	dec := yaml.NewDecoder(strings.NewReader(text))
	dec.KnownFields(true)
	if err := dec.Decode(&rule); err != nil {
		return rule, err
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		return rule, errors.New("only one YAML document is allowed")
	}
	return rule, nil
}

// saveRule validates, stores and activates a rule, then re-runs the pipeline.
func (s *Server) saveRule(r *http.Request, rule model.Rule) error {
	ctx := r.Context()
	if strings.TrimSpace(rule.ID) == "" {
		return errors.New("rule id is required")
	}
	switch rule.Status {
	case model.RuleReviewed, model.RuleDraft, model.RuleRejected:
	default:
		return errors.New("status must be reviewed, draft or rejected")
	}
	if s.d.Rules != nil {
		if err := s.d.Rules.Validate(rule); err != nil {
			return err
		}
	}
	if err := s.d.Store.UpsertRule(ctx, rule, s.now()); err != nil {
		return &internalError{err}
	}
	if s.d.Rules != nil {
		if err := s.d.Rules.Reload(ctx); err != nil {
			return &internalError{err}
		}
	}
	if s.d.Pipeline != nil {
		s.d.Pipeline.TriggerAll()
	}
	return nil
}

type internalError struct{ err error }

func (e *internalError) Error() string { return "internal error: " + e.err.Error() }
func (e *internalError) Unwrap() error { return e.err }

func (s *Server) handleRuleEdit(w http.ResponseWriter, r *http.Request, sess *session) {
	id := r.PathValue("id")
	text := r.PostFormValue("yaml")
	current, ok := s.findRule(r.Context(), id)
	if !ok {
		s.notFound(w, r, sess)
		return
	}
	if s.staleRule(w, r, sess, current) || !s.reauth(w, r, sess) {
		return
	}
	rule, err := parseRuleYAML(text)
	if err == nil && rule.ID != id {
		err = errors.New("the id in the YAML must stay \"" + id + "\"")
	}
	if err == nil {
		// The status is never taken from the YAML: it changes only through Approve / Reject.
		if rule.Status != "" && rule.Status != current.Status {
			err = errors.New("status cannot be changed here (use Approve or Reject); leave it as \"" + string(current.Status) + "\"")
		}
		rule.Status = current.Status
		if rule.Status == "" {
			rule.Status = model.RuleDraft
		}
	}
	if err == nil {
		rule.Source = "user"
		err = s.saveRule(r, rule)
	}
	if err != nil {
		var ie *internalError
		if errors.As(err, &ie) {
			s.fail(w, r, sess, http.StatusInternalServerError, "Could not save the rule; see server log.", ie.err)
			return
		}
		s.renderRule(w, r, sess, http.StatusUnprocessableEntity, current, text, err.Error())
		return
	}
	s.auditRule(r, sess.Username, "rule_edit", current, rule)
	s.redirectOK(w, r, "/rules/"+url.PathEscape(id), "saved")
}

func (s *Server) handleRuleSetStatus(st model.RuleStatus) handler {
	return func(w http.ResponseWriter, r *http.Request, sess *session) {
		id := r.PathValue("id")
		rule, ok := s.findRule(r.Context(), id)
		if !ok {
			s.notFound(w, r, sess)
			return
		}
		if s.staleRule(w, r, sess, rule) || !s.reauth(w, r, sess) {
			return
		}
		before := rule
		rule.Status = st
		if rule.Source == "" || rule.Source == "builtin" {
			rule.Source = "user"
		}
		if err := s.saveRule(r, rule); err != nil {
			var ie *internalError
			if errors.As(err, &ie) {
				s.fail(w, r, sess, http.StatusInternalServerError, "Could not save the rule; see server log.", ie.err)
				return
			}
			s.renderRule(w, r, sess, http.StatusUnprocessableEntity, rule, ruleYAML(rule), err.Error())
			return
		}
		flash, action := "approved", "rule_approve"
		if st == model.RuleRejected {
			flash, action = "rejected", "rule_reject"
		}
		s.auditRule(r, sess.Username, action, before, rule)
		s.redirectOK(w, r, "/rules/"+url.PathEscape(id), flash)
	}
}

func (s *Server) auditRule(r *http.Request, actor, action string, old, nw model.Rule) {
	s.audit(r, actor, action, nw.ID,
		"old_status", string(old.Status), "new_status", string(nw.Status),
		"old_exploitable_if_sha256", sha256hex(old.ExploitableIf), "new_exploitable_if_sha256", sha256hex(nw.ExploitableIf),
		"old_not_affected_if_sha256", sha256hex(old.NotAffectedIf), "new_not_affected_if_sha256", sha256hex(nw.NotAffectedIf))
}

// kvNotifyErrors is written by internal/server/health (last delivery problems of the notifier).
const kvNotifyErrors = "health.notify_errors"

type notifyProblem struct {
	At        time.Time `json:"at"`
	Room      string    `json:"room"`
	Status    int       `json:"status"`
	Kind      string    `json:"kind"`
	Permanent bool      `json:"permanent"`
}

// notifyProblems turns the stored problem list into banner lines (one per room and status, newest
// first, problems older than 24 h are not shown).
func (s *Server) notifyProblems(raw string) []string {
	if raw == "" {
		return nil
	}
	var ps []notifyProblem
	if err := json.Unmarshal([]byte(raw), &ps); err != nil {
		return nil
	}
	now := s.now()
	seen := map[string]bool{}
	var out []string
	for i := len(ps) - 1; i >= 0; i-- {
		p := ps[i]
		if now.Sub(p.At) > 24*time.Hour {
			continue
		}
		room := clip(p.Room, 80)
		key := room + "|" + strconv.Itoa(p.Status)
		if seen[key] {
			continue
		}
		seen[key] = true
		line := "alerts are not being delivered to " + room
		if room == "" {
			line = "alerts have no Matrix room to go to"
		}
		if p.Status > 0 {
			line += ": " + strconv.Itoa(p.Status)
		}
		out = append(out, line+" (last seen "+humanAge(now.Sub(p.At))+", "+clip(p.Kind, 32)+")")
	}
	return out
}

// epssPct formats the EPSS threshold as a percentage for the dashboard explainer (0.1 -> "10").
func epssPct(f float64) string { return strconv.FormatFloat(f*100, 'f', -1, 64) }
