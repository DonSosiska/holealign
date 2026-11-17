package web

import (
	"bytes"
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

	"panoptes/internal/model"
	"panoptes/internal/server/store"
)

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request, sess *session) {
	ctx := r.Context()
	type count struct {
		Verdict model.Verdict
		N       int
	}
	var counts []count
	for _, v := range allVerdicts[:4] {
		_, n, err := s.d.Store.ListFindings(ctx, store.FindingFilter{Verdict: v, Limit: 1})
		if err != nil {
			s.storeErr(w, r, sess, err)
			return
		}
		counts = append(counts, count{v, n})
	}
	top, _, err := s.d.Store.ListFindings(ctx, store.FindingFilter{Verdict: model.VerdictExploitable, Limit: 1000})
	if err != nil {
		s.storeErr(w, r, sess, err)
		return
	}
	sort.SliceStable(top, func(i, j int) bool {
		if top[i].KEV != top[j].KEV {
			return top[i].KEV
		}
		return top[i].CVSS > top[j].CVSS
	})
	if len(top) > 10 {
		top = top[:10]
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
		"Counts": counts, "Top": top, "HostNames": names, "Stale": stale, "HostCount": len(hosts),
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
	type row struct {
		model.Host
		Exploitable, Unknown int
	}
	rows := make([]row, 0, len(hosts))
	for _, h := range hosts {
		fs, err := s.d.Store.HostFindings(ctx, h.ID)
		if err != nil {
			s.storeErr(w, r, sess, err)
			return
		}
		rw := row{Host: h}
		for _, f := range fs {
			switch f.Verdict {
			case model.VerdictExploitable:
				rw.Exploitable++
			case model.VerdictConditionsUnknown:
				rw.Unknown++
			}
		}
		rows = append(rows, rw)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Exploitable != rows[j].Exploitable {
			return rows[i].Exploitable > rows[j].Exploitable
		}
		return rows[i].Hostname < rows[j].Hostname
	})
	s.render(w, r, sess, http.StatusOK, "hosts", map[string]any{"Rows": rows})
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
	all := r.URL.Query().Get("all") == "1"
	var shown []model.Finding
	hidden := 0
	for _, f := range fs {
		if f.Verdict == model.VerdictResolved && !all {
			hidden++
			continue
		}
		shown = append(shown, f)
	}
	sortFindings(shown)
	s.render(w, r, sess, http.StatusOK, "host", map[string]any{
		"Host": h, "Targets": targets, "Findings": shown, "Hidden": hidden, "All": all,
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
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	f.Offset = (page - 1) * pageSize
	return f, page
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request, sess *session) {
	ctx := r.Context()
	q := r.URL.Query()
	f, page := parseFilter(q)
	list, total, err := s.d.Store.ListFindings(ctx, f)
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
	pageURL := func(p int) string {
		v := url.Values{}
		for k, vs := range q {
			if k != "page" {
				v[k] = vs
			}
		}
		v.Set("page", strconv.Itoa(p))
		return "/findings?" + v.Encode()
	}
	pages := (total + pageSize - 1) / pageSize
	data := map[string]any{
		"Findings": list, "Total": total, "Page": page, "Pages": pages, "HostNames": names, "Hosts": hosts, "Labels": labels,
		"Verdicts": allVerdicts, "Q": q.Get("q"), "FVerdict": string(f.Verdict), "FLabel": f.Label, "FHost": f.HostID,
		"FKEV": q.Get("kev"), "FResolved": f.IncludeResolved,
	}
	if page > 1 {
		data["PrevURL"] = pageURL(page - 1)
	}
	if page < pages {
		data["NextURL"] = pageURL(page + 1)
	}
	s.render(w, r, sess, http.StatusOK, "findings", data)
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
	list, _, err := s.d.Store.ListFindings(ctx, store.FindingFilter{VulnID: id, IncludeResolved: true, Limit: 1000})
	if err != nil {
		s.storeErr(w, r, sess, err)
		return
	}
	if len(list) == 0 {
		s.notFound(w, r, sess)
		return
	}
	hn, _, err := s.hostNames(ctx)
	if err != nil {
		s.storeErr(w, r, sess, err)
		return
	}
	type group struct {
		Verdict  model.Verdict
		Findings []model.Finding
	}
	var groups []group
	for _, v := range allVerdicts {
		var fs []model.Finding
		for _, f := range list {
			if f.Verdict == v {
				fs = append(fs, f)
			}
		}
		if len(fs) > 0 {
			sortFindings(fs)
			groups = append(groups, group{v, fs})
		}
	}
	s.render(w, r, sess, http.StatusOK, "vuln", map[string]any{"VulnID": id, "Groups": groups, "HostNames": hn, "Total": len(list)})
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
		if p.Type != "" {
			n += " (" + clip(p.Type, 32) + ")"
		}
		pkgs = append(pkgs, n)
	}
	s.render(w, r, sess, status, "rule", map[string]any{
		"Rule": rule, "YAML": yamlText, "Error": errMsg, "Findings": findings, "HostNames": names, "NoEngine": s.d.Rules == nil,
		"Version": ruleVersion(stored), "Draft": rule.Status == model.RuleDraft,
		"FactRows": factRows(rule), "Pkgs": pkgs,
		"LLMTitle": clip(rule.Title, llmTitleMax), "LLMExplanation": clip(rule.Explanation, llmExplanationMax),
		"LLMUpgrade": clip(rule.Fix.Upgrade, llmFixMax), "LLMMitigation": clip(rule.Fix.Mitigation, llmFixMax),
	})
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
