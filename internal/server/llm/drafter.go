package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"panoptes/internal/model"
	"panoptes/internal/server/rules"
	"panoptes/internal/server/store"
)

const (
	queueSize   = 256
	failedTTL   = 7 * 24 * time.Hour
	kvFailedPfx = "llm.failed."
	kvCallsPfx  = "llm.calls."
	kvCoolPfx   = "llm.cooldown."

	cooldownTTL          = 6 * time.Hour
	completeTimeout      = 120 * time.Second
	maxEnqueuePerHostDay = 100
	maxRetryErrBytes     = 2048
	maxFixChars          = 300
)

// Validator checks a drafted rule (implemented by internal/server/rules).
type Validator interface{ Validate(r model.Rule) error }

// Deps are the Drafter's collaborators.
type Deps struct {
	Store       store.Store
	Provider    Provider
	Validator   Validator
	FactCatalog []FactSpec
	DailyLimit  int // default 50
	OnRuleAdded func(ctx context.Context, r model.Rule)
	Advisory    AdvisorySource // default: OSV
	// Siblings returns the findings of a vulnerability that share a source package (optional).
	Siblings func(ctx context.Context, vulnID, source string) []model.Finding
	// Rules returns the engine's rules (file rules included) for coverage checks (optional).
	Rules  func() []model.Rule
	Logger *slog.Logger
	Now    func() time.Time
}

// Drafter implements core.RuleDrafter.
type Drafter struct {
	d     Deps
	queue chan model.Finding

	mu       sync.Mutex
	inflight map[string]bool
	limitLog string // day for which the limit message was logged
	hostDay  string
	hostCnt  map[string]int
}

// NewDrafter fills defaults.
func NewDrafter(d Deps) *Drafter {
	if d.DailyLimit <= 0 {
		d.DailyLimit = 50
	}
	if d.Advisory == nil {
		d.Advisory = NewOSVSource()
	}
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	return &Drafter{d: d, queue: make(chan model.Finding, queueSize), inflight: map[string]bool{}, hostCnt: map[string]int{}}
}

func keyOf(f model.Finding) string { return f.VulnID + "|" + SourceOf(f) }

// sourceOf returns the source package of a finding: the "upstream" qualifier of its PURL
// (without any @version), falling back to the package name.
// SourceOf returns the source (upstream) package of a finding: the PURL "upstream"
// qualifier without version, or the package name.
func SourceOf(f model.Finding) string {
	if i := strings.IndexByte(f.PURL, '?'); i >= 0 {
		if q, err := url.ParseQuery(f.PURL[i+1:]); err == nil {
			up := q.Get("upstream")
			if j := strings.IndexByte(up, '@'); j >= 0 {
				up = up[:j]
			}
			if up != "" {
				return up
			}
		}
	}
	return f.PackageName
}

func selectorMatches(sels []model.PackageSelector, name, typ string) bool {
	for _, p := range sels {
		if ok, _ := path.Match(p.Name, name); ok && (p.Type == "" || p.Type == typ) {
			return true
		}
	}
	return false
}

// covered reports whether any stored rule already covers the finding's vuln and package.
func (d *Drafter) covered(ctx context.Context, f model.Finding) (bool, error) {
	rules, err := d.d.Store.ListRules(ctx)
	if err != nil {
		return false, err
	}
	if d.d.Rules != nil {
		rules = append(rules, d.d.Rules()...)
	}
	ids := append([]string{f.VulnID}, f.Aliases...)
	for _, r := range rules {
		for _, id := range ids {
			if contains(r.Vulns, id) && selectorMatches(r.Packages, f.PackageName, f.PackageType) {
				return true, nil
			}
		}
	}
	return false, nil
}

// siblingPackages returns the distinct (name, type) pairs of the findings, sorted.
func siblingPackages(fs []model.Finding) []model.PackageSelector {
	seen := map[model.PackageSelector]bool{}
	var out []model.PackageSelector
	for _, f := range fs {
		s := model.PackageSelector{Name: f.PackageName, Type: f.PackageType}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Type < out[j].Type
	})
	return out
}

// Start launches the single worker; it stops when ctx is done.
func (d *Drafter) Start(ctx context.Context) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case f := <-d.queue:
				d.handle(ctx, f)
				d.mu.Lock()
				delete(d.inflight, keyOf(f))
				d.mu.Unlock()
			}
		}
	}()
}

// Enqueue never blocks. Duplicate queued/in-flight findings are ignored.
func (d *Drafter) Enqueue(_ context.Context, f model.Finding) {
	if d.d.Provider == nil {
		return
	}
	k := keyOf(f)
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.inflight[k] {
		return
	}
	day := d.d.Now().UTC().Format("2006-01-02")
	if d.hostDay != day {
		d.hostDay, d.hostCnt = day, map[string]int{}
	}
	// Findings always carry a host; the empty ID only occurs in tests.
	if f.HostID != "" && d.hostCnt[f.HostID] >= maxEnqueuePerHostDay {
		d.d.Logger.Debug("llm: per-host daily enqueue cap reached", "host", f.HostID)
		return
	}
	select {
	case d.queue <- f:
		d.inflight[k] = true
		if f.HostID != "" {
			d.hostCnt[f.HostID]++
		}
	default:
		d.d.Logger.Debug("llm: queue full, dropping", "key", k)
	}
}

// RuleID is the ID generated for a finding's LLM rule.
func RuleID(vulnID, pkg string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(pkg) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	return vulnID + "-" + b.String()
}

func (d *Drafter) handle(ctx context.Context, f model.Finding) {
	log := d.d.Logger.With("vuln", f.VulnID, "package", f.PackageName)
	key := keyOf(f)
	id := RuleID(f.VulnID, SourceOf(f))
	now := d.d.Now()

	if _, err := d.d.Store.GetRule(ctx, id); err == nil {
		return // exists (including rejected)
	} else if !errors.Is(err, store.ErrNotFound) {
		log.Warn("llm: rule lookup failed", "err", err)
		return
	}
	if cov, err := d.covered(ctx, f); err != nil {
		log.Warn("llm: rule listing failed", "err", err)
		return
	} else if cov {
		return
	}
	if v, err := d.d.Store.KVGet(ctx, kvFailedPfx+key); err == nil {
		if t, perr := time.Parse(time.RFC3339, v); perr == nil && now.Sub(t) < failedTTL {
			return
		}
	}

	if v, err := d.d.Store.KVGet(ctx, kvCoolPfx+key); err == nil {
		if t, perr := time.Parse(time.RFC3339, v); perr == nil && now.Sub(t) < cooldownTTL {
			return
		}
	}
	if !d.underLimit(ctx, now, log) { // before any network I/O
		return
	}

	distro := ""
	if h, err := d.d.Store.GetHost(ctx, f.HostID); err == nil {
		distro = h.OS.PrettyName
		if distro == "" {
			distro = strings.TrimSpace(h.OS.ID + " " + h.OS.VersionID)
		}
	}
	advisory, err := d.d.Advisory.Get(ctx, f.VulnID, f.Aliases)
	if err != nil {
		log.Debug("llm: advisory unavailable, drafting from finding data", "err", err)
		advisory = ""
	}
	source := SourceOf(f)
	all := []model.Finding{f}
	if d.d.Siblings != nil {
		all = append(all, d.d.Siblings(ctx, f.VulnID, source)...)
	}
	siblings := siblingPackages(all)
	system := buildSystemPrompt(d.d.FactCatalog)
	user := buildUserPrompt(f, source, siblings, distro, advisory) +
		"\n\nIf you declare fact_requests, every name must start with \"" + rules.FactRequestPrefix(id) + "\" followed by a short id."

	var lastReply string
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		prompt := user
		if attempt == 1 {
			prompt = buildRetryPrompt(user, lastReply, lastErr)
		}
		if !d.takeCall(ctx, now, log) {
			return
		}
		cctx, cancel := context.WithTimeout(ctx, completeTimeout)
		reply, err := d.d.Provider.Complete(cctx, system, prompt)
		cancel()
		if err != nil {
			if errors.Is(err, ErrRefused) {
				log.Warn("llm: model refused")
				d.markFailed(ctx, key, now)
			} else {
				// API/network error: cool this key down so a failing provider is not hammered.
				log.Warn("llm: completion failed", "err", err)
				if kerr := d.d.Store.KVSet(ctx, kvCoolPfx+key, now.UTC().Format(time.RFC3339), now); kerr != nil {
					log.Warn("llm: recording cooldown", "err", kerr)
				}
			}
			return
		}
		rule, err := d.parse(reply, f, siblings, id)
		if err == nil {
			err = d.d.Validator.Validate(rule)
		}
		if err != nil {
			lastReply, lastErr = reply, err
			log.Info("llm: draft invalid", "attempt", attempt+1, "err", err)
			continue
		}
		if err := d.d.Store.UpsertRule(ctx, rule, now); err != nil {
			log.Error("llm: storing rule failed", "err", err)
			return
		}
		log.Info("llm: rule drafted", "rule", rule.ID)
		if d.d.OnRuleAdded != nil {
			d.d.OnRuleAdded(ctx, rule)
		}
		return
	}
	d.markFailed(ctx, key, now)
}

func (d *Drafter) markFailed(ctx context.Context, key string, now time.Time) {
	if err := d.d.Store.KVSet(ctx, kvFailedPfx+key, now.UTC().Format(time.RFC3339), now); err != nil {
		d.d.Logger.Warn("llm: recording failure", "err", err)
	}
}

func (d *Drafter) underLimit(ctx context.Context, now time.Time, log *slog.Logger) bool {
	day := now.UTC().Format("2006-01-02")
	n := 0
	if v, err := d.d.Store.KVGet(ctx, kvCallsPfx+day); err == nil {
		n, _ = strconv.Atoi(v)
	}
	if n >= d.d.DailyLimit {
		d.mu.Lock()
		first := d.limitLog != day
		d.limitLog = day
		d.mu.Unlock()
		if first {
			log.Warn("llm: daily limit reached, dropping drafts", "limit", d.d.DailyLimit)
		}
		return false
	}
	return true
}

// takeCall enforces and increments the UTC daily counter.
func (d *Drafter) takeCall(ctx context.Context, now time.Time, log *slog.Logger) bool {
	day := now.UTC().Format("2006-01-02")
	k := kvCallsPfx + day
	n := 0
	if v, err := d.d.Store.KVGet(ctx, k); err == nil {
		n, _ = strconv.Atoi(v)
	}
	if n >= d.d.DailyLimit {
		d.mu.Lock()
		first := d.limitLog != day
		d.limitLog = day
		d.mu.Unlock()
		if first {
			log.Warn("llm: daily limit reached, dropping drafts", "limit", d.d.DailyLimit)
		}
		return false
	}
	if err := d.d.Store.KVSet(ctx, k, strconv.Itoa(n+1), now); err != nil {
		log.Warn("llm: counter update failed", "err", err)
	}
	return true
}

func (d *Drafter) parse(reply string, f model.Finding, siblings []model.PackageSelector, id string) (model.Rule, error) {
	var r model.Rule
	obj, err := extractJSON(reply)
	if err != nil {
		return r, err
	}
	if err := json.Unmarshal([]byte(obj), &r); err != nil {
		return r, fmt.Errorf("invalid rule JSON: %w", err)
	}
	r.ID = id
	r.Status = model.RuleDraft
	name := d.d.Provider.Name()
	if i := strings.Index(name, ":"); i >= 0 {
		name = name[i+1:]
	}
	r.Source = "llm:" + name
	// Vulns and Packages are forced from the finding: nothing the model wrote there is trusted.
	r.Vulns = nil
	for _, v := range append([]string{f.VulnID}, f.Aliases...) {
		if v != "" && !contains(r.Vulns, v) {
			r.Vulns = append(r.Vulns, v)
		}
	}
	allowed := map[model.PackageSelector]bool{}
	var forced []model.PackageSelector
	for _, sel := range append([]model.PackageSelector{{Name: f.PackageName, Type: f.PackageType}}, siblings...) {
		if sel.Name == "" {
			continue
		}
		e := model.PackageSelector{Name: escapeGlob(sel.Name), Type: sel.Type}
		if !allowed[e] {
			allowed[e] = true
			forced = append(forced, e)
		}
	}
	var kept []model.PackageSelector
	for _, sel := range r.Packages { // drop anything not in the allowed set
		if allowed[sel] {
			kept = append(kept, sel)
		}
	}
	r.Packages = normalizeSelectors(append(kept, forced...))
	if len(r.Packages) == 0 {
		return r, errors.New("no package selectors for the finding")
	}
	r.Fix.Upgrade = cleanText(r.Fix.Upgrade, maxFixChars)
	r.Fix.Mitigation = cleanText(r.Fix.Mitigation, maxFixChars)
	for i := range r.FactRequests {
		if r.FactRequests[i].Collector == "" {
			r.FactRequests[i].Collector = "file.match"
		}
	}
	return r, nil
}

// normalizeSelectors drops exact duplicate package selectors and sorts the rest
// by name, then type, so that drafted rules have stable output.
func normalizeSelectors(sels []model.PackageSelector) []model.PackageSelector {
	if sels == nil {
		return nil
	}
	seen := make(map[model.PackageSelector]bool, len(sels))
	out := make([]model.PackageSelector, 0, len(sels))
	for _, s := range sels {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Type < out[j].Type
	})
	return out
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// extractJSON returns the first balanced top-level JSON object in s (fences tolerated).
func extractJSON(s string) (string, error) {
	start := strings.IndexByte(s, '{')
	if start < 0 {
		return "", errors.New("no JSON object in reply")
	}
	depth, inStr, esc := 0, false, false
	for i := start; i < len(s); i++ {
		c := s[i]
		switch {
		case inStr:
			if esc {
				esc = false
			} else if c == '\\' {
				esc = true
			} else if c == '"' {
				inStr = false
			}
		case c == '"':
			inStr = true
		case c == '{':
			depth++
		case c == '}':
			depth--
			if depth == 0 {
				return s[start : i+1], nil
			}
		}
	}
	return "", errors.New("unterminated JSON object in reply")
}

// escapeGlob escapes path.Match metacharacters so that name matches literally.
func escapeGlob(name string) string {
	var b strings.Builder
	for _, r := range name {
		if strings.ContainsRune(`*?[]\`, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}
