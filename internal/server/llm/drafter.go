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
	"panoptes/internal/server/store"
)

const (
	queueSize   = 256
	failedTTL   = 7 * 24 * time.Hour
	kvFailedPfx = "llm.failed."
	kvCallsPfx  = "llm.calls."
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
	Logger   *slog.Logger
	Now      func() time.Time
}

// Drafter implements core.RuleDrafter.
type Drafter struct {
	d     Deps
	queue chan model.Finding

	mu       sync.Mutex
	inflight map[string]bool
	limitLog string // day for which the limit message was logged
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
	return &Drafter{d: d, queue: make(chan model.Finding, queueSize), inflight: map[string]bool{}}
}

func keyOf(f model.Finding) string { return f.VulnID + "|" + sourceOf(f) }

// sourceOf returns the source package of a finding: the "upstream" qualifier of its PURL
// (without any @version), falling back to the package name.
func sourceOf(f model.Finding) string {
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
	select {
	case d.queue <- f:
		d.inflight[k] = true
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
	id := RuleID(f.VulnID, sourceOf(f))
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
	source := sourceOf(f)
	all := []model.Finding{f}
	if d.d.Siblings != nil {
		all = append(all, d.d.Siblings(ctx, f.VulnID, source)...)
	}
	siblings := siblingPackages(all)
	system := buildSystemPrompt(d.d.FactCatalog)
	user := buildUserPrompt(f, source, siblings, distro, advisory)

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
		reply, err := d.d.Provider.Complete(ctx, system, prompt)
		if err != nil {
			if errors.Is(err, ErrRefused) {
				log.Warn("llm: model refused")
				d.markFailed(ctx, key, now)
			} else {
				// API/network error: not recorded, so the next pipeline run retries.
				log.Warn("llm: completion failed", "err", err)
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
	if !contains(r.Vulns, f.VulnID) {
		r.Vulns = append(r.Vulns, f.VulnID)
	}
	for _, sel := range append([]model.PackageSelector{{Name: f.PackageName, Type: f.PackageType}}, siblings...) {
		if !selectorMatches(r.Packages, sel.Name, sel.Type) {
			r.Packages = append(r.Packages, sel)
		}
	}
	for i := range r.FactRequests {
		if r.FactRequests[i].Collector == "" {
			r.FactRequests[i].Collector = "file.match"
		}
	}
	return r, nil
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
