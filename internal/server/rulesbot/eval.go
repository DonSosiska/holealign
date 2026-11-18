package rulesbot

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/DonSosiska/holealign/internal/model"
	"github.com/DonSosiska/holealign/internal/server/config"
	"github.com/DonSosiska/holealign/internal/server/llm"
	"github.com/DonSosiska/holealign/internal/server/rules"
)

const maxEvalErrChars = 300

// Variant is one model (and effort) under evaluation.
type Variant struct {
	Model  string `json:"model"`
	Effort string `json:"effort"`
}

func (v Variant) String() string { return v.Model + "@" + v.Effort }

// ParseVariants parses a comma-separated list of model[@effort]. A missing effort is defaultEffort
// (medium when empty). Duplicates are an error.
func ParseVariants(s, defaultEffort string) ([]Variant, error) {
	if defaultEffort == "" {
		defaultEffort = "medium"
	}
	var out []Variant
	seen := map[Variant]bool{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		v := Variant{Model: part, Effort: defaultEffort}
		if i := strings.LastIndex(part, "@"); i >= 0 {
			v.Model, v.Effort = strings.TrimSpace(part[:i]), strings.TrimSpace(part[i+1:])
		}
		if v.Model == "" {
			return nil, fmt.Errorf("variant %q: empty model", part)
		}
		if !config.ValidEffort(v.Effort) || v.Effort == "" {
			return nil, fmt.Errorf("variant %q: effort must be one of %s", part, strings.Join(config.LLMEfforts, ", "))
		}
		if seen[v] {
			return nil, fmt.Errorf("variant %s is listed twice", v)
		}
		seen[v] = true
		out = append(out, v)
	}
	if len(out) == 0 {
		return nil, errors.New("no variants")
	}
	return out, nil
}

// CandidateFromRule derives the drafting input from a reference rule: the first CVE (else the first
// ID) of its vulns, its other vulns as aliases, and a package selector (a deb one if there is one):
// the source package if the selector has one, else its name without glob stars.
func CandidateFromRule(r model.Rule) (Candidate, error) {
	if len(r.Vulns) == 0 {
		return Candidate{}, errors.New("the rule has no vulns")
	}
	vuln := r.Vulns[0]
	for _, v := range r.Vulns {
		if strings.HasPrefix(v, "CVE-") {
			vuln = v
			break
		}
	}
	var aliases []string
	for _, v := range r.Vulns {
		if v != vuln {
			aliases = append(aliases, v)
		}
	}
	var sel *model.PackageSelector
	for i := range r.Packages {
		if r.Packages[i].Type == "deb" {
			sel = &r.Packages[i]
			break
		}
	}
	if sel == nil && len(r.Packages) > 0 {
		sel = &r.Packages[0]
	}
	if sel == nil {
		return Candidate{}, errors.New("the rule has no package selector")
	}
	typ := sel.Type
	if typ == "" {
		typ = "deb"
	}
	var eco string
	switch typ {
	case "deb":
		eco = "Debian:12"
	case "apk":
		eco = "Alpine:v3.20"
	default:
		return Candidate{}, fmt.Errorf("package type %q is not supported", typ)
	}
	pkg := sel.Source
	if pkg == "" {
		pkg = strings.ReplaceAll(sel.Name, "*", "")
	}
	if pkg == "" {
		return Candidate{}, errors.New("the package selector names no package")
	}
	var bins []string
	for _, s := range r.Packages {
		t := s.Type
		if t == "" {
			t = "deb"
		}
		if t == typ && s.Source == "" && s.Name != "" {
			if b := strings.ReplaceAll(s.Name, "*", ""); b != "" && !stringIn(bins, b) {
				bins = append(bins, b)
			}
		}
	}
	return Candidate{Vuln: vuln, Aliases: aliases, Package: pkg, Source: pkg, BinaryPackages: bins, Type: typ, Ecosystem: eco}, nil
}

func stringIn(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// Score compares a drafted rule with the reference test cases.
type Score struct {
	Compared          int `json:"compared"`
	Matched           int `json:"matched"`
	Skipped           int `json:"skipped"`
	Unsafe            int `json:"unsafe"`
	MissedExploitable int `json:"missed_exploitable"`
	// Unknown counts compared cases where the draft says conditions_unknown but the reference does not:
	// the draft reads a fact the reference case does not provide. Conservative, not wrong.
	Unknown   int          `json:"unknown"`
	Agreement float64      `json:"agreement"` // matched/compared; 0 when nothing was compared
	Cases     []CaseResult `json:"cases,omitempty"`
}

// CaseResult is one reference test case evaluated with the drafted rule.
type CaseResult struct {
	Name    string        `json:"name"`
	Want    model.Verdict `json:"want"`
	Got     model.Verdict `json:"got,omitempty"`
	Reason  string        `json:"reason,omitempty"`
	Skipped bool          `json:"skipped,omitempty"`
}

// ScoreDraft evaluates every reference case with the drafted rule (status forced to reviewed, as rule
// tests are) and compares the verdict with the case's want. A case counts only when the drafted rule
// matches its finding; the others are skipped. A case without a source whose package the reference
// rule selects by name gets the candidate's source package, so a drafted source selector can match it.
//
//	unsafe             the reference wants exploitable or conditions_unknown, the draft says
//	                   affected_not_exploitable or not_affected
//	missed_exploitable the reference wants exploitable, the draft does not
func ScoreDraft(drafted model.Rule, ref model.Rule, cases []rules.TestCase, source string) Score {
	drafted.Status = model.RuleReviewed
	e := rules.New([]model.Rule{drafted}, nil)
	var s Score
	for _, c := range cases {
		if c.Finding.Source == "" && source != "" && rules.SelectorMatches(ref.Packages, c.Finding.Package, c.Finding.Package, c.Finding.Type) {
			c.Finding.Source = source
		}
		ev, err := rules.EvalCase(e, c)
		if err != nil || ev.Rule == nil || ev.Rule.ID != drafted.ID {
			s.Skipped++
			s.Cases = append(s.Cases, CaseResult{Name: c.Name, Want: c.Want, Skipped: true})
			continue
		}
		s.Compared++
		s.Cases = append(s.Cases, CaseResult{Name: c.Name, Want: c.Want, Got: ev.Verdict, Reason: capText(ev.Reason, 300)})
		if ev.Verdict == c.Want {
			s.Matched++
		} else if ev.Verdict == model.VerdictConditionsUnknown {
			s.Unknown++
		}
		wantRisky := c.Want == model.VerdictExploitable || c.Want == model.VerdictConditionsUnknown
		gotSafe := ev.Verdict == model.VerdictNotExploitable || ev.Verdict == model.VerdictNotAffected
		if wantRisky && gotSafe {
			s.Unsafe++
		}
		if c.Want == model.VerdictExploitable && ev.Verdict != model.VerdictExploitable {
			s.MissedExploitable++
		}
	}
	if s.Compared > 0 {
		s.Agreement = float64(s.Matched) / float64(s.Compared)
	}
	return s
}

// EvalOptions configure RunEval.
type EvalOptions struct {
	Rules       []model.Rule                // the reference rules (all of them: the others are few-shot examples)
	Tests       map[string][]rules.TestCase // reference tests by rule ID
	IDs         []string                    // rules to evaluate; default: reviewed rules that have tests
	Variants    []Variant
	Runs        int // per rule and variant; default 3
	MaxAttempts int // per draft; default 2
	Concurrency int // default 2
	NewProvider func(Variant) (llm.Provider, error)
	Catalog     []llm.FactSpec
	Advisory    llm.AdvisorySource
	Logger      *slog.Logger
}

// RunResult is one draft of one reference rule by one variant.
type RunResult struct {
	RuleID   string      `json:"rule_id"`
	Variant  string      `json:"variant"`
	Run      int         `json:"run"`
	Success  bool        `json:"success"`
	Attempts int         `json:"attempts"`
	Refused  bool        `json:"refused"`
	Error    string      `json:"error,omitempty"`
	WallMS   int64       `json:"wall_ms"`
	Calls    int         `json:"calls"` // responses counted from the usage sink (0 when the provider reports none)
	Reached  bool        `json:"-"`     // the provider answered at least once
	Usage    llm.Usage   `json:"usage"`
	EstUSD   float64     `json:"est_usd"`
	EstKnown bool        `json:"est_known"` // false when the model has no price
	Score    *Score      `json:"score,omitempty"`
	Draft    *model.Rule `json:"draft,omitempty"`          // the drafted rule, for review of the scores
	Skipped  string      `json:"skipped_reason,omitempty"` // the rule could not be turned into a candidate
}

// Report is the result of RunEval.
type Report struct {
	GeneratedAt time.Time   `json:"generated_at"`
	Variants    []Variant   `json:"variants"`
	RuleIDs     []string    `json:"rule_ids"`
	Runs        int         `json:"runs_per_rule"`
	MaxAttempts int         `json:"max_attempts"`
	Results     []RunResult `json:"results"`
}

// ErrNoCalls is returned by RunEval (with the report) when no LLM call returned a response.
var ErrNoCalls = errors.New("no LLM call could be made")

// DefaultEvalIDs returns the IDs of the reviewed rules that have tests, sorted.
func DefaultEvalIDs(rs []model.Rule, tests map[string][]rules.TestCase) []string {
	var ids []string
	for _, r := range rs {
		if r.Status == model.RuleReviewed && len(tests[r.ID]) > 0 {
			ids = append(ids, r.ID)
		}
	}
	sort.Strings(ids)
	return ids
}

// cachedAdvisory fetches each advisory once, so every variant and run drafts from the same text.
type cachedAdvisory struct {
	src llm.AdvisorySource
	mu  sync.Mutex
	m   map[string]string
}

func (c *cachedAdvisory) Get(ctx context.Context, id string, aliases []string) (string, error) {
	key := id + "|" + strings.Join(aliases, ",")
	c.mu.Lock()
	if v, ok := c.m[key]; ok {
		c.mu.Unlock()
		return v, nil
	}
	c.mu.Unlock()
	v, err := c.src.Get(ctx, id, aliases)
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	c.m[key] = v
	c.mu.Unlock()
	return v, nil
}

// RunEval drafts every selected reference rule with every variant (Runs times each), through the same
// Draft pipeline as "rules draft", and scores the successful drafts against the reference tests.
// Nothing is written. Draft failures are results, not errors. The report is returned together with
// ErrNoCalls when not a single LLM call returned a response.
func RunEval(ctx context.Context, o EvalOptions) (*Report, error) {
	if o.Runs <= 0 {
		o.Runs = 3
	}
	if o.MaxAttempts <= 0 {
		o.MaxAttempts = 2
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 2
	}
	if len(o.Variants) == 0 {
		return nil, errors.New("no variants")
	}
	if o.NewProvider == nil {
		return nil, errors.New("no provider factory")
	}
	log := o.Logger
	if log == nil {
		log = slog.Default()
	}
	ids := o.IDs
	if len(ids) == 0 {
		ids = DefaultEvalIDs(o.Rules, o.Tests)
	}
	if len(ids) == 0 {
		return nil, errors.New("no reference rules to evaluate (reviewed rules with tests)")
	}
	byID := map[string]model.Rule{}
	for _, r := range o.Rules {
		byID[r.ID] = r
	}
	for _, id := range ids {
		if _, ok := byID[id]; !ok {
			return nil, fmt.Errorf("rule %s not found", id)
		}
		if len(o.Tests[id]) == 0 {
			return nil, fmt.Errorf("rule %s has no tests", id)
		}
	}
	provs := make([]llm.Provider, len(o.Variants))
	for i, v := range o.Variants {
		p, err := o.NewProvider(v)
		if err != nil {
			return nil, fmt.Errorf("variant %s: %w", v, err)
		}
		if p == nil {
			return nil, fmt.Errorf("variant %s: no provider", v)
		}
		provs[i] = p
	}
	adv := o.Advisory
	if adv != nil {
		adv = &cachedAdvisory{src: adv, m: map[string]string{}}
	}

	type job struct {
		idx, vi, run int
		id           string
	}
	var jobs []job
	for _, id := range ids {
		for vi := range o.Variants {
			for run := 1; run <= o.Runs; run++ {
				jobs = append(jobs, job{len(jobs), vi, run, id})
			}
		}
	}
	results := make([]RunResult, len(jobs))
	ch := make(chan job)
	var wg sync.WaitGroup
	for w := 0; w < o.Concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range ch {
				results[j.idx] = evalOne(ctx, o, provs[j.vi], o.Variants[j.vi], byID[j.id], j.run, adv, log)
			}
		}()
	}
loop:
	for _, j := range jobs {
		select {
		case ch <- j:
		case <-ctx.Done():
			break loop
		}
	}
	close(ch)
	wg.Wait()

	rep := &Report{GeneratedAt: time.Now().UTC(), Variants: o.Variants, RuleIDs: ids, Runs: o.Runs, MaxAttempts: o.MaxAttempts}
	reached := 0
	for _, r := range results {
		if r.RuleID == "" { // not started (cancelled)
			continue
		}
		if r.Reached {
			reached++
		}
		rep.Results = append(rep.Results, r)
	}
	if ctx.Err() != nil {
		return rep, ctx.Err()
	}
	if reached == 0 {
		return rep, ErrNoCalls
	}
	return rep, nil
}

func evalOne(ctx context.Context, o EvalOptions, prov llm.Provider, v Variant, ref model.Rule, run int, adv llm.AdvisorySource, log *slog.Logger) RunResult {
	res := RunResult{RuleID: ref.ID, Variant: v.String(), Run: run}
	cand, err := CandidateFromRule(ref)
	if err != nil {
		res.Skipped = err.Error()
		res.Error = capText(err.Error(), maxEvalErrChars)
		return res
	}
	// No leakage: the reference rule is neither a few-shot example nor an ID collision.
	var others []model.Rule
	for _, r := range o.Rules {
		if r.ID != ref.ID {
			others = append(others, r)
		}
	}
	var mu sync.Mutex
	ctx = llm.WithUsageSink(ctx, func(u llm.Usage) {
		mu.Lock()
		res.Usage = res.Usage.Add(u)
		res.Calls++
		mu.Unlock()
	})
	var st DraftStats
	start := time.Now()
	d, err := Draft(ctx, DraftOptions{Candidate: cand, Provider: prov, Rules: others, Tests: o.Tests, Catalog: o.Catalog,
		Advisory: adv, MaxAttempts: o.MaxAttempts, Logger: log.With("rule", ref.ID, "variant", v.String(), "run", run), Stats: &st})
	res.WallMS = time.Since(start).Milliseconds()
	res.Attempts, res.Refused, res.Reached = st.Attempts, st.Refused, st.Responses > 0
	if res.Usage.Model == "" {
		res.Usage.Model = v.Model
	}
	res.EstUSD, res.EstKnown = llm.EstimateUSD(res.Usage)
	if err != nil {
		res.Error = capText(err.Error(), maxEvalErrChars)
		return res
	}
	res.Success = true
	sc := ScoreDraft(d.Rule, ref, o.Tests[ref.ID], cand.Package)
	res.Score = &sc
	drafted := d.Rule
	res.Draft = &drafted
	return res
}

func capText(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "..."
	}
	return s
}

// Stats aggregates the results of one variant (for one rule, or for all of them).
type Stats struct {
	Runs      int
	Successes int
	Agreement float64 // mean over successful drafts that had at least one compared case
	Scored    int     // successful drafts that had at least one compared case
	Unsafe    int
	Missed    int
	Unknown   int
	// Decisive is the mean, over successful drafts, of matched / (compared - unknown): agreement on
	// the cases where the draft gave a definite verdict. DecisiveN counts the drafts it averages.
	Decisive  float64
	DecisiveN int
	Attempts  float64 // mean per run
	Tokens    float64 // mean per run, all kinds
	USDTotal  float64
	USDKnown  bool // every run's model has a price
	USDPerOK  float64
}

func aggregate(rs []RunResult) Stats {
	var s Stats
	s.USDKnown = true
	var agr float64
	var att, tok int64
	for _, r := range rs {
		s.Runs++
		att += int64(r.Attempts)
		tok += r.Usage.InputTokens + r.Usage.OutputTokens + r.Usage.CacheReadTokens + r.Usage.CacheWriteTokens
		if r.EstKnown {
			s.USDTotal += r.EstUSD
		} else if r.Calls > 0 {
			s.USDKnown = false
		}
		if r.Success {
			s.Successes++
			if r.Score != nil {
				s.Unsafe += r.Score.Unsafe
				s.Missed += r.Score.MissedExploitable
				s.Unknown += r.Score.Unknown
				if d := r.Score.Compared - r.Score.Unknown; d > 0 {
					s.Decisive += float64(r.Score.Matched) / float64(d)
					s.DecisiveN++
				}
				if r.Score.Compared > 0 {
					agr += r.Score.Agreement
					s.Scored++
				}
			}
		}
	}
	if s.Scored > 0 {
		s.Agreement = agr / float64(s.Scored)
	}
	if s.DecisiveN > 0 {
		s.Decisive /= float64(s.DecisiveN)
	}
	if s.Runs > 0 {
		s.Attempts = float64(att) / float64(s.Runs)
		s.Tokens = float64(tok) / float64(s.Runs)
	}
	if s.Successes > 0 {
		s.USDPerOK = s.USDTotal / float64(s.Successes)
	}
	return s
}

func usdCell(v float64, known bool, ok bool) string {
	if !known || !ok {
		return "n/a"
	}
	return fmt.Sprintf("$%.4f", v)
}

func pct(f float64, ok bool) string {
	if !ok {
		return "n/a"
	}
	return fmt.Sprintf("%.0f%%", f*100)
}

// Markdown renders the summary: one table per variant (per rule), then a comparison of the variants.
func (r *Report) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Rule drafting evaluation\n\n%d reference rule(s), %d run(s) each, up to %d attempt(s) per draft. Estimated costs are list prices and approximate.\n\n",
		len(r.RuleIDs), r.Runs, r.MaxAttempts)
	for _, v := range r.Variants {
		name := v.String()
		fmt.Fprintf(&b, "## %s\n\n", name)
		b.WriteString("| Rule | Success | Mean agreement | Unsafe | Mean attempts | Mean tokens | Est. USD per success |\n|---|---|---|---|---|---|---|\n")
		for _, id := range r.RuleIDs {
			var rs []RunResult
			for _, x := range r.Results {
				if x.Variant == name && x.RuleID == id {
					rs = append(rs, x)
				}
			}
			if len(rs) == 0 {
				continue
			}
			s := aggregate(rs)
			fmt.Fprintf(&b, "| %s | %d/%d | %s | %d | %.1f | %.0f | %s |\n", id, s.Successes, s.Runs,
				pct(s.Agreement, s.Scored > 0), s.Unsafe, s.Attempts, s.Tokens, usdCell(s.USDPerOK, s.USDKnown, s.Successes > 0))
		}
		b.WriteString("\n")
	}
	b.WriteString("## Variants compared\n\n")
	b.WriteString("| Variant | Runs | Success rate | Mean agreement | Decisive agreement | Unsafe | Missed exploitable | Unknown instead | Est. USD per success | Total est. USD |\n|---|---|---|---|---|---|---|---|---|---|\n")
	for _, v := range r.Variants {
		var rs []RunResult
		for _, x := range r.Results {
			if x.Variant == v.String() {
				rs = append(rs, x)
			}
		}
		s := aggregate(rs)
		rate := 0.0
		if s.Runs > 0 {
			rate = float64(s.Successes) / float64(s.Runs)
		}
		fmt.Fprintf(&b, "| %s | %d | %s | %s | %s | %d | %d | %d | %s | %s |\n", v, s.Runs, pct(rate, s.Runs > 0),
			pct(s.Agreement, s.Scored > 0), pct(s.Decisive, s.DecisiveN > 0), s.Unsafe, s.Missed, s.Unknown, usdCell(s.USDPerOK, s.USDKnown, s.Successes > 0), usdCell(s.USDTotal, s.USDKnown, true))
	}
	b.WriteString("\nUnsafe: compared reference cases that want exploitable or conditions_unknown where the draft says affected_not_exploitable or not_affected. Agreement is averaged over successful drafts with at least one compared case. Decisive agreement: agreement over the cases where the draft gave a definite verdict (the unknown-instead cases left out). Unknown instead: mismatches where the draft says conditions_unknown because it reads a fact the reference case does not provide (conservative, not wrong).\n")
	return b.String()
}
