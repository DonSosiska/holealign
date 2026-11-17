// Package match wraps Grype (used as a Go library) to turn a CycloneDX SBOM into findings.
//
// KEV and EPSS come straight from the Grype DB (schema v6 ships CISA KEV and FIRST EPSS
// enrichment): vulnerability.Metadata.KnownExploited / .EPSS, fetched through the
// provider's VulnerabilityMetadata for the (CVE-normalised) vulnerability reference.
// No separate KEV/EPSS fetchers are needed.
package match

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype"
	v6dist "github.com/anchore/grype/grype/db/v6/distribution"
	v6inst "github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/matcher/dpkg"
	"github.com/anchore/grype/grype/matcher/golang"
	"github.com/anchore/grype/grype/matcher/java"
	"github.com/anchore/grype/grype/matcher/rpm"
	"github.com/anchore/grype/grype/matcher/stock"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"

	"github.com/DonSosiska/panoptes/internal/model"
)

// MaxPackages caps the packages Grype may decode from one SBOM; the API pre-parser enforces the same
// limit on CycloneDX components, this one does not depend on it.
const MaxPackages = 50000

// ErrTooManyPackages is returned by Match when a decoded SBOM has more than MaxPackages packages.
var ErrTooManyPackages = errors.New("sbom has too many packages")

// ErrNoDB is returned by Match when no Grype database has been loaded yet.
var ErrNoDB = errors.New("grype vulnerability DB not available")

// DBStatus describes the loaded vulnerability DB.
type DBStatus struct {
	Built         time.Time
	SchemaVersion string
	Path          string
}

// Grype implements pipeline.Matcher with the Grype library. It is safe for concurrent use;
// Reload swaps the underlying DB atomically.
type Grype struct {
	dbRoot string
	log    *slog.Logger

	mu     sync.Mutex
	cur    *provRef
	status DBStatus
}

// provRef is a reference-counted provider: Reload retires the old one, which is closed once the
// last in-flight Match using it finished (Match does not hold g.mu while matching).
type provRef struct {
	p       vulnerability.Provider
	refs    int
	retired bool
}

func (g *Grype) acquire() *provRef {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.cur != nil {
		g.cur.refs++
	}
	return g.cur
}

func (g *Grype) release(r *provRef) {
	g.mu.Lock()
	r.refs--
	closeNow := r.retired && r.refs == 0
	g.mu.Unlock()
	if closeNow {
		_ = r.p.Close()
	}
}

// retireLocked marks r retired and reports whether it can be closed right away.
func retireLocked(r *provRef) bool {
	if r == nil {
		return false
	}
	r.retired = true
	return r.refs == 0
}

// dbMaxAge is the age after which a loaded DB triggers a warning.
const dbMaxAge = 5 * 24 * time.Hour

// NewGrype creates a matcher whose DB lives under dbRoot (e.g. data_dir/grype-db).
// Call Reload before Match.
func NewGrype(dbRoot string, log *slog.Logger) *Grype {
	if log == nil {
		log = slog.Default()
	}
	return &Grype{dbRoot: dbRoot, log: log}
}

// Ready reports whether a DB is loaded.
func (g *Grype) Ready() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.cur != nil
}

// Status returns information about the loaded DB.
func (g *Grype) Status() DBStatus {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.status
}

// Reload loads the DB from disk. With update=true it first tries to download a newer DB;
// download failures are logged and the existing DB (if any) is kept. It returns true when the
// loaded DB differs from the one served before (different build time).
func (g *Grype) Reload(ctx context.Context, update bool) (changed bool, err error) {
	id := clio.Identification{Name: "panoptes", Version: "dev"}
	dist := v6dist.DefaultConfig()
	dist.ID = id
	dist.RequireUpdateCheck = false // offline: keep the old DB
	inst := v6inst.DefaultConfig(id)
	inst.DBRootDir = g.dbRoot
	inst.ValidateAge = false // an old DB beats no DB; the feeds timestamps tell the operator

	type result struct {
		p   vulnerability.Provider
		st  *vulnerability.ProviderStatus
		err error
	}
	ch := make(chan result, 1)
	go func() {
		p, st, err := grype.LoadVulnerabilityDB(dist, inst, update)
		ch <- result{p, st, err}
	}()
	var r result
	select {
	case r = <-ch:
	case <-ctx.Done():
		go func() { // do not leak the provider if it finishes later
			if late := <-ch; late.p != nil {
				_ = late.p.Close()
			}
		}()
		return false, ctx.Err()
	}
	if r.err != nil {
		return false, fmt.Errorf("load grype db: %w", r.err)
	}
	st := DBStatus{Path: r.st.Path, SchemaVersion: r.st.SchemaVersion, Built: r.st.Built}

	g.mu.Lock()
	old := g.cur
	changed = old == nil || !g.status.Built.Equal(st.Built)
	g.cur, g.status = &provRef{p: r.p}, st
	closeOld := retireLocked(old)
	g.mu.Unlock()
	if closeOld {
		_ = old.p.Close()
	}
	if !st.Built.IsZero() && time.Since(st.Built) > dbMaxAge {
		g.log.Warn("grype db is stale; vulnerability data may be outdated", "built", st.Built,
			"age_days", int(time.Since(st.Built).Hours()/24))
	}
	g.log.Info("grype db loaded", "built", st.Built, "schema", st.SchemaVersion, "changed", changed)
	return changed, nil
}

// Close releases the DB.
func (g *Grype) Close() error {
	g.mu.Lock()
	old := g.cur
	g.cur = nil
	closeNow := retireLocked(old)
	g.mu.Unlock()
	if closeNow {
		return old.p.Close()
	}
	return nil
}

func matcherConfig() matcher.Config {
	return matcher.Config{
		Java:   java.MatcherConfig{UseCPEs: false},
		Golang: golang.MatcherConfig{},
		Stock:  stock.MatcherConfig{UseCPEs: true},
		Dpkg:   dpkg.MatcherConfig{MissingEpochStrategy: version.MissingEpochStrategyZero},
		Rpm:    rpm.MatcherConfig{MissingEpochStrategy: version.MissingEpochStrategyAuto},
	}
}

// Match finds vulnerabilities in one CycloneDX SBOM. For host targets the OS info from
// the check-in is used as a distro hint; image SBOMs carry their own distro.
// Returned findings have only matcher-derived fields set (no HostID/Target/Verdict).
func (g *Grype) Match(ctx context.Context, kind model.TargetKind, sbom []byte, osInfo model.OSInfo) ([]model.Finding, error) {
	ref := g.acquire()
	if ref == nil {
		return nil, ErrNoDB
	}
	defer g.release(ref)
	provider := ref.p
	cfg := pkg.ProviderConfig{}
	if kind == model.TargetHost && osInfo.ID != "" {
		cfg.Distro.Override = distro.NewFromNameVersion(osInfo.ID, osInfo.VersionID)
	}
	pkgs, pctx, _, err := pkg.ProvideFromReader(bytes.NewReader(sbom), cfg)
	if err != nil {
		return nil, fmt.Errorf("decode sbom: %w", err)
	}
	if err := checkPackageCap(len(pkgs)); err != nil {
		return nil, err
	}
	vm := &grype.VulnerabilityMatcher{
		VulnerabilityProvider: provider,
		Matchers:              matcher.NewDefaultMatchers(matcherConfig()),
		NormalizeByCVE:        true,
	}
	matches, _, err := vm.FindMatchesContext(ctx, pkgs, pctx)
	if err != nil {
		return nil, fmt.Errorf("grype match: %w", err)
	}
	if matches == nil {
		return nil, nil
	}
	var out []model.Finding
	nvd := map[string]*vulnerability.Metadata{}
	for _, m := range matches.Sorted() {
		var md *vulnerability.Metadata
		md, err = provider.VulnerabilityMetadata(vulnerability.Reference{ID: m.Vulnerability.ID, Namespace: m.Vulnerability.Namespace})
		if err != nil || md == nil {
			md = m.Vulnerability.Metadata
		}
		f := toFinding(m.Package, m.Vulnerability, md)
		// Distro records often lack CVSS (and downgrade severity); enrich from the NVD record of the CVE.
		if cve := cveOf(m.Vulnerability); cve != "" {
			nm, ok := nvd[cve]
			if !ok {
				nm, _ = provider.VulnerabilityMetadata(vulnerability.Reference{ID: cve, Namespace: "nvd:cpe"})
				nvd[cve] = nm
			}
			mergeMetadata(&f, nm)
		}
		out = append(out, f)
	}
	return dedupe(out), nil
}

func checkPackageCap(n int) error {
	if n > MaxPackages {
		return fmt.Errorf("%w: %d > %d", ErrTooManyPackages, n, MaxPackages)
	}
	return nil
}

// toFinding maps a Grype match to a model.Finding (matcher-derived fields only).
func toFinding(p pkg.Package, v vulnerability.Vulnerability, md *vulnerability.Metadata) model.Finding {
	f := model.Finding{
		PackageName:   p.Name,
		PackageVer:    p.Version,
		PackageType:   string(p.Type),
		PURL:          p.PURL,
		VulnID:        v.ID,
		Aliases:       []string{},
		FixedVersions: append([]string{}, v.Fix.Versions...),
		FixState:      string(v.Fix.State),
		Severity:      "Unknown",
	}
	if f.FixState == "" {
		f.FixState = string(vulnerability.FixStateUnknown)
	}
	seen := map[string]bool{v.ID: true}
	for _, r := range v.RelatedVulnerabilities {
		if r.ID != "" && !seen[r.ID] {
			seen[r.ID] = true
			f.Aliases = append(f.Aliases, r.ID)
		}
	}
	if md != nil {
		f.Severity = normSeverity(md.Severity)
		for _, c := range md.Cvss {
			if c.Metrics.BaseScore > f.CVSS {
				f.CVSS = c.Metrics.BaseScore
			}
		}
		f.KEV = len(md.KnownExploited) > 0
		for _, e := range md.EPSS {
			if e.EPSS > f.EPSS {
				f.EPSS = e.EPSS
			}
		}
	}
	return f
}

func cveOf(v vulnerability.Vulnerability) string {
	if strings.HasPrefix(v.ID, "CVE-") {
		return v.ID
	}
	for _, r := range v.RelatedVulnerabilities {
		if strings.HasPrefix(r.ID, "CVE-") {
			return r.ID
		}
	}
	return ""
}

var severityRank = map[string]int{"Unknown": 0, "Negligible": 1, "Low": 2, "Medium": 3, "High": 4, "Critical": 5}

// mergeMetadata folds a second record of the same CVE into f, keeping the worse severity,
// the highest CVSS base score, and any KEV/EPSS data. Erring upwards is deliberate: a distro
// downgrade must not hide a risk from the rule engine.
func mergeMetadata(f *model.Finding, md *vulnerability.Metadata) {
	if md == nil {
		return
	}
	if sev := normSeverity(md.Severity); severityRank[sev] > severityRank[f.Severity] {
		f.Severity = sev
	}
	for _, c := range md.Cvss {
		f.CVSS = max(f.CVSS, c.Metrics.BaseScore)
	}
	f.KEV = f.KEV || len(md.KnownExploited) > 0
	for _, e := range md.EPSS {
		f.EPSS = max(f.EPSS, e.EPSS)
	}
}

func normSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	case "negligible":
		return "Negligible"
	default:
		return "Unknown"
	}
}

// dedupe collapses findings with the same (package, version, vuln id), merging aliases and fixes.
func dedupe(in []model.Finding) []model.Finding {
	idx := map[string]int{}
	var out []model.Finding
	for _, f := range in {
		k := f.PackageName + "\x00" + f.PackageVer + "\x00" + f.VulnID
		i, ok := idx[k]
		if !ok {
			idx[k] = len(out)
			out = append(out, f)
			continue
		}
		o := &out[i]
		o.Aliases = unionStrings(o.Aliases, f.Aliases)
		o.FixedVersions = unionStrings(o.FixedVersions, f.FixedVersions)
		o.KEV = o.KEV || f.KEV
		o.CVSS = max(o.CVSS, f.CVSS)
		o.EPSS = max(o.EPSS, f.EPSS)
	}
	return out
}

func unionStrings(a, b []string) []string {
	have := map[string]bool{}
	for _, s := range a {
		have[s] = true
	}
	for _, s := range b {
		if !have[s] {
			have[s] = true
			a = append(a, s)
		}
	}
	return a
}
