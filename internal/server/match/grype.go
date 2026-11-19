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
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype"
	v6 "github.com/anchore/grype/grype/db/v6"
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
	_ "github.com/glebarez/go-sqlite"

	"github.com/DonSosiska/holealign/internal/model"
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
	Built           time.Time
	SchemaVersion   string
	Path            string
	Vulnerabilities int64
}

// Options configure a Grype matcher.
type Options struct {
	DBRoot    string
	LatestURL string // optional custom Grype DB distribution URL (e.g. internal mirror)
	CACert    string // optional PEM CA bundle path for LatestURL
	Log       *slog.Logger
}

// Grype implements pipeline.Matcher with the Grype library. It is safe for concurrent use;
// Reload swaps the underlying DB atomically.
type Grype struct {
	dbRoot        string
	latestURL     string
	caCert        string
	log           *slog.Logger
	newDistClient func(v6dist.Config) (v6dist.Client, error) // nil = v6dist.NewClient (overridden in tests)

	reloadMu sync.Mutex // serializes disk updates/swaps without blocking Match

	mu     sync.Mutex
	cur    *provRef
	status DBStatus
}

// provRef is a reference-counted provider: Reload retires the old one, which is closed once the
// last in-flight Match using it finished (Match does not hold g.mu while matching).
type provRef struct {
	p         vulnerability.Provider
	genDir    string // optional gen-* directory owned by this provider, removed after Close
	refs      int
	retired   bool
	removeDir bool // true when retired by a newer generation (false on Close/shutdown)
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
	removeDir := closeNow && r.removeDir && r.genDir != ""
	genDir := r.genDir
	g.mu.Unlock()
	if closeNow {
		_ = r.p.Close()
		if removeDir {
			_ = os.RemoveAll(genDir)
		}
	}
}

// retireLocked marks r retired and reports whether it can be closed right away.
func retireLocked(r *provRef, removeDir bool) bool {
	if r == nil {
		return false
	}
	r.retired = true
	if removeDir {
		r.removeDir = true
	}
	return r.refs == 0
}

// dbMaxAge is the age after which a loaded DB triggers a warning.
const dbMaxAge = 5 * 24 * time.Hour

// minAnomalyBaseline is the minimum previous vulnerability count above which a >50% drop in a
// newly downloaded DB is refused as a likely corrupted or poisoned upstream database.
const minAnomalyBaseline int64 = 1000

// NewGrype creates a matcher whose DB lives under dbRoot (e.g. data_dir/grype-db).
// Call Reload before Match.
func NewGrype(dbRoot string, log *slog.Logger) *Grype {
	return NewGrypeWithOptions(Options{DBRoot: dbRoot, Log: log})
}

// NewGrypeWithOptions creates a matcher with optional custom distribution URL and CA bundle.
func NewGrypeWithOptions(opts Options) *Grype {
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	return &Grype{
		dbRoot:    opts.DBRoot,
		latestURL: opts.LatestURL,
		caCert:    opts.CACert,
		log:       opts.Log,
	}
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

// Reload loads the DB from disk. With update=true it checks for a newer DB, downloads it into a
// fresh staging directory, validates its checksum and vulnerability record count (refusing an
// empty DB or a >50% catastrophic drop compared to the active DB), promotes it to a unique
// generation directory (avoiding SQLite cache=shared collisions with the still-open previous DB),
// and only then swaps it into memory. Failures leave both the active in-memory provider and the
// on-disk DB untouched.
func (g *Grype) Reload(ctx context.Context, update bool) (changed bool, err error) {
	type result struct {
		p         vulnerability.Provider
		st        *vulnerability.ProviderStatus
		genDir    string
		vulnCount int64
		noChange  bool
		err       error
	}
	ch := make(chan result, 1)
	go func() {
		g.reloadMu.Lock()
		defer g.reloadMu.Unlock()
		p, st, genDir, count, noChange, err := g.loadOrStage(ctx, update)
		ch <- result{p: p, st: st, genDir: genDir, vulnCount: count, noChange: noChange, err: err}
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
	if r.noChange {
		return false, nil
	}
	st := DBStatus{
		Path:            r.st.Path,
		SchemaVersion:   r.st.SchemaVersion,
		Built:           r.st.Built,
		Vulnerabilities: r.vulnCount,
	}

	g.mu.Lock()
	old := g.cur
	changed = old == nil || !g.status.Built.Equal(st.Built)
	removeOldDir := old != nil && old.genDir != "" && old.genDir != r.genDir
	g.cur, g.status = &provRef{p: r.p, genDir: r.genDir}, st
	closeOld := retireLocked(old, removeOldDir)
	g.mu.Unlock()
	if closeOld {
		_ = old.p.Close()
		if removeOldDir {
			_ = os.RemoveAll(old.genDir)
		}
	}
	if !st.Built.IsZero() && time.Since(st.Built) > dbMaxAge {
		g.log.Warn("grype db is stale; vulnerability data may be outdated", "built", st.Built,
			"age_days", int(time.Since(st.Built).Hours()/24))
	}
	g.log.Info("grype db loaded", "built", st.Built, "schema", st.SchemaVersion,
		"vulnerabilities", st.Vulnerabilities, "changed", changed)
	return changed, nil
}

func (g *Grype) dbConfigs(root string) (v6dist.Config, v6inst.Config) {
	id := clio.Identification{Name: "holealign", Version: "dev"}
	dist := v6dist.DefaultConfig()
	dist.ID = id
	dist.RequireUpdateCheck = false
	if g.latestURL != "" {
		dist.LatestURL = g.latestURL
	}
	if g.caCert != "" {
		dist.CACert = g.caCert
	}
	inst := v6inst.DefaultConfig(id)
	inst.DBRootDir = root
	inst.ValidateAge = false // an old DB beats no DB; the feeds timestamps tell the operator
	inst.ValidateChecksum = true
	return dist, inst
}

func (g *Grype) distClient(dist v6dist.Config) (v6dist.Client, error) {
	if g.newDistClient != nil {
		return g.newDistClient(dist)
	}
	return v6dist.NewClient(dist)
}

func loadDBWithClient(client v6dist.Client, distCfg v6dist.Config, installCfg v6inst.Config, update bool) (vulnerability.Provider, *vulnerability.ProviderStatus, error) {
	c, err := v6inst.NewCurator(installCfg, client)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create curator: %w", err)
	}
	if update {
		if _, err := c.Update(); err != nil && distCfg.RequireUpdateCheck {
			return nil, nil, fmt.Errorf("unable to update db: %w", err)
		}
	}
	s := c.Status()
	if s.Error != nil {
		return nil, nil, s.Error
	}
	rdr, err := c.Reader()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create db reader: %w", err)
	}
	return v6.NewVulnerabilityProvider(rdr), &s, nil
}

// activeRoot returns the currently active DB root (a gen-* subdir recorded in <dbRoot>/active,
// or g.dbRoot itself for legacy layouts) along with the genDir path when a generation dir is used.
func (g *Grype) activeRoot() (root, genDir, genName string) {
	raw, err := os.ReadFile(filepath.Join(g.dbRoot, activeGenFile))
	if err == nil {
		name := strings.TrimSpace(string(raw))
		if validGenName(name) {
			candidate := filepath.Join(g.dbRoot, name)
			if st, serr := os.Stat(candidate); serr == nil && st.IsDir() {
				return candidate, candidate, name
			}
		}
	}
	return g.dbRoot, "", ""
}

const activeGenFile = "active"

func validGenName(name string) bool {
	return strings.HasPrefix(name, "gen-") &&
		!strings.ContainsAny(name, "/\\") &&
		filepath.Base(name) == name
}

func writeActiveGen(dbRoot, genName string) error {
	tmp, err := os.CreateTemp(dbRoot, ".active-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, werr := tmp.WriteString(genName + "\n")
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Chmod(name, 0o640)
	}
	if werr == nil {
		werr = os.Rename(name, filepath.Join(dbRoot, activeGenFile))
	}
	if werr != nil {
		_ = os.Remove(name)
	}
	return werr
}

// loadOrStage runs under g.reloadMu.
func (g *Grype) loadOrStage(ctx context.Context, update bool) (p vulnerability.Provider, st *vulnerability.ProviderStatus, genDir string, vulnCount int64, noChange bool, err error) {
	curRoot, curGenDir, curGenName := g.activeRoot()
	g.mu.Lock()
	ready := g.cur != nil
	curBuilt := g.status.Built
	prevCount := g.status.Vulnerabilities
	inUseGen := ""
	if g.cur != nil {
		inUseGen = filepath.Base(g.cur.genDir)
	}
	g.mu.Unlock()
	cleanupTempDirs(g.dbRoot, curGenName, inUseGen)

	dist, inst := g.dbConfigs(curRoot)
	client, err := g.distClient(dist)
	if err != nil {
		return nil, nil, "", 0, false, fmt.Errorf("create distribution client: %w", err)
	}

	if !update {
		p, st, err = loadDBWithClient(client, dist, inst, false)
		if err != nil {
			return nil, nil, "", 0, false, err
		}
		n, cerr := countVulnerabilities(st.Path)
		if cerr != nil {
			_ = p.Close()
			return nil, nil, "", 0, false, cerr
		}
		if verr := validateDBCounts(0, n); verr != nil {
			_ = p.Close()
			return nil, nil, "", 0, false, verr
		}
		return p, st, curGenDir, n, false, nil
	}

	current, _ := v6.ReadDescription(inst.DBFilePath())
	if prevCount == 0 && current != nil {
		if c, cerr := countVulnerabilities(inst.DBFilePath()); cerr == nil {
			prevCount = c
		}
	}

	avail, checkErr := client.IsUpdateAvailable(current)
	if checkErr != nil {
		return nil, nil, "", 0, false, fmt.Errorf("check update: %w", checkErr)
	}
	if avail == nil {
		if ready && current != nil && curBuilt.Equal(current.Built.Time) {
			return nil, nil, curGenDir, prevCount, true, nil
		}
		p, st, err = loadDBWithClient(client, dist, inst, false)
		if err != nil {
			return nil, nil, "", 0, false, err
		}
		n, cerr := countVulnerabilities(st.Path)
		if cerr != nil {
			_ = p.Close()
			return nil, nil, "", 0, false, cerr
		}
		if verr := validateDBCounts(0, n); verr != nil {
			_ = p.Close()
			return nil, nil, "", 0, false, verr
		}
		return p, st, curGenDir, n, false, nil
	}

	if err := os.MkdirAll(g.dbRoot, 0o700); err != nil {
		return nil, nil, "", 0, false, fmt.Errorf("create db root: %w", err)
	}
	stagingRoot, err := os.MkdirTemp(g.dbRoot, ".staging-*")
	if err != nil {
		return nil, nil, "", 0, false, fmt.Errorf("create staging dir: %w", err)
	}
	keepStaging := false
	defer func() {
		if !keepStaging {
			_ = os.RemoveAll(stagingRoot)
		}
	}()

	stagingDist, stagingInst := g.dbConfigs(stagingRoot)
	stagingDist.RequireUpdateCheck = true
	stagingInst.UpdateCheckMaxFrequency = 0

	stagingClient, err := g.distClient(stagingDist)
	if err != nil {
		return nil, nil, "", 0, false, fmt.Errorf("create staging distribution client: %w", err)
	}
	sp, sst, err := loadDBWithClient(stagingClient, stagingDist, stagingInst, true)
	if err != nil {
		return nil, nil, "", 0, false, fmt.Errorf("download staged db: %w", err)
	}
	newCount, cerr := countVulnerabilities(sst.Path)
	_ = sp.Close()
	if cerr != nil {
		return nil, nil, "", 0, false, fmt.Errorf("inspect staged db: %w", cerr)
	}
	if verr := validateDBCounts(prevCount, newCount); verr != nil {
		g.log.Warn("grype db update rejected by anomaly guard; keeping previous db",
			"prev_vulns", prevCount, "new_vulns", newCount, "err", verr)
		return nil, nil, "", 0, false, verr
	}
	if ctx.Err() != nil {
		return nil, nil, "", 0, false, ctx.Err()
	}

	// Promote the verified staging root to a unique generation directory so opening the new DB
	// uses a distinct file path (Grype opens SQLite with immutable=1&cache=shared, which would
	// otherwise return stale cached pages from the still-open previous provider).
	newGenName := fmt.Sprintf("gen-%d", time.Now().UnixNano())
	newGenDir := filepath.Join(g.dbRoot, newGenName)
	if err := os.Rename(stagingRoot, newGenDir); err != nil {
		return nil, nil, "", 0, false, fmt.Errorf("promote staged db: %w", err)
	}
	keepStaging = true

	newDist, newInst := g.dbConfigs(newGenDir)
	p, st, err = loadDBWithClient(client, newDist, newInst, false)
	if err != nil {
		_ = os.RemoveAll(newGenDir)
		return nil, nil, "", 0, false, fmt.Errorf("open promoted db: %w", err)
	}
	if err := writeActiveGen(g.dbRoot, newGenName); err != nil {
		_ = p.Close()
		_ = os.RemoveAll(newGenDir)
		return nil, nil, "", 0, false, fmt.Errorf("record active db generation: %w", err)
	}
	return p, st, newGenDir, newCount, false, nil
}

// countVulnerabilities reads the vulnerability_handles row count from a Grype v6 SQLite file
// in read-only mode.
func countVulnerabilities(dbPath string) (int64, error) {
	if dbPath == "" {
		return 0, errors.New("grype db path is empty")
	}
	esc := strings.NewReplacer("?", "%3f", "#", "%23").Replace(dbPath)
	dsn := "file:" + esc + "?mode=ro&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return 0, err
	}
	defer db.Close()
	var n int64
	if err := db.QueryRow(`SELECT COUNT(*) FROM vulnerability_handles`).Scan(&n); err != nil {
		return 0, fmt.Errorf("count vulnerability_handles: %w", err)
	}
	return n, nil
}

// validateDBCounts rejects empty DBs and catastrophic (>50%) drops from an established baseline.
func validateDBCounts(prev, next int64) error {
	if next <= 0 {
		return errors.New("grype db anomaly: database contains 0 vulnerability records")
	}
	if prev >= minAnomalyBaseline && next*2 < prev {
		return fmt.Errorf("grype db anomaly: vulnerability count dropped from %d to %d (>50%% drop); refusing update", prev, next)
	}
	return nil
}

func cleanupTempDirs(root, activeGen, inUseGen string) {
	ents, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, ".staging-") || strings.HasPrefix(name, ".prev-") {
			_ = os.RemoveAll(filepath.Join(root, name))
			continue
		}
		if strings.HasPrefix(name, "gen-") && name != activeGen && name != inUseGen {
			_ = os.RemoveAll(filepath.Join(root, name))
		}
	}
}

// Close releases the DB.
func (g *Grype) Close() error {
	g.mu.Lock()
	old := g.cur
	g.cur = nil
	closeNow := retireLocked(old, false)
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
		//lint:ignore SA1019 grype v0.122 metadata lookup
		md, err = provider.VulnerabilityMetadata(vulnerability.Reference{ID: m.Vulnerability.ID, Namespace: m.Vulnerability.Namespace})
		if err != nil || md == nil {
			md = m.Vulnerability.Metadata
		}
		f := toFinding(m.Package, m.Vulnerability, md)
		// Distro records often lack CVSS (and downgrade severity); enrich from the NVD record of the CVE.
		if cve := cveOf(m.Vulnerability); cve != "" {
			nm, ok := nvd[cve]
			if !ok {
				//lint:ignore SA1019 grype v0.122 metadata lookup
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
