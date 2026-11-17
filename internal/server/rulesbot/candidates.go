package rulesbot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/DonSosiska/panoptes/internal/model"
)

// Defaults of the candidates command.
const (
	DefaultOSVURL    = "https://api.osv.dev"
	DefaultKEVURL    = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	DefaultEPSSURL   = "https://api.first.org/data/v1/epss?cve="
	DefaultMax       = 20
	DefaultMaxReqs   = 2000
	DefaultSince     = 30 * 24 * time.Hour
	MaxBodyBytes     = 8 << 20
	RequestTimeout   = 30 * time.Second
	UserAgent        = "panoptes-rules-bot"
	epssBatch        = 100
	maxQueryPages    = 50
	maxBinaryPackets = 50
)

// DefaultEcosystems are the OSV ecosystem names queried by default.
var DefaultEcosystems = []string{"Debian:12", "Ubuntu:24.04:LTS", "Alpine:v3.20"}

// ErrRequestCap is returned (and logged) when the per-run HTTP request budget is used up.
var ErrRequestCap = errors.New("http request limit reached")

// Candidate is a CVE worth a rule that the repository does not cover yet.
type Candidate struct {
	Vuln           string   `json:"vuln"`
	Aliases        []string `json:"aliases"`
	Package        string   `json:"package"`
	BinaryPackages []string `json:"binary_packages"`
	Type           string   `json:"type"`
	Ecosystem      string   `json:"ecosystem"`
	Severity       string   `json:"severity"`
	CVSS           float64  `json:"cvss"`
	EPSS           float64  `json:"epss"`
	KEV            bool     `json:"kev"`
	Published      string   `json:"published"`
}

// CandidateOptions configure FindCandidates.
type CandidateOptions struct {
	OSVURL      string // default DefaultOSVURL
	KEV         string // URL or file path of the CISA KEV JSON; default DefaultKEVURL
	EPSSURL     string // URL prefix; the comma-separated CVE list is appended; default DefaultEPSSURL
	Ecosystems  []string
	Packages    []string
	Rules       []model.Rule // existing rules, for the covered check
	Since       time.Duration
	Max         int
	MaxRequests int
	Client      *http.Client
	Now         func() time.Time
	Logger      *slog.Logger
}

// EcosystemType returns the package type ("deb", "apk", "rpm") of an OSV ecosystem name.
func EcosystemType(eco string) (string, error) {
	base, _, _ := strings.Cut(eco, ":")
	switch base {
	case "Debian", "Ubuntu":
		return "deb", nil
	case "Alpine":
		return "apk", nil
	case "Red Hat":
		return "rpm", nil
	}
	return "", fmt.Errorf("unsupported OSV ecosystem %q (supported: Debian, Ubuntu, Alpine, Red Hat)", eco)
}

// ParsePackages reads a package list: one name per line, "#" starts a comment.
func ParsePackages(data []byte) []string {
	var out []string
	seen := map[string]bool{}
	for _, l := range strings.Split(string(data), "\n") {
		if i := strings.IndexByte(l, '#'); i >= 0 {
			l = l[:i]
		}
		l = strings.TrimSpace(l)
		if l != "" && !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	return out
}

// ParseSince parses "30d", "12h" or any time.ParseDuration value.
func ParseSince(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil || n < 0 {
			return 0, fmt.Errorf("bad duration %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("bad duration %q", s)
	}
	return d, nil
}

type fetcher struct {
	c     *http.Client
	max   int
	count int
}

func (f *fetcher) do(ctx context.Context, method, u string, body []byte) ([]byte, error) {
	if f.count >= f.max {
		return nil, ErrRequestCap
	}
	f.count++
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := f.c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxBodyBytes {
		return nil, fmt.Errorf("response from %s is larger than %d bytes", redact(u), MaxBodyBytes)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", redact(u), resp.StatusCode)
	}
	return raw, nil
}

func redact(u string) string {
	if i := strings.IndexByte(u, '?'); i >= 0 {
		return u[:i]
	}
	return u
}

type osvDetail struct {
	ID        string   `json:"id"`
	Aliases   []string `json:"aliases"`
	Published string   `json:"published"`
	Withdrawn string   `json:"withdrawn"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific map[string]any `json:"database_specific"`
	Affected         []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		EcosystemSpecific map[string]any `json:"ecosystem_specific"`
	} `json:"affected"`
}

var (
	cveRe    = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)
	cveOnlyR = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
)

// FindCandidates queries OSV, KEV and EPSS and returns the ranked candidates (see docs/rules-feed.md).
func FindCandidates(ctx context.Context, o CandidateOptions) ([]Candidate, error) {
	if o.OSVURL == "" {
		o.OSVURL = DefaultOSVURL
	}
	if o.KEV == "" {
		o.KEV = DefaultKEVURL
	}
	if o.EPSSURL == "" {
		o.EPSSURL = DefaultEPSSURL
	}
	if len(o.Ecosystems) == 0 {
		o.Ecosystems = DefaultEcosystems
	}
	if o.Since <= 0 {
		o.Since = DefaultSince
	}
	if o.Max <= 0 {
		o.Max = DefaultMax
	}
	if o.MaxRequests <= 0 {
		o.MaxRequests = DefaultMaxReqs
	}
	if o.Client == nil {
		o.Client = &http.Client{Timeout: RequestTimeout}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	log := o.Logger
	if len(o.Packages) == 0 {
		return nil, errors.New("no packages to check")
	}
	types := map[string]string{}
	for _, e := range o.Ecosystems {
		t, err := EcosystemType(e)
		if err != nil {
			return nil, err
		}
		types[e] = t
	}
	f := &fetcher{c: o.Client, max: o.MaxRequests}
	cutoff := o.Now().Add(-o.Since)

	kev, err := loadKEV(ctx, f, o.KEV)
	if err != nil {
		return nil, fmt.Errorf("KEV: %w", err)
	}
	log.Info("KEV loaded", "cves", len(kev))

	details := map[string]*osvDetail{}
	seen := map[string]bool{}
	var out []Candidate
	okQueries, queries := 0, 0
outer:
	for _, pkg := range o.Packages {
		for _, eco := range o.Ecosystems {
			queries++
			ids, err := queryPackage(ctx, f, o.OSVURL, pkg, eco)
			if errors.Is(err, ErrRequestCap) {
				log.Warn("request limit reached, stopping", "limit", o.MaxRequests)
				break outer
			}
			if err != nil {
				log.Warn("OSV query failed, skipping", "package", pkg, "ecosystem", eco, "err", err)
				if len(ids) == 0 {
					continue
				}
			}
			okQueries++
			for _, v := range ids {
				cve := cveRe.FindString(v.id)
				inKEV := cve != "" && kev[cve]
				if !inKEV && !v.modified.After(cutoff) {
					continue
				}
				d, ok := details[v.id]
				if !ok {
					d, err = fetchDetail(ctx, f, o.OSVURL, v.id)
					if errors.Is(err, ErrRequestCap) {
						log.Warn("request limit reached, stopping", "limit", o.MaxRequests)
						break outer
					}
					if err != nil {
						log.Warn("OSV detail failed, skipping", "id", v.id, "err", err)
						continue
					}
					details[v.id] = d
				}
				if d == nil || d.Withdrawn != "" {
					continue
				}
				c, ok := toCandidate(d, pkg, eco, types[eco], kev)
				if !ok {
					continue
				}
				if !c.KEV && c.Severity != "High" && c.Severity != "Critical" {
					continue
				}
				if covered(o.Rules, c) {
					continue
				}
				key := c.Vuln + "|" + c.Package
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, c)
			}
		}
	}
	if queries > 0 && okQueries == 0 {
		return nil, errors.New("every OSV query failed")
	}

	enrichEPSS(ctx, f, o.EPSSURL, out, log)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.KEV != b.KEV {
			return a.KEV
		}
		if a.EPSS != b.EPSS {
			return a.EPSS > b.EPSS
		}
		if a.CVSS != b.CVSS {
			return a.CVSS > b.CVSS
		}
		if a.Vuln != b.Vuln {
			return a.Vuln < b.Vuln
		}
		return a.Package < b.Package
	})
	if len(out) > o.Max {
		out = out[:o.Max]
	}
	if out == nil {
		out = []Candidate{}
	}
	log.Info("candidates selected", "count", len(out), "http_requests", f.count)
	return out, nil
}

type osvRef struct {
	id       string
	modified time.Time
}

func queryPackage(ctx context.Context, f *fetcher, base, pkg, eco string) ([]osvRef, error) {
	var out []osvRef
	token := ""
	for page := 0; page < maxQueryPages; page++ {
		q := map[string]any{"package": map[string]string{"name": pkg, "ecosystem": eco}}
		if token != "" {
			q["page_token"] = token
		}
		body, _ := json.Marshal(map[string]any{"queries": []any{q}})
		raw, err := f.do(ctx, http.MethodPost, strings.TrimRight(base, "/")+"/v1/querybatch", body)
		if err != nil {
			return out, err
		}
		var resp struct {
			Results []struct {
				Vulns []struct {
					ID       string `json:"id"`
					Modified string `json:"modified"`
				} `json:"vulns"`
				NextPageToken string `json:"next_page_token"`
			} `json:"results"`
		}
		if err := json.Unmarshal(raw, &resp); err != nil {
			return out, fmt.Errorf("querybatch: %w", err)
		}
		if len(resp.Results) == 0 {
			return out, nil
		}
		r := resp.Results[0]
		for _, v := range r.Vulns {
			t, _ := time.Parse(time.RFC3339, v.Modified)
			out = append(out, osvRef{id: v.ID, modified: t})
		}
		if r.NextPageToken == "" {
			return out, nil
		}
		token = r.NextPageToken
	}
	return out, nil
}

func fetchDetail(ctx context.Context, f *fetcher, base, id string) (*osvDetail, error) {
	raw, err := f.do(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/v1/vulns/"+url.PathEscape(id), nil)
	if err != nil {
		return nil, err
	}
	var d osvDetail
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

func loadKEV(ctx context.Context, f *fetcher, src string) (map[string]bool, error) {
	var raw []byte
	var err error
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		raw, err = f.do(ctx, http.MethodGet, src, nil)
	} else {
		raw, err = os.ReadFile(strings.TrimPrefix(src, "file://"))
		if err == nil && len(raw) > MaxBodyBytes {
			err = errors.New("file too large")
		}
	}
	if err != nil {
		return nil, err
	}
	var doc struct {
		Vulnerabilities []struct {
			CVEID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(doc.Vulnerabilities))
	for _, v := range doc.Vulnerabilities {
		if cveOnlyR.MatchString(v.CVEID) {
			out[v.CVEID] = true
		}
	}
	return out, nil
}

// toCandidate builds a candidate from an OSV record; ok is false when it has no CVE id or no usable severity (and is not in KEV).
func toCandidate(d *osvDetail, pkg, eco, typ string, kev map[string]bool) (Candidate, bool) {
	ids := append([]string{d.ID}, d.Aliases...)
	cve := ""
	for _, id := range ids {
		if cveOnlyR.MatchString(id) {
			cve = id
			break
		}
	}
	if cve == "" {
		if m := cveRe.FindString(d.ID); m != "" {
			cve = m
		}
	}
	if cve == "" {
		return Candidate{}, false
	}
	c := Candidate{Vuln: cve, Package: pkg, Type: typ, Ecosystem: eco, Published: d.Published, KEV: kev[cve], Aliases: []string{}}
	seen := map[string]bool{cve: true}
	for _, id := range ids {
		if id != "" && !seen[id] {
			seen[id] = true
			c.Aliases = append(c.Aliases, id)
		}
	}
	sort.Strings(c.Aliases)
	c.CVSS, c.Severity = severityOf(d)
	if c.Severity == "" {
		if !c.KEV {
			return Candidate{}, false
		}
		c.Severity = "Unknown"
	}
	bins := map[string]bool{}
	for _, a := range d.Affected {
		if a.Package.Name != pkg || a.Package.Ecosystem != eco {
			continue
		}
		if l, ok := a.EcosystemSpecific["binaries"].([]any); ok {
			for _, e := range l {
				if m, ok := e.(map[string]any); ok {
					if n, ok := m["binary_name"].(string); ok && n != "" && len(n) <= 100 && len(bins) < maxBinaryPackets {
						bins[n] = true
					}
				}
			}
		}
	}
	if len(bins) == 0 {
		bins[pkg] = true
	}
	for b := range bins {
		c.BinaryPackages = append(c.BinaryPackages, b)
	}
	sort.Strings(c.BinaryPackages)
	return c, true
}

// severityOf returns the CVSS v3 base score and rating of a record. CVSS v4 vectors (not computed
// here) and plain ratings fall back to a qualitative rating from the record, score 0.
func severityOf(d *osvDetail) (float64, string) {
	for _, s := range d.Severity {
		if strings.HasPrefix(s.Score, "CVSS:3") {
			if v, err := CVSS3Score(s.Score); err == nil {
				return v, Rating(v)
			}
		}
	}
	words := []string{}
	for _, s := range d.Severity {
		if !strings.HasPrefix(s.Score, "CVSS:") {
			words = append(words, s.Score)
		}
	}
	if v, ok := d.DatabaseSpecific["severity"].(string); ok {
		words = append(words, v)
	}
	for _, w := range words {
		switch strings.ToLower(strings.TrimSpace(w)) {
		case "critical":
			return 0, "Critical"
		case "high", "important":
			return 0, "High"
		case "medium", "moderate":
			return 0, "Medium"
		case "low":
			return 0, "Low"
		}
	}
	return 0, ""
}

// covered reports whether any rule lists the candidate's CVE (or an alias) for a matching package.
func covered(rs []model.Rule, c Candidate) bool {
	ids := append([]string{c.Vuln}, c.Aliases...)
	names := append([]string{c.Package}, c.BinaryPackages...)
	for _, r := range rs {
		listed := false
		for _, id := range ids {
			for _, v := range r.Vulns {
				if v == id {
					listed = true
				}
			}
		}
		if !listed {
			continue
		}
		for _, sel := range r.Packages {
			if sel.Type != "" && sel.Type != c.Type {
				continue
			}
			for _, n := range names {
				if ok, _ := path.Match(sel.Name, n); ok {
					return true
				}
			}
		}
	}
	return false
}

func enrichEPSS(ctx context.Context, f *fetcher, tmpl string, cs []Candidate, log *slog.Logger) {
	uniq := map[string]bool{}
	var cves []string
	for _, c := range cs {
		if !uniq[c.Vuln] {
			uniq[c.Vuln] = true
			cves = append(cves, c.Vuln)
		}
	}
	sort.Strings(cves)
	scores := map[string]float64{}
	for i := 0; i < len(cves); i += epssBatch {
		end := min(i+epssBatch, len(cves))
		raw, err := f.do(ctx, http.MethodGet, tmpl+strings.Join(cves[i:end], ","), nil)
		if err != nil {
			log.Warn("EPSS lookup failed, scores left at 0", "err", err)
			continue
		}
		var resp struct {
			Data []struct {
				CVE  string `json:"cve"`
				EPSS string `json:"epss"`
			} `json:"data"`
		}
		if err := json.Unmarshal(raw, &resp); err != nil {
			log.Warn("EPSS response unreadable, scores left at 0", "err", err)
			continue
		}
		for _, d := range resp.Data {
			if v, err := strconv.ParseFloat(d.EPSS, 64); err == nil {
				scores[d.CVE] = v
			}
		}
	}
	for i := range cs {
		cs[i].EPSS = scores[cs[i].Vuln]
	}
}
