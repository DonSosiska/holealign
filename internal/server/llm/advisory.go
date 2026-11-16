package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const maxAdvisoryChars = 12000

// AdvisorySource fetches advisory text for a vulnerability.
type AdvisorySource interface {
	Get(ctx context.Context, vulnID string, aliases []string) (string, error)
}

// OSVSource queries the OSV database.
type OSVSource struct {
	BaseURL string // default https://api.osv.dev
	Client  *http.Client
}

// NewOSVSource returns the default advisory source.
func NewOSVSource() *OSVSource {
	return &OSVSource{BaseURL: "https://api.osv.dev", Client: &http.Client{Timeout: 20 * time.Second}}
}

type osvVuln struct {
	ID        string   `json:"id"`
	Aliases   []string `json:"aliases"`
	Summary   string   `json:"summary"`
	Details   string   `json:"details"`
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
		Ranges            []struct {
			Type   string              `json:"type"`
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
}

// Get tries the vuln ID, then each alias, and renders the first hit.
func (o *OSVSource) Get(ctx context.Context, vulnID string, aliases []string) (string, error) {
	base := o.BaseURL
	if base == "" {
		base = "https://api.osv.dev"
	}
	hc := o.Client
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second}
	}
	var lastErr error = errors.New("no advisory found")
	for _, id := range append([]string{vulnID}, aliases...) {
		if id == "" {
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/v1/vulns/"+url.PathEscape(id), nil)
		if err != nil {
			lastErr = err
			continue
		}
		resp, err := hc.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		raw, rerr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if rerr != nil || resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("osv %s: status %d", id, resp.StatusCode)
			continue
		}
		var v osvVuln
		if err := json.Unmarshal(raw, &v); err != nil {
			lastErr = err
			continue
		}
		return renderOSV(v), nil
	}
	return "", lastErr
}

func renderOSV(v osvVuln) string {
	var b strings.Builder
	fmt.Fprintf(&b, "ID: %s\n", v.ID)
	if len(v.Aliases) > 0 {
		fmt.Fprintf(&b, "Aliases: %s\n", strings.Join(v.Aliases, ", "))
	}
	if v.Summary != "" {
		fmt.Fprintf(&b, "Summary: %s\n", v.Summary)
	}
	if v.Withdrawn != "" {
		fmt.Fprintf(&b, "WITHDRAWN: this advisory was withdrawn on %s\n", v.Withdrawn)
	}
	for _, sv := range v.Severity {
		if sv.Score != "" {
			fmt.Fprintf(&b, "Severity (%s): %s\n", sv.Type, sv.Score)
		}
	}
	if t := specificText("Database-specific", v.DatabaseSpecific); t != "" {
		b.WriteString(t)
	}
	if v.Details != "" {
		fmt.Fprintf(&b, "\nDetails:\n%s\n", v.Details)
	}
	if len(v.Affected) > 0 {
		b.WriteString("\nAffected:\n")
		for _, a := range v.Affected {
			fmt.Fprintf(&b, "- %s (%s)\n", a.Package.Name, a.Package.Ecosystem)
			if t := specificText("    Ecosystem-specific", a.EcosystemSpecific); t != "" {
				b.WriteString(t)
			}
			for _, r := range a.Ranges {
				var parts []string
				for _, e := range r.Events {
					for k, val := range e {
						parts = append(parts, k+"="+val)
					}
				}
				fmt.Fprintf(&b, "    %s: %s\n", r.Type, strings.Join(parts, " "))
			}
		}
	}
	if len(v.References) > 0 {
		b.WriteString("\nReferences:\n")
		for _, r := range v.References {
			fmt.Fprintf(&b, "- %s\n", r.URL)
		}
	}
	return truncate(b.String(), maxAdvisoryChars)
}

// specificText renders the short scalar values of an OSV database_specific /
// ecosystem_specific object (for example Debian's urgency "unimportant" or a
// "disputed" flag) as "<label> <key>: <value>" lines, in key order.
func specificText(label string, m map[string]any) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		switch v := m[k].(type) {
		case string:
			if v != "" && len(v) <= 300 {
				fmt.Fprintf(&b, "%s %s: %s\n", label, k, v)
			}
		case bool, float64:
			fmt.Fprintf(&b, "%s %s: %v\n", label, k, v)
		}
	}
	return b.String()
}
