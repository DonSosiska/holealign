package llm

import (
	"strings"
	"testing"
)

func TestRenderOSVHints(t *testing.T) {
	v := osvVuln{ID: "CVE-1", Withdrawn: "2024-01-01T00:00:00Z"}
	v.Severity = append(v.Severity, struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	}{"CVSS_V3", "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"})
	v.DatabaseSpecific = map[string]any{"urgency": "unimportant", "disputed": true}
	out := renderOSV(v)
	for _, s := range []string{"WITHDRAWN", "Severity (CVSS_V3): CVSS:3.1/AV:L", "Database-specific urgency: unimportant", "Database-specific disputed: true"} {
		if !strings.Contains(out, s) {
			t.Errorf("missing %q in %s", s, out)
		}
	}
}
