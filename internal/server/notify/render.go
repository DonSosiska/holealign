package notify

import (
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/DonSosiska/holealign/internal/model"
)

// lineSet collects the lines of a Message.
type lineSet struct {
	lines []Line
}

func (l *lineSet) add(spans ...Span) { l.lines = append(l.lines, Line(spans)) }

const (
	maxFieldRunes = 300     // every untrusted field is cut to this many runes
	maxBodyBytes  = 8 << 10 // plain and formatted bodies are each capped at this size
	maxListItems  = 10      // distinct items per joined line

	maxGroupEvents   = 50 // events rendered per group; the rest is summarised as a count
	maxFixedVersions = 5  // fixed versions listed per package
	maxDetailLines   = 60 // lines of a health event's detail (aggregated silence lists 50 hosts)
	truncatedNote    = "…(truncated)"
)

// cl neutralises an untrusted plain-text value: control characters and bidi overrides are
// dropped (newlines and tabs become spaces) and the result is cut to maxFieldRunes runes.
func cl(s string) string {
	return strings.ReplaceAll(clBase(s), "@", "@\u200b")
}

// zwsp after the "@" of every "@room" (any case) in text that must keep its other "@" characters.
var atRoom = regexp.MustCompile(`(?i)@room`)

func neutralRoom(s string) string {
	return atRoom.ReplaceAllStringFunc(s, func(m string) string { return "@\u200b" + m[1:] })
}

// clBase is cl without the mention neutralisation (for values such as shell commands that must
// stay copy-pasteable; the caller applies neutralRoom).
func clBase(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		switch {
		case r == '\r':
			continue
		case r == '\n' || r == '\t':
			r = ' '
		case unicode.IsControl(r), r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069, r == 0x2028, r == 0x2029:
			continue
		}
		if n++; n > maxFieldRunes {
			b.WriteString("…")
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

func clAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = cl(s)
	}
	return out
}

// sanitize returns a copy of ev with every untrusted field cleaned (see cl).
func sanitize(ev model.Event) model.Event {
	f := &ev.Finding
	f.VulnID, f.Target, f.PackageName, f.PackageVer = cl(f.VulnID), cl(f.Target), cl(f.PackageName), cl(f.PackageVer)
	f.PURL, f.VerdictReason, f.Severity = cl(f.PURL), cl(f.VerdictReason), cl(f.Severity)
	f.FixedVersions = clAll(f.FixedVersions[:min(len(f.FixedVersions), maxFixedVersions)])
	ev.Host.Hostname = cl(ev.Host.Hostname)
	if ev.Detail != "" { // multi-line: clean each line, keep the line structure
		lines := strings.Split(ev.Detail, "\n")
		for i, l := range lines {
			lines[i] = cl(l)
		}
		if len(lines) > maxDetailLines {
			lines = append(lines[:maxDetailLines], "…")
		}
		ev.Detail = strings.Join(lines, "\n")
	}
	ev.FixCmd = neutralRoom(clBase(ev.FixCmd))
	if ev.Rule != nil {
		r := *ev.Rule
		r.Title, r.Explanation = cl(r.Title), cl(r.Explanation)
		r.Fix.Upgrade, r.Fix.Mitigation = cl(r.Fix.Upgrade), cl(r.Fix.Mitigation)
		ev.Rule = &r
	}
	return ev
}

func isDraft(ev model.Event) bool {
	return ev.Finding.RuleStatus == model.RuleDraft || (ev.Rule != nil && ev.Rule.Status == model.RuleDraft)
}

// draftSafeReason replaces the reason of an unreviewed LLM draft by a fixed string. Draft rules
// are attacker-influenceable text (the model reads vulnerability descriptions), so nothing the
// evaluator or an older server version appended to the reason is relayed to the chat room.
func draftSafeReason(r string) string {
	if strings.HasPrefix(r, "LLM draft suggests not exploitable") {
		return "LLM draft suggests not exploitable (unreviewed); conditions not verified"
	}
	if strings.HasPrefix(r, "LLM draft") {
		return "LLM draft (unreviewed); conditions not verified"
	}
	return r
}

// capJoin joins at most maxListItems items.
func capJoin(items []string, sep string) string {
	if len(items) > maxListItems {
		return strings.Join(items[:maxListItems], sep) + fmt.Sprintf("%s…and %d more", sep, len(items)-maxListItems)
	}
	return strings.Join(items, sep)
}

func cutBytes(s string, max int) string {
	if len(s) <= max {
		return s
	}
	s = s[:max]
	for !utf8.ValidString(s) && len(s) > 0 {
		s = s[:len(s)-1]
	}
	return s
}

// esc HTML-escapes a value that comes from a host, finding or rule.
func esc(s string) string { return html.EscapeString(s) }

// distinct returns the non-empty values of vals in first-seen order without duplicates.
func distinct(vals []string) []string {
	seen := make(map[string]struct{}, len(vals))
	var out []string
	for _, v := range vals {
		if v == "" {
			continue
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// findingsURL derives "<public base>/findings" from an event's WebURL, where the base is
// everything before a "/findings" path segment (or the origin when there is none).
// Returns "" when WebURL is not an absolute http(s) URL.
func findingsURL(webURL string) string {
	if webURL == "" || !isHTTP(webURL) {
		return ""
	}
	u, err := url.Parse(webURL)
	if err != nil {
		return ""
	}
	base := u.Path
	if i := strings.Index(base, "/findings"); i >= 0 {
		base = base[:i]
	}
	u.Path = strings.TrimSuffix(base, "/")
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return u.String() + "/findings"
}

func isHTTP(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}
