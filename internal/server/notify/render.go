package notify

import (
	"fmt"
	"html"
	"net/url"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"panoptes/internal/model"
)

// lineSet collects a message as parallel plain-text and HTML lines.
// Callers must escape every untrusted value in the html argument themselves.
type lineSet struct {
	plain, html []string
}

func (l *lineSet) add(plain, h string) {
	l.plain = append(l.plain, plain)
	l.html = append(l.html, h)
}

const (
	maxFieldRunes = 300     // every untrusted field is cut to this many runes
	maxBodyBytes  = 8 << 10 // plain and formatted bodies are each capped at this size
	maxListItems  = 10      // distinct items per joined line
	truncatedNote = "…(truncated)"
)

// cl neutralises an untrusted plain-text value: control characters and bidi overrides are
// dropped (newlines and tabs become spaces) and the result is cut to maxFieldRunes runes.
func cl(s string) string {
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
	f.FixedVersions = clAll(f.FixedVersions)
	ev.Host.Hostname = cl(ev.Host.Hostname)
	ev.FixCmd = cl(ev.FixCmd)
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

// draftSafeReason removes the LLM-written explanation that the evaluator appends to the reason
// of ungrounded drafts ("LLM draft (...): likely exploitable — <explanation>").
func draftSafeReason(r string) string {
	if strings.HasPrefix(r, "LLM draft") {
		if i := strings.Index(r, " — "); i >= 0 {
			return r[:i]
		}
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

// render joins the lines; whole lines are dropped (never cut mid-tag) once either body would
// exceed maxBodyBytes, and a truncation note is appended.
func (l *lineSet) render() (string, string) {
	pl, hl := 0, 0
	keep := 0
	for i := range l.plain {
		p, h := len(l.plain[i])+1, len(l.html[i])+len("<br>")
		if pl+p > maxBodyBytes-64 || hl+h > maxBodyBytes-64 {
			break
		}
		pl, hl = pl+p, hl+h
		keep = i + 1
	}
	plain, formatted := l.plain[:keep], l.html[:keep]
	if keep < len(l.plain) {
		if keep == 0 { // a single huge line: fall back to escaped truncated plain text
			t := cutBytes(l.plain[0], maxBodyBytes/4)
			plain, formatted = []string{t}, []string{esc(t)}
		}
		plain = append(slices.Clone(plain), truncatedNote)
		formatted = append(slices.Clone(formatted), truncatedNote)
	}
	return strings.Join(plain, "\n"), strings.Join(formatted, "<br>")
}

// esc HTML-escapes a value that comes from a host, finding or rule.
func esc(s string) string { return html.EscapeString(s) }

// renderEvent renders a single event; it is renderGroup of one.
func renderEvent(ev model.Event) (plain, formatted string) {
	return renderGroup([]model.Event{ev})
}

// distinct returns the non-empty values of vals in first-seen order without duplicates.
func distinct(vals []string) []string {
	var out []string
	for _, v := range vals {
		if v != "" && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

// renderGroup returns the plain-text body and the HTML formatted_body for a group of events
// that share kind, host, vulnerability and target. Values are merged as described in the
// package documentation: packages listed, severity maxima, deduplicated reasons and fixes.
func renderGroup(raw []model.Event) (string, string) {
	evs := make([]model.Event, len(raw))
	for i, ev := range raw {
		evs[i] = sanitize(ev)
	}
	g := group{evs: evs}
	first := g.first()
	f := first.Finding
	host := first.Host.Hostname
	var l lineSet

	if first.Kind == model.EventResolved {
		var plain, h []string
		for _, ev := range evs {
			p := ev.Finding.PackageName + " " + ev.Finding.PackageVer + ": now " + string(ev.Finding.Verdict)
			plain = append(plain, p)
			h = append(h, esc(ev.Finding.PackageName)+" "+esc(ev.Finding.PackageVer)+": now "+esc(string(ev.Finding.Verdict)))
		}
		l.add("✅ RESOLVED: "+f.VulnID+" on "+host,
			"✅ <b>RESOLVED: "+esc(f.VulnID)+" on "+esc(host)+"</b>")
		l.add(strings.Join(distinct(plain), "; "), strings.Join(distinct(h), "; "))
		return l.render()
	}

	switch first.Kind {
	case model.EventUnknownCritical:
		l.add("🟠 CHECK: "+f.VulnID+" on "+host,
			"🟠 <b>CHECK: "+esc(f.VulnID)+" on "+esc(host)+"</b>")
	case model.EventExploitable:
		l.add("🔴 EXPLOITABLE: "+f.VulnID+" on "+host,
			"🔴 <b>EXPLOITABLE: "+esc(f.VulnID)+" on "+esc(host)+"</b>")
	default:
		l.add("ℹ️ "+string(first.Kind)+": "+f.VulnID+" on "+host,
			"ℹ️ <b>"+esc(string(first.Kind))+": "+esc(f.VulnID)+" on "+esc(host)+"</b>")
	}

	// Packages with their fix availability, deduplicated.
	var pkgPlain, pkgHTML []string
	for _, ev := range evs {
		name := ev.Finding.PackageName + " " + ev.Finding.PackageVer
		if len(ev.Finding.FixedVersions) > 0 {
			fixed := strings.Join(ev.Finding.FixedVersions, ", ")
			pkgPlain = append(pkgPlain, name+" → fixed in "+fixed)
			pkgHTML = append(pkgHTML, esc(name)+" → fixed in "+esc(fixed))
		} else {
			pkgPlain = append(pkgPlain, name+" → no fix yet")
			pkgHTML = append(pkgHTML, esc(name)+" → no fix yet")
		}
	}
	pkgPlain, pkgHTML = distinct(pkgPlain), distinct(pkgHTML)
	if len(pkgPlain) == 1 {
		l.add("Package: "+pkgPlain[0], "Package: "+pkgHTML[0])
	} else {
		l.add("Packages: "+capJoin(pkgPlain, "; "), "Packages: "+capJoin(pkgHTML, "; "))
	}

	// Target.
	if f.TargetKind == model.TargetContainerImage {
		l.add("Target: image "+f.Target, "Target: image "+esc(f.Target))
	} else {
		l.add("Target: host", "Target: host")
	}

	// Severity, CVSS, EPSS, KEV: maxima over the group.
	var sevP, sevH []string
	if sev := g.maxSeverity(); sev != "" {
		sevP = append(sevP, "Severity "+sev)
		sevH = append(sevH, "Severity "+esc(sev))
	}
	if cvss := g.maxCVSS(); cvss > 0 {
		s := fmt.Sprintf("CVSS %.1f", cvss)
		sevP, sevH = append(sevP, s), append(sevH, s)
	}
	if epss := g.maxEPSS(); epss > 0 {
		s := fmt.Sprintf("EPSS %.1f%%", epss*100)
		sevP, sevH = append(sevP, s), append(sevH, s)
	}
	if g.anyKEV() {
		sevP = append(sevP, "🚨 KEV")
		sevH = append(sevH, "🚨 <b>KEV</b>")
	}
	if len(sevP) > 0 {
		l.add(strings.Join(sevP, " · "), strings.Join(sevH, " · "))
	}

	// Why it matters, one line per distinct reason.
	var reasons []string
	for _, ev := range evs {
		r := ev.Finding.VerdictReason
		if isDraft(ev) {
			r = draftSafeReason(r)
		}
		reasons = append(reasons, r)
	}
	label := "Why: "
	if first.Kind == model.EventUnknownCritical {
		label = "Conditions not verified: "
	}
	for _, r := range distinct(reasons)[:min(len(distinct(reasons)), maxListItems)] {
		l.add(label+r, label+esc(r))
	}

	// Rules, one line per distinct rule.
	var rules []string
	for _, ev := range evs {
		if ev.Rule == nil || isDraft(ev) { // never relay LLM-drafted rule text
			continue
		}
		text := ev.Rule.Title
		if ev.Rule.Explanation != "" {
			text += " — " + ev.Rule.Explanation
		}
		rules = append(rules, text)
	}
	for _, r := range distinct(rules) {
		l.add("Rule: "+r, "Rule: "+esc(r))
	}
	for _, ev := range evs {
		if isDraft(ev) {
			const w = "⚠️ unreviewed LLM draft — review the rule in the web UI before acting"
			l.add(w, "⚠️ <b>"+esc(w[len("⚠️ "):])+"</b>")
			break
		}
	}

	// Fix commands (distinct), falling back to rule upgrade advice.
	var cmds []string
	for _, ev := range evs {
		cmds = append(cmds, ev.FixCmd)
	}
	if cmds = distinct(cmds); len(cmds) > 0 {
		for _, c := range cmds {
			l.add("Fix: "+c, "Fix: <code>"+esc(c)+"</code>")
		}
	} else {
		var upgrades []string
		for _, ev := range evs {
			if ev.Rule != nil && !isDraft(ev) {
				upgrades = append(upgrades, ev.Rule.Fix.Upgrade)
			}
		}
		for _, u := range distinct(upgrades) {
			l.add("Fix: "+u, "Fix: "+esc(u))
		}
	}

	// Mitigations, deduplicated.
	var mitigations []string
	for _, ev := range evs {
		if ev.Rule != nil && !isDraft(ev) { // reviewed rules only; always plain text, never <code>
			mitigations = append(mitigations, ev.Rule.Fix.Mitigation)
		}
	}
	for _, m := range distinct(mitigations) {
		l.add("Mitigation: "+m, "Mitigation: "+esc(m))
	}

	// Link to the first event's finding.
	if first.WebURL != "" && isHTTP(first.WebURL) {
		l.add("Details: "+first.WebURL, `Details: <a href="`+esc(first.WebURL)+`">`+esc(first.WebURL)+`</a>`)
	}
	return l.render()
}

// renderSummary builds the burst summary for the groups that were not sent individually.
// findingsLink may be empty.
func renderSummary(rest []group, findingsLink string) message {
	var l lineSet
	header := fmt.Sprintf("…and %d more findings", len(rest))
	l.add(header, esc(header))
	for i, g := range rest {
		if i == summaryMaxLines {
			more := fmt.Sprintf("…and %d more not listed", len(rest)-summaryMaxLines)
			l.add(more, esc(more))
			break
		}
		item := cl(g.first().Finding.VulnID) + "@" + cl(g.first().Host.Hostname)
		l.add("• "+item, "• "+esc(item))
	}
	if findingsLink != "" {
		l.add("All findings: "+findingsLink, `All findings: <a href="`+esc(findingsLink)+`">`+esc(findingsLink)+`</a>`)
	}
	plain, h := l.render()
	return message{MsgType: "m.text", Body: plain, Format: "org.matrix.custom.html", FormattedBody: h}
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
