package notify

import (
	"fmt"
	"html"
	"net/url"
	"strings"

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

func (l *lineSet) render() (string, string) {
	return strings.Join(l.plain, "\n"), strings.Join(l.html, "<br>")
}

// esc HTML-escapes a value that comes from a host, finding or rule.
func esc(s string) string { return html.EscapeString(s) }

// renderEvent returns the plain-text body and the HTML formatted_body for an event.
func renderEvent(ev model.Event) (plain, formatted string) {
	f := ev.Finding
	host := ev.Host.Hostname
	var l lineSet

	switch ev.Kind {
	case model.EventResolved:
		l.add("✅ RESOLVED: "+f.VulnID+" on "+host,
			"✅ <b>RESOLVED: "+esc(f.VulnID)+" on "+esc(host)+"</b>")
		l.add(f.PackageName+" "+f.PackageVer+": now "+string(f.Verdict),
			esc(f.PackageName)+" "+esc(f.PackageVer)+": now "+esc(string(f.Verdict)))
		return l.render()

	case model.EventUnknownCritical:
		l.add("🟠 CHECK: "+f.VulnID+" on "+host,
			"🟠 <b>CHECK: "+esc(f.VulnID)+" on "+esc(host)+"</b>")

	case model.EventExploitable:
		l.add("🔴 EXPLOITABLE: "+f.VulnID+" on "+host,
			"🔴 <b>EXPLOITABLE: "+esc(f.VulnID)+" on "+esc(host)+"</b>")

	default:
		l.add("ℹ️ "+string(ev.Kind)+": "+f.VulnID+" on "+host,
			"ℹ️ <b>"+esc(string(ev.Kind))+": "+esc(f.VulnID)+" on "+esc(host)+"</b>")
	}

	// Package and fix availability.
	pkgPlain := f.PackageName + " " + f.PackageVer
	pkgHTML := esc(f.PackageName) + " " + esc(f.PackageVer)
	if len(f.FixedVersions) > 0 {
		fixed := strings.Join(f.FixedVersions, ", ")
		l.add("Package: "+pkgPlain+" → fixed in "+fixed, "Package: "+pkgHTML+" → fixed in "+esc(fixed))
	} else {
		l.add("Package: "+pkgPlain+" → no fix yet", "Package: "+pkgHTML+" → no fix yet")
	}

	// Target.
	if f.TargetKind == model.TargetContainerImage {
		l.add("Target: image "+f.Target, "Target: image "+esc(f.Target))
	} else {
		l.add("Target: host", "Target: host")
	}

	// Severity, CVSS, EPSS, KEV.
	var sevP, sevH []string
	if f.Severity != "" {
		sevP = append(sevP, "Severity "+f.Severity)
		sevH = append(sevH, "Severity "+esc(f.Severity))
	}
	if f.CVSS > 0 {
		s := fmt.Sprintf("CVSS %.1f", f.CVSS)
		sevP, sevH = append(sevP, s), append(sevH, s)
	}
	if f.EPSS > 0 {
		s := fmt.Sprintf("EPSS %.1f%%", f.EPSS*100)
		sevP, sevH = append(sevP, s), append(sevH, s)
	}
	if f.KEV {
		sevP = append(sevP, "🚨 KEV")
		sevH = append(sevH, "🚨 <b>KEV</b>")
	}
	if len(sevP) > 0 {
		l.add(strings.Join(sevP, " · "), strings.Join(sevH, " · "))
	}

	// Why it matters.
	if ev.Kind == model.EventUnknownCritical {
		if f.VerdictReason != "" {
			l.add("Conditions not verified: "+f.VerdictReason, "Conditions not verified: "+esc(f.VerdictReason))
		}
	} else if f.VerdictReason != "" {
		l.add("Why: "+f.VerdictReason, "Why: "+esc(f.VerdictReason))
	}

	// Rule.
	if ev.Rule != nil {
		text := ev.Rule.Title
		if ev.Rule.Explanation != "" {
			text += " — " + ev.Rule.Explanation
		}
		if text != "" {
			l.add("Rule: "+text, "Rule: "+esc(text))
		}
	}
	if f.RuleStatus == model.RuleDraft {
		l.add("⚠️ rule is an unreviewed LLM draft", "⚠️ <b>rule is an unreviewed LLM draft</b>")
	}

	// Fix and mitigation.
	switch {
	case ev.FixCmd != "":
		l.add("Fix: "+ev.FixCmd, "Fix: <code>"+esc(ev.FixCmd)+"</code>")
	case ev.Rule != nil && ev.Rule.Fix.Upgrade != "":
		l.add("Fix: "+ev.Rule.Fix.Upgrade, "Fix: "+esc(ev.Rule.Fix.Upgrade))
	}
	if ev.Rule != nil && ev.Rule.Fix.Mitigation != "" {
		l.add("Mitigation: "+ev.Rule.Fix.Mitigation, "Mitigation: "+esc(ev.Rule.Fix.Mitigation))
	}

	// Link.
	if ev.WebURL != "" && isHTTP(ev.WebURL) {
		l.add("Details: "+ev.WebURL, `Details: <a href="`+esc(ev.WebURL)+`">`+esc(ev.WebURL)+`</a>`)
	}
	return l.render()
}

// renderSummary builds the burst summary for the findings that were not sent individually.
// findingsLink may be empty.
func renderSummary(rest []model.Event, findingsLink string) message {
	var l lineSet
	header := fmt.Sprintf("…and %d more findings", len(rest))
	l.add(header, esc(header))
	for i, ev := range rest {
		if i == summaryMaxLines {
			more := fmt.Sprintf("…and %d more not listed", len(rest)-summaryMaxLines)
			l.add(more, esc(more))
			break
		}
		item := ev.Finding.VulnID + "@" + ev.Host.Hostname
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
