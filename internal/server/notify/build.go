package notify

import (
	"fmt"
	"strings"

	"github.com/DonSosiska/holealign/internal/model"
)

// buildGroup builds the neutral message for a group of events that share kind, host, vulnerability
// and target. Values are merged: packages listed, severity maxima, deduplicated reasons and fixes.
// Every untrusted value is cleaned (see cl) but not escaped; formatters escape per markup.
func buildGroup(raw []model.Event) Message {
	extraEvents := 0
	if len(raw) > maxGroupEvents {
		extraEvents = len(raw) - maxGroupEvents
		raw = raw[:maxGroupEvents]
	}
	events := make([]MessageEvent, len(raw))
	for i, ev := range raw {
		events[i] = messageEvent(ev)
	}
	evs := make([]model.Event, len(raw))
	moreFixes := make([]int, len(raw))
	for i, ev := range raw {
		moreFixes[i] = max(0, len(ev.Finding.FixedVersions)-maxFixedVersions)
		evs[i] = sanitize(ev)
	}
	g := group{evs: evs}
	first := g.first()
	out := Message{Kind: first.Kind, Notice: isNotice(first.Kind), Events: events}
	if first.Kind.IsHealth() {
		out.Lines = buildHealth(first)
		return out
	}
	f := first.Finding
	host := first.Host.Hostname
	var l lineSet

	if first.Kind == model.EventResolved {
		var plain []string
		for _, ev := range evs {
			plain = append(plain, ev.Finding.PackageName+" "+ev.Finding.PackageVer+": now "+string(ev.Finding.Verdict))
		}
		l.add(txt("✅ "), bold("RESOLVED: "+f.VulnID+" on "+host))
		l.add(txt(strings.Join(distinct(plain), "; ")))
		out.Lines = l.lines
		return out
	}

	switch first.Kind {
	case model.EventUnknownCritical:
		l.add(txt("🟠 "), bold("CHECK: "+f.VulnID+" on "+host))
	case model.EventExploitable:
		l.add(txt("🔴 "), bold("EXPLOITABLE: "+f.VulnID+" on "+host))
	default:
		l.add(txt("ℹ️ "), bold(string(first.Kind)+": "+f.VulnID+" on "+host))
	}

	// Packages with their fix availability, deduplicated.
	var pkgs []string
	for i, ev := range evs {
		name := ev.Finding.PackageName + " " + ev.Finding.PackageVer
		if len(ev.Finding.FixedVersions) > 0 {
			fixed := strings.Join(ev.Finding.FixedVersions, ", ")
			if moreFixes[i] > 0 {
				fixed += fmt.Sprintf(", +%d more", moreFixes[i])
			}
			pkgs = append(pkgs, name+" → fixed in "+fixed)
		} else {
			pkgs = append(pkgs, name+" → no fix yet")
		}
	}
	pkgs = distinct(pkgs)
	if len(pkgs) == 1 {
		l.add(txt("Package: " + pkgs[0]))
	} else {
		l.add(txt("Packages: " + capJoin(pkgs, "; ")))
	}

	if extraEvents > 0 {
		l.add(txt(fmt.Sprintf("…and %d more events for this vulnerability not listed", extraEvents)))
	}

	// Target.
	if f.TargetKind == model.TargetContainerImage {
		l.add(txt("Target: image " + f.Target))
	} else {
		l.add(txt("Target: host"))
	}

	// Severity, CVSS, EPSS, KEV: maxima over the group.
	var facts [][]Span
	if sev := g.maxSeverity(); sev != "" {
		facts = append(facts, []Span{txt("Severity " + sev)})
	}
	if cvss := g.maxCVSS(); cvss > 0 {
		facts = append(facts, []Span{txt(fmt.Sprintf("CVSS %.1f", cvss))})
	}
	if epss := g.maxEPSS(); epss > 0 {
		facts = append(facts, []Span{txt(fmt.Sprintf("EPSS %.1f%%", epss*100))})
	}
	if g.anyKEV() {
		facts = append(facts, []Span{txt("🚨 "), bold("KEV")})
	}
	if len(facts) > 0 {
		var spans []Span
		for i, fs := range facts {
			if i > 0 {
				spans = append(spans, txt(" · "))
			}
			spans = append(spans, fs...)
		}
		l.add(spans...)
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
		l.add(txt(label + r))
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
		l.add(txt("Rule: " + r))
	}
	for _, ev := range evs {
		if isDraft(ev) {
			l.add(txt("⚠️ "), bold("unreviewed LLM draft — review the rule in the web UI before acting"))
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
			l.add(txt("Fix: "), code(c))
		}
	} else {
		var upgrades []string
		for _, ev := range evs {
			if ev.Rule != nil && !isDraft(ev) {
				upgrades = append(upgrades, ev.Rule.Fix.Upgrade)
			}
		}
		for _, u := range distinct(upgrades) {
			l.add(txt("Fix: " + u))
		}
	}

	// Mitigations, deduplicated.
	var mitigations []string
	for _, ev := range evs {
		if ev.Rule != nil && !isDraft(ev) { // reviewed rules only; always plain text, never code
			mitigations = append(mitigations, ev.Rule.Fix.Mitigation)
		}
	}
	for _, m := range distinct(mitigations) {
		l.add(txt("Mitigation: " + m))
	}

	// Link to the first event's finding.
	if first.WebURL != "" && isHTTP(first.WebURL) {
		l.add(txt("Details: "), link(first.WebURL, first.WebURL))
	}
	out.Lines = l.lines
	return out
}

// summaryMessage builds the burst summary for the groups that were not sent individually.
// findingsLink may be empty.
func summaryMessage(rest []group, findingsLink string) Message {
	var l lineSet
	l.add(txt(fmt.Sprintf("…and %d more findings", len(rest))))
	for i, g := range rest {
		if i == summaryMaxLines {
			l.add(txt(fmt.Sprintf("…and %d more not listed", len(rest)-summaryMaxLines)))
			break
		}
		l.add(txt("• " + cl(g.first().Finding.VulnID) + "@" + cl(g.first().Host.Hostname)))
	}
	if findingsLink != "" {
		l.add(txt("All findings: "), link(findingsLink, findingsLink))
	}
	return Message{Lines: l.lines}
}

// buildHealth renders feed, pipeline and agent silence events. ev must be sanitized.
func buildHealth(ev model.Event) []Line {
	host := ev.Host.Hostname
	if host == "" {
		host = "(unnamed host)"
	}
	icon, label, subject := "ℹ️", string(ev.Kind), host
	detail := ev.Detail
	switch ev.Kind {
	case model.EventAgentSilent:
		icon, label = "🔇", "AGENT SILENT"
		if ev.Host.ID == "" { // aggregated: the detail names the hosts
			subject = ""
		}
		if detail == "" && !ev.Host.LastCheckin.IsZero() {
			detail = "no check-in (last: " + ev.Host.LastCheckin.UTC().Format("2006-01-02 15:04 UTC") + ")"
		}
	case model.EventAgentBack:
		icon, label = "🔊", "AGENT BACK"
		if ev.Host.ID == "" {
			subject = ""
		}
		if detail == "" {
			detail = "checking in again"
		}
	case model.EventFeedStale:
		icon, label, subject = "🟣", "FEED STALE", ""
	case model.EventFeedOK:
		icon, label, subject = "✅", "FEED OK", ""
		if detail == "" {
			detail = "vulnerability DB is up to date again"
		}
	case model.EventPipelineError:
		icon, label = "⚠️", "PIPELINE ERROR"
		if ev.Host.ID == "" {
			subject = ""
		}
	}
	lines := strings.Split(detail, "\n")
	head := label + ":"
	if subject != "" {
		head += " " + subject
	}
	first := strings.TrimSpace(lines[0])
	var l lineSet
	if first != "" {
		sep := " — "
		if subject == "" {
			sep = " "
		}
		l.add(txt(icon+" "), bold(head), txt(sep+first))
	} else {
		l.add(txt(icon+" "), bold(head))
	}
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) != "" {
			l.add(txt(line))
		}
	}
	if ev.WebURL != "" && isHTTP(ev.WebURL) {
		l.add(txt("Details: "), link(ev.WebURL, ev.WebURL))
	}
	return l.lines
}

// plainField cleans a value for the structured output: control characters dropped, cut to
// maxFieldRunes runes, no markup escaping and no mention neutralisation.
func plainField(s string) string { return clBase(s) }

func plainFields(in []string, limit int) []string {
	out := make([]string, 0, len(in))
	for _, s := range in[:min(len(in), limit)] {
		out = append(out, plainField(s))
	}
	return out
}

// messageEvent converts an event to its structured form. Draft rules are treated like in the chat
// text: the reason of an unreviewed draft is replaced by a fixed string.
func messageEvent(ev model.Event) MessageEvent {
	f := ev.Finding
	reason := f.VerdictReason
	if ev.Kind.IsHealth() {
		reason = ev.Detail
	} else if isDraft(ev) {
		reason = draftSafeReason(reason)
	}
	if len(reason) > 4*maxFieldRunes {
		reason = cutBytes(reason, 4*maxFieldRunes)
	}
	// health details are multi-line; keep the line structure for them, clean each line
	lines := strings.Split(reason, "\n")
	for i, l := range lines {
		lines[i] = plainField(l)
	}
	reason = strings.Join(lines[:min(len(lines), maxDetailLines)], "\n")
	url := ""
	if ev.WebURL != "" && isHTTP(ev.WebURL) {
		url = ev.WebURL
	}
	return MessageEvent{
		Kind: string(ev.Kind), Host: plainField(ev.Host.Hostname), Labels: plainFields(ev.Host.Labels, 32),
		VulnID: plainField(f.VulnID), Aliases: plainFields(f.Aliases, 20),
		Package: plainField(f.PackageName), Version: plainField(f.PackageVer),
		FixedVersion: strings.Join(plainFields(f.FixedVersions, maxFixedVersions), ", "),
		Verdict:      string(f.Verdict), Severity: plainField(f.Severity), CVSS: f.CVSS, EPSS: f.EPSS, KEV: f.KEV,
		Reason: reason, FindingURL: url,
	}
}
