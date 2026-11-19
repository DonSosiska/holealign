package notify

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"unicode/utf8"

	"github.com/DonSosiska/holealign/internal/model"
)

// SpanKind is the inline style of a Span.
type SpanKind uint8

const (
	SpanText SpanKind = iota // plain text
	SpanBold                 // emphasised text (headers, KEV)
	SpanCode                 // copy-pasteable code (fix commands)
	SpanLink                 // hyperlink: Text is the label, URL an absolute http(s) URL
)

// Span is a piece of a Line. Text is untrusted (already cleaned of control characters and cut to
// length by the renderer, but not escaped): every formatter must escape it for its markup.
type Span struct {
	Kind SpanKind
	Text string
	URL  string // SpanLink only
}

// Line is one line of a message.
type Line []Span

// Message is the channel-neutral content of one notification: a header line, fact lines, host
// lines, reason, fix hint, links. Channels format it for their markup (see formatMatrix,
// formatSlack, formatTelegram).
type Message struct {
	Kind   model.EventKind // kind of the (first) event; "" for a burst summary
	Notice bool            // informational (resolved, agent back, feed ok): no alert-style notification
	Lines  []Line
	// Events is the structured content of the message (one entry per event of the group, capped at
	// maxGroupEvents), with the same cleaning as Lines but no markup. Channels that deliver data
	// instead of text (the generic webhook) are built from it. Nil for burst summaries.
	Events []MessageEvent
	// ID is a unique idempotency key assigned by the Notifier; it is the same for all retries of one
	// delivery (Matrix uses it as transaction ID).
	ID string
}

// MessageEvent is one event of a Message in machine-readable form. The JSON names are the stable
// schema (version 1) of the generic webhook; see docs/notifications.md. Text fields are cleaned of
// control characters and cut to maxFieldRunes runes, but not escaped for any markup.
type MessageEvent struct {
	Kind         string   `json:"kind"`
	Host         string   `json:"host"`
	Labels       []string `json:"labels"`
	VulnID       string   `json:"vuln_id"`
	Aliases      []string `json:"aliases"`
	Package      string   `json:"package"`
	Version      string   `json:"version"`
	FixedVersion string   `json:"fixed_version"` // fixed versions joined with ", "; "" when none
	Verdict      string   `json:"verdict"`
	Severity     string   `json:"severity"`
	CVSS         float64  `json:"cvss"`
	EPSS         float64  `json:"epss"`
	KEV          bool     `json:"kev"`
	Reason       string   `json:"reason"`
	FindingURL   string   `json:"finding_url"`
}

func txt(s string) Span        { return Span{Kind: SpanText, Text: s} }
func bold(s string) Span       { return Span{Kind: SpanBold, Text: s} }
func code(s string) Span       { return Span{Kind: SpanCode, Text: s} }
func link(text, u string) Span { return Span{Kind: SpanLink, Text: text, URL: u} }
func (l Line) plain() string {
	var b strings.Builder
	for _, s := range l {
		b.WriteString(s.Text)
	}
	return b.String()
}

// fingerprint identifies the content (not the ID) for the partial-delivery memory.
func (m Message) fingerprint() string {
	h := sha256.New()
	for _, l := range m.Lines {
		for _, s := range l {
			h.Write([]byte{byte(s.Kind)})
			h.Write([]byte(s.Text))
			h.Write([]byte{0})
			h.Write([]byte(s.URL))
			h.Write([]byte{0})
		}
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil)[:12])
}

func isNotice(k model.EventKind) bool {
	return k == model.EventResolved || k == model.EventAgentBack || k == model.EventFeedOK
}

// zwsp is inserted after every "@" so that "@everyone", "@room", "@channel" and "@username" in
// untrusted text cannot ping anybody. It is idempotent.
const zwsp = "\u200b"

func neutralAt(s string) string {
	if !strings.Contains(s, "@") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		b.WriteByte(s[i])
		if s[i] == '@' && !strings.HasPrefix(s[i+1:], zwsp) {
			b.WriteString(zwsp)
		}
	}
	return b.String()
}

// visibleLen is the number of runes of the plain text of a line.
func (l Line) visibleLen() int {
	n := 0
	for _, s := range l {
		n += utf8.RuneCountInString(s.Text)
	}
	return n
}

// fitLine returns l cut to at most limit runes of visible text: trailing spans are dropped whole
// (never a formatted span cut in the middle, except that a single span longer than limit is cut by
// runes) and an ellipsis is appended when something was removed.
func fitLine(l Line, limit int) Line {
	if l.visibleLen() <= limit {
		return l
	}
	var out Line
	used := 0
	budget := limit - 1 // room for the ellipsis
	for _, s := range l {
		n := utf8.RuneCountInString(s.Text)
		if used+n <= budget {
			out = append(out, s)
			used += n
			continue
		}
		if len(out) == 0 { // first span alone is too long
			r := []rune(s.Text)
			s.Text = string(r[:max(0, budget)])
			out = append(out, s)
		}
		break
	}
	return append(out, txt("…"))
}

// fitLines keeps whole lines while the visible length (plus one per line) stays within limit runes
// and appends truncatedNote when some were dropped. Over-long lines are cut with fitLine.
func fitLines(lines []Line, limit int) []Line {
	total := 0
	for _, l := range lines {
		total += l.visibleLen() + 1
	}
	if total <= limit {
		return lines
	}
	budget := limit - utf8.RuneCountInString(truncatedNote) - 1
	var out []Line
	used := 0
	for _, l := range lines {
		l = fitLine(l, budget)
		if used+l.visibleLen()+1 > budget {
			break
		}
		out = append(out, l)
		used += l.visibleLen() + 1
	}
	return append(out, Line{txt(truncatedNote)})
}
