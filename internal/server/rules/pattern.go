package rules

import (
	"fmt"
	"regexp"
	"regexp/syntax"
	"unicode/utf8"
)

const (
	minMandatoryLiteral = 4
	maxRepeatCount      = 100
	maxProbeMatches     = 3
)

// probeLines are diverse sample lines (words, digits, punctuation, typical
// configuration lines). A file.match pattern may match at most maxProbeMatches
// of them; this is a secondary check next to the structural literal rule.
var probeLines = []string{
	"a", "Z", "0", "-", "#", "/", "=", " ", "_", "@", "!important", "$var", "(paren)",
	"hello world", "the quick brown fox", "12345", "# comment line", "; ini comment",
	"key = value", "name: value", "[section]", "{", "}", "server { }", "listen 80;",
	"include /etc/foo/*.conf;", "Port 22", "PermitRootLogin no",
	"LoadModule foo_module modules/mod_foo.so", "user www-data;", "worker_processes auto;",
	"export PATH=/usr/bin", "error_log /var/log/foo.log warn;", "ServerName example.com",
	"x = 1", "foo.bar.baz=true", "enabled yes", "true", "false", "192.168.0.1",
	"https://example.com/path", "UPPERCASE LINE", "mixed Case Line 42",
	"\tindented tab line", "    four spaces indent", "_underscore_",
}

// checkPattern applies the file.match pattern policy and returns a problem
// description, or "" when the pattern is acceptable.
func checkPattern(pat string) string {
	if len(pat) > maxFileMatchPatLen {
		return fmt.Sprintf("is longer than %d chars", maxFileMatchPatLen)
	}
	parsed, err := syntax.Parse(pat, syntax.Perl)
	if err != nil {
		return fmt.Sprintf("is not valid RE2: %v", err)
	}
	if maxRepeat(parsed) > maxRepeatCount {
		return fmt.Sprintf("uses a repeat count above %d", maxRepeatCount)
	}
	re, err := regexp.Compile(pat)
	if err != nil {
		return fmt.Sprintf("is not valid RE2: %v", err)
	}
	if re.MatchString("") {
		return "matches the empty string (match-all patterns are not allowed)"
	}
	if n := mandatoryLiteralLen(parsed.Simplify()); n < minMandatoryLiteral {
		return fmt.Sprintf("must contain a literal of at least %d characters that every match contains (name the directive); found %d", minMandatoryLiteral, n)
	}
	hits := 0
	for _, l := range probeLines {
		if re.MatchString(l) {
			hits++
		}
	}
	if hits > maxProbeMatches {
		return "is too broad (matches almost any line); use a specific directive"
	}
	return ""
}

func maxRepeat(re *syntax.Regexp) int {
	m := 0
	if re.Op == syntax.OpRepeat {
		m = max(re.Min, re.Max)
	}
	for _, s := range re.Sub {
		m = max(m, maxRepeat(s))
	}
	return m
}

// mandatoryLiteralLen returns the length (in runes) of the longest literal run
// that every match of re must contain. Optional or star-quantified parts never
// count; alternations count only the shortest such run across all branches.
func mandatoryLiteralLen(re *syntax.Regexp) int {
	switch re.Op {
	case syntax.OpLiteral:
		return utf8.RuneCountInString(string(re.Rune))
	case syntax.OpCapture, syntax.OpPlus:
		return mandatoryLiteralLen(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return mandatoryLiteralLen(re.Sub[0])
		}
		return 0
	case syntax.OpConcat:
		best, run := 0, 0
		var runFold syntax.Flags
		flush := func() {
			best = max(best, run)
			run = 0
		}
		for _, s := range re.Sub {
			if s.Op == syntax.OpLiteral {
				f := s.Flags & syntax.FoldCase
				if run > 0 && f != runFold {
					flush()
				}
				runFold = f
				run += len(s.Rune)
				continue
			}
			flush()
			best = max(best, mandatoryLiteralLen(s))
		}
		flush()
		return best
	case syntax.OpAlternate:
		low := -1
		for _, s := range re.Sub {
			if n := mandatoryLiteralLen(s); low < 0 || n < low {
				low = n
			}
		}
		return max(low, 0)
	}
	return 0
}
