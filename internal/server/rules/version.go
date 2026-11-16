package rules

import "strings"

// versionCompare compares two version strings loosely. A Debian-style epoch
// ("1:9.2p1-2") is compared first. The remainder is split into segments at
// non-alphanumeric characters and at digit/letter boundaries; numeric segments
// compare numerically, alphabetic ones lexically, missing segments count as 0.
func versionCompare(a, b string) int {
	ea, ra := splitEpoch(a)
	eb, rb := splitEpoch(b)
	if c := cmpNumeric(ea, eb); c != 0 {
		return c
	}
	sa, sb := versionSegments(ra), versionSegments(rb)
	n := len(sa)
	if len(sb) > n {
		n = len(sb)
	}
	for i := 0; i < n; i++ {
		x, y := "0", "0"
		if i < len(sa) {
			x = sa[i]
		}
		if i < len(sb) {
			y = sb[i]
		}
		if c := cmpSegment(x, y); c != 0 {
			return c
		}
	}
	return 0
}

func splitEpoch(v string) (string, string) {
	v = strings.TrimSpace(v)
	if i := strings.IndexByte(v, ':'); i > 0 && isDigits(v[:i]) {
		return v[:i], v[i+1:]
	}
	return "0", v
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func versionSegments(v string) []string {
	var segs []string
	start := -1
	class := 0 // 1 digit, 2 alpha
	flush := func(end int) {
		if start >= 0 {
			segs = append(segs, v[start:end])
			start = -1
		}
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		cl := 0
		switch {
		case isDigit(c):
			cl = 1
		case isAlpha(c):
			cl = 2
		}
		if cl == 0 {
			flush(i)
			class = 0
			continue
		}
		if cl != class {
			flush(i)
			start = i
			class = cl
		}
	}
	flush(len(v))
	return segs
}

func cmpNumeric(a, b string) int {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

func cmpSegment(a, b string) int {
	if isDigits(a) && isDigits(b) {
		return cmpNumeric(a, b)
	}
	return strings.Compare(a, b)
}
