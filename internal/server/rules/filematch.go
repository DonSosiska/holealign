package rules

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

const (
	maxFactRequests    = 5
	maxFileMatchPatLen = 256
	maxRequestSuffix   = 64
)

// denyPatterns are component sequences (lowercase, path.Match globs) that must
// never appear in a file.match path. Keep in sync with the agent's copy.
var denyPatterns = [][]string{
	{"shadow*"}, {"gshadow*"}, {"passwd-"}, {"sudoers*"}, {"ssh", "ssh_host_*"},
	{"ssl", "private"}, {"letsencrypt"}, {"pki"}, {"panoptes"}, {"krb5.keytab"},
	{"*.key"}, {"*.pem"}, {"*.p12"}, {"*.pfx"}, {"*.jks"}, {"*.keystore"},
	{".htpasswd"}, {"*secret*"}, {"*credential*"}, {"*token*"},
	{"networkmanager"}, {"wireguard"}, {"openvpn"}, {"ppp"}, {"security"},
	{"polkit-1"}, {"ipsec*"}, {"strongswan*"}, {"cloud"},
	{"mysql", "debian.cnf"}, {"*.env"},
}

func hasMeta(s string) bool { return strings.ContainsAny(s, "*?") }

// exemplars of a deny pattern: stars replaced by "" or "x".
func exemplars(d string) []string {
	out := []string{""}
	parts := strings.Split(d, "*")
	out = []string{parts[0]}
	for _, p := range parts[1:] {
		var next []string
		for _, o := range out {
			next = append(next, o+p, o+"x"+p)
		}
		out = next
	}
	return out
}

// globCandidates are concrete strings a glob component can produce.
func globCandidates(g string) []string {
	a := strings.NewReplacer("*", "", "?", "x").Replace(g)
	b := strings.NewReplacer("*", "x", "?", "x").Replace(g)
	return []string{a, b}
}

// mayMatch reports whether glob/literal component g can match deny pattern d.
func mayMatch(g, d string) bool {
	if !hasMeta(g) {
		ok, _ := path.Match(d, g)
		return ok
	}
	for _, x := range exemplars(d) {
		if ok, _ := path.Match(g, x); ok {
			return true
		}
	}
	for _, c := range globCandidates(g) {
		if ok, _ := path.Match(d, c); ok {
			return true
		}
	}
	return false
}

// FileMatchPathAllowed reports whether a file.match path glob is acceptable:
// absolute, clean, under an allowed configuration root and not able to match
// anything on the secret denylist.
func FileMatchPathAllowed(p string) error {
	if p == "" || len(p) > 1024 {
		return fmt.Errorf("path must be 1..1024 characters")
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("path contains control characters")
		}
	}
	if strings.ContainsAny(p, `[]\`) {
		return fmt.Errorf("path %q: character classes and escapes are not allowed", p)
	}
	if !strings.HasPrefix(p, "/") {
		return fmt.Errorf("path %q must be absolute", p)
	}
	if path.Clean(p) != p {
		return fmt.Errorf("path %q must be clean (no '..', '.', '//' or trailing '/')", p)
	}
	comps := strings.Split(p[1:], "/")
	for _, c := range comps {
		if c == "" || c == "." || c == ".." {
			return fmt.Errorf("path %q must be clean", p)
		}
	}
	chk := make([]string, len(comps))
	for i, c := range comps {
		chk[i] = strings.ToLower(c)
	}
	ok := false
	switch {
	case chk[0] == "etc" && len(chk) >= 2:
		ok = true
	case len(chk) >= 4 && chk[0] == "usr" && chk[1] == "local" && chk[2] == "etc":
		ok = true
	case len(chk) >= 4 && chk[0] == "opt" && (chk[2] == "conf" || chk[2] == "etc"):
		ok = true
		if chk[1] == "*" {
			chk[1] = "x" // the wildcard application directory of the root itself
		}
	}
	if !ok {
		return fmt.Errorf("path %q is not under an allowed root (/etc/, /opt/*/conf/, /opt/*/etc/, /usr/local/etc/)", p)
	}
	for _, d := range denyPatterns {
		for i := 0; i+len(d) <= len(chk); i++ {
			all := true
			for j := range d {
				if !mayMatch(chk[i+j], d[j]) {
					all = false
					break
				}
			}
			if all {
				return fmt.Errorf("path %q may match a protected (secret/credential) location", p)
			}
		}
	}
	return nil
}

func sanitizeRuleID(id string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(id) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	return b.String()
}

// FactRequestPrefix is the mandatory name prefix of a rule's file.match
// requests: "file.match:<ruleID-sanitized>.".
func FactRequestPrefix(ruleID string) string {
	return FileMatchPrefix + sanitizeRuleID(ruleID) + "."
}

var requestSuffixRe = regexp.MustCompile(`^[a-z0-9._-]+$`)

var probes = []string{"a", "Z", "0", "-", "#", "/", "=", " "}

func checkRequest(ruleID string, fr factReq) []string {
	var p []string
	pre := FactRequestPrefix(ruleID)
	if !strings.HasPrefix(fr.Name, pre) || len(fr.Name) == len(pre) {
		p = append(p, fmt.Sprintf("name %q must be %s<id> (namespaced by rule id)", fr.Name, pre))
	} else {
		suf := fr.Name[len(FileMatchPrefix):]
		if len(suf) > maxRequestSuffix || !requestSuffixRe.MatchString(suf) {
			p = append(p, fmt.Sprintf("name %q: part after %q must be [a-z0-9._-] and at most %d chars", fr.Name, FileMatchPrefix, maxRequestSuffix))
		}
	}
	if fr.Path != "" {
		if err := FileMatchPathAllowed(fr.Path); err != nil {
			p = append(p, "params.path: "+err.Error())
		}
	}
	pat := fr.Pattern
	if pat != "" {
		if len(pat) > maxFileMatchPatLen {
			p = append(p, fmt.Sprintf("params.pattern longer than %d chars", maxFileMatchPatLen))
		} else if re, err := regexp.Compile(pat); err != nil {
			p = append(p, fmt.Sprintf("params.pattern is not valid RE2: %v", err))
		} else {
			if re.MatchString("") {
				p = append(p, "params.pattern matches the empty string (match-all patterns are not allowed)")
			} else {
				n := 0
				for _, s := range probes {
					if re.MatchString(s) {
						n++
					}
				}
				if n >= 3 {
					p = append(p, "params.pattern is too broad (matches almost any line); use a specific directive")
				}
			}
		}
	}
	return p
}

type factReq struct{ Name, Path, Pattern string }
