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
// never appear in a file.match path, at any depth. The agent keeps its own copy
// (fmDenyPatterns, fmDenyPaths in internal/agent/facts/filematch.go) and re-checks it on
// resolved paths; a test in that package keeps both lists identical to these.
var denyPatterns = [][]string{
	{"shadow*"}, {"gshadow*"}, {"passwd-"}, {"sudoers*"}, {"ssh", "ssh_host_*"},
	{"ssl", "private"}, {"letsencrypt"}, {"pki"}, {"holealign"}, {"krb5.keytab"},
	{"*.key"}, {"*.pem"}, {"*.p12"}, {"*.pfx"}, {"*.jks"}, {"*.keystore"},
	{".htpasswd"}, {"*secret*"}, {"*credential*"}, {"*token*"},
	{"networkmanager"}, {"wireguard"}, {"openvpn"}, {"ppp"}, {"security"},
	{"polkit-1"}, {"ipsec*"}, {"strongswan*"}, {"cloud"},
	{"mysql", "debian.cnf"}, {"*.env"}, {"tomcat-users*.xml"},
}

// denyPaths are absolute path globs (lowercase) of credential-bearing files and
// directories. A path is rejected when it equals, lies below, or (for a
// wildcard final component) may match one of them.
var denyPaths = []string{
	"/etc/kubernetes", "/etc/rancher", "/etc/fstab", "/etc/exim4/passwd.client",
	"/etc/postfix/sasl_passwd*", "/etc/samba/smbpasswd", "/etc/pgbouncer",
	"/etc/wpa_supplicant", "/etc/environment", "/etc/default", "/etc/sysconfig",
	"/etc/boto.cfg", "/etc/aws", "/etc/gcloud", "/etc/vault*", "/etc/consul*",
	"/etc/nomad*", "/etc/ansible", "/etc/openldap", "/etc/ldap", "/etc/dovecot",
	"/etc/zabbix", "/etc/telegraf", "/etc/filebeat", "/etc/grafana", "/etc/docker",
	"/etc/opasswd", "/etc/cron*", "/etc/crontab", "/etc/redis", "/etc/mysql",
	"/etc/postgresql", "/etc/mongod.conf", "/etc/rabbitmq", "/etc/elasticsearch",
	"/etc/kibana", "/etc/logstash", "/etc/sssd", "/etc/krb5*", "/etc/letsencrypt",
	"/etc/ssl", "/etc/pki",
	"/etc/apt/auth.conf*", "/etc/hostapd", "/etc/squid/passwords*", "/etc/gitlab",
	"/etc/phpmyadmin/config-db.php", "/etc/msmtprc", "/etc/nagios/resource.cfg", "/etc/ssmtp",
}

// secretSubstrings must not occur in the final path component (literal parts).
var secretSubstrings = []string{
	"key", "secret", "token", "shadow", "passwd", "credential", ".pem", ".p12",
	".pfx", ".jks", ".env", "htpasswd", "keystore", "sudoers", "keytab",
}

const minFinalLiteral = 3

func hasMeta(s string) bool { return strings.ContainsAny(s, "*?") }

// literalParts splits a glob component into its literal runs.
func literalParts(g string) []string {
	return strings.FieldsFunc(g, func(r rune) bool { return r == '*' || r == '?' })
}

// fuzzyMatch reports whether wildcard component g may match deny component d:
// every literal part of g occurs in d (stripped of its own '*'), in order.
func fuzzyMatch(g, d string) bool {
	d = strings.ReplaceAll(d, "*", "")
	for _, p := range literalParts(g) {
		i := strings.Index(d, p)
		if i < 0 {
			return false
		}
		d = d[i+len(p):]
	}
	return true
}

// seqMayMatch reports whether the deny component sequence d can match chk at
// some offset. Only the last component of chk may be a wildcard (wild).
func seqMayMatch(chk, d []string, wild bool) bool {
	n := len(chk)
	for i := 0; i < n; i++ {
		ok := true
		for j := range d {
			pos := i + j
			if pos >= n {
				ok = false
				break
			}
			if pos == n-1 && wild {
				if !fuzzyMatch(chk[pos], d[j]) {
					ok = false
				}
				break // the wildcard component ends the comparison
			}
			if m, _ := path.Match(d[j], chk[pos]); !m {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// pathDenied checks chk against the absolute deny globs.
func pathDenied(chk []string, wild bool) bool {
	n := len(chk)
	for _, e := range denyPaths {
		ec := strings.Split(e[1:], "/")
		for k := 1; k <= len(ec) && k <= n; k++ {
			if k == n && wild {
				// the wildcard final component against entry component k-1; deeper
				// entry components below it are not reachable by a file glob
				if exactPrefix(chk[:k-1], ec[:k-1]) && fuzzyMatch(chk[k-1], ec[k-1]) {
					return true
				}
				continue
			}
			if k == len(ec) && exactPrefix(chk[:k], ec) {
				return true
			}
		}
	}
	return false
}

func exactPrefix(chk, ec []string) bool {
	for i := range ec {
		if m, _ := path.Match(ec[i], chk[i]); !m {
			return false
		}
	}
	return true
}

// FileMatchPathAllowed reports whether a file.match path glob is acceptable:
// absolute, clean, under an allowed configuration root, with wildcards only in
// the final component, and not able to match anything on the secret denylist.
// The agent applies its own denylist again to the resolved physical path.
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
	n := len(chk)
	for _, c := range chk[:n-1] {
		if hasMeta(c) {
			return fmt.Errorf("path %q: wildcards are only allowed in the final path component", p)
		}
	}
	last := chk[n-1]
	wild := hasMeta(last)
	if wild {
		pre := last[:strings.IndexAny(last, "*?")]
		suf := last[strings.LastIndexAny(last, "*?")+1:]
		if len(pre) < minFinalLiteral && len(suf) < minFinalLiteral {
			return fmt.Errorf("path %q: a wildcard file name needs a literal prefix or suffix of at least %d characters", p, minFinalLiteral)
		}
	}
	for _, s := range secretSubstrings {
		if strings.Contains(last, s) {
			return fmt.Errorf("path %q may match a protected (secret/credential) location (%q)", p, s)
		}
	}
	ok := false
	switch {
	case chk[0] == "etc" && n >= 2:
		ok = true
	case n >= 4 && chk[0] == "usr" && chk[1] == "local" && chk[2] == "etc":
		ok = true
	case n >= 4 && chk[0] == "opt" && (chk[2] == "conf" || chk[2] == "etc"):
		ok = true
	}
	if !ok {
		return fmt.Errorf("path %q is not under an allowed root (/etc/, /opt/<app>/conf/, /opt/<app>/etc/, /usr/local/etc/)", p)
	}
	for _, d := range denyPatterns {
		if seqMayMatch(chk, d, wild) {
			return fmt.Errorf("path %q may match a protected (secret/credential) location", p)
		}
	}
	if pathDenied(chk, wild) {
		return fmt.Errorf("path %q may match a protected (secret/credential) location", p)
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
		} else if msg := checkPattern(pat); msg != "" {
			p = append(p, "params.pattern "+msg)
		}
	}
	return p
}

type factReq struct{ Name, Path, Pattern string }
