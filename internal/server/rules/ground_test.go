package rules

import (
	"strings"
	"testing"

	"panoptes/internal/model"
)

func groundRule(expr string, facts ...string) model.Rule {
	return model.Rule{
		ID: "G-1", Vulns: []string{"CVE-2030-1"}, Title: "t", Explanation: "e", Source: "llm:t",
		Status: model.RuleDraft, Facts: facts, ExploitableIf: expr,
		Packages: []model.PackageSelector{{Name: "foo"}},
	}
}

func depOf(t *testing.T, r model.Rule) bool {
	t.Helper()
	if err := Validate(r); err != nil {
		t.Fatalf("invalid rule %q: %v", r.ExploitableIf, err)
	}
	p, refs, root, err := compileBoolAST(r.ExploitableIf)
	if err != nil {
		t.Fatal(err)
	}
	return factDependent(p, root, refs, r)
}

func TestFactDependentIndependent(t *testing.T) {
	for _, c := range []struct {
		expr  string
		facts []string
	}{
		{`facts["os.id"] == facts["os.id"]`, []string{"os.id"}},
		{`facts["os.id"] != "" || true`, []string{"os.id"}},
		{`size(facts["sockets.ports"]) >= 0`, []string{"sockets.ports"}},
		{`true || facts["os.id"] == "x"`, []string{"os.id"}},
		{`facts["nginx.http2"] ? true : true`, []string{"nginx.http2"}},
		{`facts["os.id"] == "x" && false`, []string{"os.id"}},
		{`true`, nil},
		{`pkg["name"] == "foo"`, nil},
		{`facts["kernel.sysctl"][?"a"].orValue("1") == facts["kernel.sysctl"][?"a"].orValue("1")`, []string{"kernel.sysctl"}},
	} {
		if depOf(t, groundRule(c.expr, c.facts...)) {
			t.Errorf("%q judged fact-dependent", c.expr)
		}
	}
}

func TestFactDependentDependent(t *testing.T) {
	for _, c := range []struct {
		expr  string
		facts []string
	}{
		{`facts["os.id"] == "debian"`, []string{"os.id"}},
		{`"sshd" in facts["services.active"]`, []string{"services.active"}},
		{`facts["nginx.http2"] == true`, []string{"nginx.http2"}},
		{`443 in facts["sockets.ports"]`, []string{"sockets.ports"}},
		{`facts["sockets.ports"].exists(p, p == 8443)`, []string{"sockets.ports"}},
		{`facts["sockets.ports"].exists(p, p >= 1024 && p < 2000)`, []string{"sockets.ports"}},
		{`has_module(facts["nginx.modules"], "http_v2_module")`, []string{"nginx.modules"}},
		{`facts["sshd.config"][?"permitrootlogin"].orValue("no") == "yes"`, []string{"sshd.config"}},
		{`facts["kernel.sysctl"][?"user.max_user_namespaces"].orValue("1") != "0"`, []string{"kernel.sysctl"}},
		{`facts["nginx.directives"][?"ssl_protocols"].orValue([]).exists(v, v.contains("TLSv1.0"))`, []string{"nginx.directives"}},
		{`facts["os.libc"] == "glibc" && facts["sshd.config"][?"logingracetime"].orValue("120") != "0"`, []string{"os.libc", "sshd.config"}},
		{`facts["sockets.listening"].exists(s, s["port"] == 22)`, []string{"sockets.listening"}},
		{`version_lt(facts["sudo.version"], "1.9.5")`, []string{"sudo.version"}},
		{`facts["docker.containers"].size() > 0`, []string{"docker.containers"}},
		{`facts["php.ini"][?"allow_url_include"].orValue("0") == "1" && "apache2handler" in facts["php.sapi"]`, []string{"php.ini", "php.sapi"}},
	} {
		if !depOf(t, groundRule(c.expr, c.facts...)) {
			t.Errorf("%q judged fact-independent", c.expr)
		}
	}
}

func TestFactDependentPackageSelector(t *testing.T) {
	r := groundRule(`pkg["name"].startsWith("openssh-server") && "sshd" in facts["services.active"]`, "services.active")
	r.Packages = []model.PackageSelector{{Name: "openssh-server", Type: "deb"}, {Name: "openssh-client", Type: "deb"}}
	if !depOf(t, r) {
		t.Error("package-gated condition judged independent")
	}
}

func TestShippedRulesAreFactDependent(t *testing.T) {
	for _, r := range loadShipped(t) {
		if strings.TrimSpace(r.ExploitableIf) == "false" {
			continue // constant by design (reviewed "no attack path" rule)
		}
		p, refs, root, err := compileBoolAST(r.ExploitableIf)
		if err != nil {
			t.Fatalf("%s: %v", r.ID, err)
		}
		if !factDependent(p, root, refs, r) {
			t.Errorf("shipped rule %s judged fact-independent", r.ID)
		}
	}
}

func TestDraftGroundingEvaluate(t *testing.T) {
	// the audit's bypass drafts
	cases := []struct {
		name, expl string
		r          model.Rule
		facts      map[string]any
		want       model.Verdict
		reason     string
	}{
		{"suppress via false&&", "x", model.Rule{ID: "a", Status: model.RuleDraft, Facts: []string{"os.id"}, ExploitableIf: `false && facts["os.id"] == "x"`},
			map[string]any{"os.id": "debian"}, model.VerdictConditionsUnknown, "LLM draft suggests not exploitable (unreviewed): because reasons"},
		{"suppress via not_affected_if", "x", model.Rule{ID: "a", Status: model.RuleDraft, Facts: []string{"os.id"}, ExploitableIf: `facts["os.id"] == "debian"`, NotAffectedIf: `facts["os.id"] != ""`},
			map[string]any{"os.id": "debian"}, model.VerdictConditionsUnknown, "LLM draft suggests not exploitable"},
		{"spam via tautology", "x", model.Rule{ID: "a", Status: model.RuleDraft, Facts: []string{"os.id"}, ExploitableIf: `facts["os.id"] == facts["os.id"]`},
			map[string]any{"os.id": "debian"}, model.VerdictConditionsUnknown, "does not depend on host facts"},
		{"genuine", "x", model.Rule{ID: "a", Status: model.RuleDraft, Facts: []string{"os.id"}, ExploitableIf: `facts["os.id"] == "debian"`},
			map[string]any{"os.id": "debian"}, model.VerdictExploitable, "LLM draft (unreviewed)"},
	}
	for _, c := range cases {
		e := draftEngine(c.r)
		for _, sev := range []string{"Low", "Medium", "High", "Critical"} {
			ev := evalSev(t, e, false, sev, c.facts)
			want(t, ev, c.want, c.reason)
		}
	}
	// reviewed rules are unaffected
	r := model.Rule{ID: "a", Status: model.RuleReviewed, Facts: []string{"os.id"}, ExploitableIf: `facts["os.id"] == facts["os.id"]`}
	want(t, evalSev(t, draftEngine(r), false, "High", map[string]any{"os.id": "x"}), model.VerdictExploitable)
	r.ExploitableIf, r.NotAffectedIf = `true`, `facts["os.id"] != ""`
	want(t, evalSev(t, draftEngine(r), false, "High", map[string]any{"os.id": "x"}), model.VerdictNotExploitable)
}

func TestFileMatchPathPolicy(t *testing.T) {
	good := []string{
		"/etc/ssh/sshd_config", "/etc/nginx/nginx.conf", "/etc/nginx/conf.d/*.conf",
		"/etc/apache2/mods-enabled/*.load", "/etc/php/8.2/apache2/php.ini", "/etc/sysctl.d/*.conf",
		"/usr/local/etc/nginx/nginx.conf", "/opt/app/conf/server.xml", "/etc/ssh/sshd_config.d/*.conf",
	}
	for _, p := range good {
		if err := FileMatchPathAllowed(p); err != nil {
			t.Errorf("rejected %q: %v", p, err)
		}
	}
	bad := []string{
		"/etc/ssh/*_key", "/etc/ssh/ssh_?ost_rsa_key", "/etc/*.conf", "/etc/*", "/etc/n*", "/etc/ng*",
		"/etc/*/nginx.conf", "/etc/ngi*/nginx.conf", "/opt/*/conf/a.conf",
		"/etc/foo/*key*", "/etc/foo/*secret*", "/etc/foo/*token*.conf", "/etc/foo/shadow", "/etc/foo/passwd",
		"/etc/foo/cred*ential", "/etc/foo/a.pem", "/etc/foo/*.p12", "/etc/foo/x.pfx", "/etc/foo/*.jks",
		"/etc/foo/app.env", "/etc/foo/htpasswd", "/etc/foo/*.env",
		"/etc/kubernetes/admin.conf", "/etc/rancher/k3s/k3s.yaml", "/etc/fstab", "/etc/exim4/passwd.client",
		"/etc/exim4/pass*", "/etc/postfix/sasl_passwd.db", "/etc/postfix/sasl_pas*", "/etc/samba/smbpasswd",
		"/etc/pgbouncer/pgbouncer.ini", "/etc/wpa_supplicant/wpa_supplicant.conf", "/etc/environment",
		"/etc/default/nginx", "/etc/sysconfig/network", "/etc/boto.cfg", "/etc/aws/config", "/etc/gcloud/x.conf",
		"/etc/vault.d/vault.hcl", "/etc/vault/config.hcl", "/etc/consul.d/consul.hcl", "/etc/nomad.d/nomad.hcl",
		"/etc/ansible/hosts", "/etc/openldap/slapd.conf", "/etc/ldap/ldap.conf", "/etc/dovecot/dovecot.conf",
		"/etc/zabbix/zabbix_agentd.conf", "/etc/telegraf/telegraf.conf", "/etc/filebeat/filebeat.yml",
		"/etc/grafana/grafana.ini", "/etc/docker/daemon.json", "/etc/security/opasswd", "/etc/cron.d/x",
		"/etc/crontab", "/etc/cron.daily/logrotate", "/etc/redis/redis.conf", "/etc/mysql/my.cnf",
		"/etc/postgresql/15/main/pg_hba.conf", "/etc/mongod.conf", "/etc/rabbitmq/rabbitmq.conf",
		"/etc/elasticsearch/elasticsearch.yml", "/etc/kibana/kibana.yml", "/etc/logstash/logstash.conf",
		"/etc/sssd/sssd.conf", "/etc/krb5.conf", "/etc/krb5.keytab", "/etc/letsencrypt/cli.ini",
		"/etc/ssl/openssl.cnf", "/etc/pki/tls/openssl.cnf", "/etc/ssh/ssh_host_rsa_key",
		"/etc/vaul*", "/etc/mongod*", "/etc/ssh/ssh_ho*", "/etc/nginx/../shadow", "/etc/a[b]c.conf",
	}
	for _, p := range bad {
		if err := FileMatchPathAllowed(p); err == nil {
			t.Errorf("accepted %q", p)
		}
	}
}

func TestFileMatchPatternPolicy(t *testing.T) {
	good := []string{
		`^\s*http2\s+on`, `(?i)^\s*PermitRootLogin\s+yes`, `LoadModule\s+proxy_module`,
		`^\s*ssl_protocols`, `ProxyPass`, `(?i)allow_url_include\s*=\s*(1|on)`, `^\s*(listen|server_name)\s`,
		`^\s*Include\s+/etc/foo`, `(?i)^[ \t]*MaxAuthTries[ \t]+[0-9]{1,3}`,
	}
	for _, p := range good {
		if msg := checkPattern(p); msg != "" {
			t.Errorf("rejected %q: %s", p, msg)
		}
	}
	bad := []string{
		``, `.*`, `.+`, `[a-z]`, `[[:alpha:]]`, `\pL`, `e`, `[a-z0-9_]`, `\w+`, `\S`, `(?s).`, `^`, `abc`,
		`(foo)?(bar)*baz`, `(abcd|ef)`, `foo|`, `(?:abcd)?`, `a{101}bcdefg`, `x*abcd?`, `[a-z]+|abcd`,
		`^\s*[a-z]+\s*=`, strings.Repeat("a", 257), `(`,
	}
	for _, p := range bad {
		if p == "" {
			continue
		}
		if msg := checkPattern(p); msg == "" {
			t.Errorf("accepted %q", p)
		}
	}
	// literal in every alternation branch counts; case-insensitive literals allowed
	for _, p := range []string{`(?i)(Header|Server)Token`, `(?:foobar|bazqux)\s+on`, `(?i)PERMITROOTLOGIN`} {
		if msg := checkPattern(p); msg != "" {
			t.Errorf("rejected %q: %s", p, msg)
		}
	}
}
