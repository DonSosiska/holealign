package rules

import (
	"regexp"
	"strings"

	"github.com/DonSosiska/panoptes/internal/model"
)

// Realistic value sets for the grounding analysis (docs/contracts.md section 4, draft guard).
//
// A draft is grounded only if its exploitable_if varies over values a real host can report, not
// merely over the literals the expression itself names: a literal that no real host ever has
// ("zzz-never") would otherwise make `facts["os.id"] != "zzz-never"` look fact-dependent while it
// is true everywhere. Hint literals are therefore only used as candidates when they are realistic
// for the fact they are compared with; for enumerable facts a literal outside the known value set
// makes the draft ungrounded outright.

var enumSets = map[string][]string{
	"os.libc":         {"glibc", "musl"},
	"services.source": {"systemd", "proc"},
	"os.id": {"debian", "ubuntu", "alpine", "rhel", "centos", "rocky", "almalinux", "fedora", "amzn", "ol",
		"sles", "opensuse-leap", "opensuse-tumbleweed", "arch", "raspbian", "kali", "linuxmint", "photon",
		"wolfi", "mariner", "azurelinux"},
}

var servicePool = []string{
	"ssh", "sshd", "nginx", "apache2", "httpd", "php-fpm", "php7.4-fpm", "php8.1-fpm", "php8.2-fpm", "php8.3-fpm",
	"docker", "dockerd", "containerd", "cron", "crond", "rsyslog", "rsyslogd", "systemd-journald", "systemd-logind",
	"dbus", "dbus-daemon", "mysql", "mysqld", "mariadb", "mariadbd", "postgresql", "postgres", "redis", "redis-server",
	"memcached", "mongod", "named", "bind9", "unbound", "dnsmasq", "exim4", "postfix", "dovecot", "smbd", "nmbd",
	"nfsd", "cups", "cupsd", "snapd", "tomcat", "tomcat9", "jenkins", "grafana-server", "prometheus", "haproxy",
	"squid", "vsftpd", "proftpd", "openvpn", "wireguard", "fail2ban", "ntpd", "chronyd", "systemd-timesyncd",
	"avahi-daemon", "NetworkManager", "polkit", "sudo", "gitlab-runner", "kubelet", "etcd", "zabbix-agent",
}

var listPools = map[string][]string{
	"services.active": servicePool,
	"kernel.modules": {"nf_tables", "nf_conntrack", "nfnetlink", "ip_tables", "xt_conntrack", "overlay", "br_netfilter",
		"veth", "bridge", "vsock", "vmw_vsock_vmci_transport", "ext4", "xfs", "btrfs", "tun", "loop", "kvm", "kvm_intel",
		"kvm_amd", "vhost_net", "nft_chain_nat", "ipv6", "usb_storage", "fuse", "cifs", "nfs", "nfsd", "rds", "tipc",
		"sctp", "dccp", "af_key", "esp4", "xt_tcpudp", "nf_nat", "x_tables", "nft_ct", "nf_defrag_ipv4", "af_packet"},
	"nginx.modules": {"http_ssl_module", "http_v2_module", "http_v3_module", "http_realip_module", "http_gzip_static_module",
		"http_stub_status_module", "http_auth_request_module", "http_sub_module", "http_dav_module", "stream",
		"stream_ssl_module", "mail", "threads", "pcre", "http_geoip_module", "http_image_filter_module",
		"http_xslt_module", "http_mp4_module", "http_flv_module", "http_slice_module", "http_addition_module",
		"http_secure_link_module", "http_random_index_module", "file-aio"},
	"apache.modules": {"proxy_module", "proxy_http_module", "proxy_fcgi_module", "http2_module", "ssl_module",
		"rewrite_module", "cgi_module", "cgid_module", "php_module", "php7_module", "mpm_prefork_module",
		"mpm_event_module", "mpm_worker_module", "headers_module", "auth_basic_module", "authz_core_module",
		"alias_module", "dir_module", "mime_module", "proxy_balancer_module", "proxy_wstunnel_module",
		"status_module", "info_module", "userdir_module", "include_module", "expires_module", "deflate_module",
		"reqtimeout_module", "security2_module", "lbmethod_byrequests_module", "slotmem_shm_module"},
	"php.sapi":      {"cli", "fpm", "php-fpm", "apache2handler", "cgi", "cgi-fcgi", "fpm-fcgi", "litespeed", "embed", "phpdbg"},
	"agent.skipped": {"nginx: /etc/nginx/conf.d writable by gid 33", "sshd: /etc/ssh not root-owned", "php: /etc/php writable", "apache: /etc/apache2 writable", "sudo: /etc/sudoers.d writable"},
}

// valuePool are realistic string values of config-map entries (sshd -T, sysctl, php -i).
var valuePool = []string{
	"", "0", "1", "2", "3", "yes", "no", "on", "off", "true", "false", "On", "Off", "prohibit-password", "without-password",
	"forced-commands-only", "none", "all", "any", "password", "publickey", "keyboard-interactive", "120", "60", "30", "10", "6",
	"9", "22", "exec,passthru,shell_exec,system", "/var/www:/tmp", "/tmp", "-1", "default", "ask", "sandbox", "auto",
	"chacha20-poly1305@openssh.com", "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com", "aes128-ctr,aes192-ctr,aes256-ctr",
	"aes128-cbc,aes256-cbc", "aes256-gcm@openssh.com", "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com",
	"hmac-sha2-256,hmac-sha1", "aes128-cbc,hmac-sha2-256-etm@openssh.com", "curve25519-sha256,diffie-hellman-group14-sha256",
}

var directivePool = []string{
	"TLSv1", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3", "TLSv1 TLSv1.1 TLSv1.2", "TLSv1.0 TLSv1.2", "TLSv1.2 TLSv1.3",
	"on", "off", "443 ssl", "443 ssl http2", "80", "443", "127.0.0.1:9000", "unix:/run/php/php-fpm.sock", "http2", "h2",
	"*", "HIGH:!aNULL:!MD5", "example.com", "/var/www/html", "$request_uri", "1", "0",
}

var versionPool = []string{
	"0.1", "0.9", "1.0", "1.5", "1.9.5", "1.9.17p1", "2.0", "2.4.52", "2.4.58", "2.17", "2.31", "2.36", "3.0.2", "3.0.11", "3.3.2",
	"5.15.0", "6.1.0-18-amd64", "7.4.33", "8.2.1", "8.2", "9.2p1", "9.7p1", "10", "12", "1.24.0", "1.25.3", "20", "22.04", "24.0.5",
	"1.1.12", "99",
}

var (
	versionFactRe = regexp.MustCompile(`(^|\.)version$|^kernel\.release$|^os\.libc_version$|^os\.version_id$`)
	versionLitRe  = regexp.MustCompile(`^[0-9]+([.][0-9]+)*[.]?([a-z][0-9]*)?(-r?[0-9]+)?$`)
	numLitRe      = regexp.MustCompile(`^-?[0-9]+$`)
)

func isVersionFact(name string) bool { return versionFactRe.MatchString(name) }

func contains(set []string, s string) bool {
	for _, x := range set {
		if x == s {
			return true
		}
	}
	return false
}

// pkgWords are the words of the rule's package selectors (globs removed): a draft about package
// foo may legitimately mention "foo" in service or module lists.
func pkgWords(r model.Rule) []string {
	var out []string
	repl := strings.NewReplacer("*", "", "?", "", "[", "", "]", "", `\`, "")
	for _, s := range r.Packages {
		w := s.Name
		if s.Source != "" {
			w = s.Source
		}
		if w = strings.ToLower(repl.Replace(w)); len(w) >= 3 {
			out = append(out, w)
		}
	}
	return out
}

func relatedToPackage(words []string, lit string) bool {
	l := strings.ToLower(lit)
	if len(l) < 3 {
		return false
	}
	for _, w := range words {
		if strings.Contains(l, w) || strings.Contains(w, l) {
			return true
		}
	}
	return false
}

// realisticStr reports whether a string literal compared with fact name can occur on a real host.
func realisticStr(name string, t FactType, lit string, words []string) bool {
	if set, ok := enumSets[name]; ok {
		return contains(set, lit)
	}
	if strings.HasPrefix(name, FileMatchPrefix) {
		return true // lines of a real file: any text
	}
	if isVersionFact(name) && t == TString {
		return versionLitRe.MatchString(lit) || contains(versionPool, lit)
	}
	if lit == "" || numLitRe.MatchString(lit) {
		return true
	}
	switch t {
	case TStringList:
		return contains(listPools[name], lit) || relatedToPackage(words, lit)
	case TStringMap, TMapOfList:
		return contains(valuePool, lit) || contains(directivePool, lit) || relatedToPackage(words, lit) || substringOfPool(lit)
	case TObjectList:
		return contains(servicePool, lit) || contains(objectPool, lit) || relatedToPackage(words, lit)
	}
	return false
}

var objectPool = []string{"tcp", "udp", "tcp6", "udp6", "0.0.0.0", "127.0.0.1", "::", "::1", "[::]:22", "22/tcp", "80/tcp", "443/tcp", "latest"}

// realisticHints filters the literals collected around fact name down to realistic ones. ungrounded
// is true when name is enumerable and the expression compares it with a value outside the set.
func realisticHints(name string, h *hints, words []string) (out *hints, ungrounded bool) {
	out = &hints{}
	if h == nil {
		return out, false
	}
	t, _ := FactTypeOf(name)
	_, enum := enumSets[name]
	for _, s := range h.strs {
		switch {
		case realisticStr(name, t, s, words):
			out.addStr(s)
		case enum && partOfEnum(name, s):
			// a prefix/substring test such as startsWith("deb"): not a candidate, not a violation
		case enum:
			return out, true
		}
	}
	for _, n := range h.ints {
		if n >= 0 && n <= 65535 {
			out.addInt(n)
		}
	}
	return out, false
}

func strListOf(v []string) []any {
	out := make([]any, len(v))
	for i, s := range v {
		out[i] = s
	}
	return out
}

func partOfEnum(name, lit string) bool {
	if len(lit) < 2 {
		return false
	}
	for _, v := range enumSets[name] {
		if strings.Contains(v, lit) {
			return true
		}
	}
	return false
}

// substringOfPool accepts fragments of realistic config values, as used with contains/startsWith.
func substringOfPool(lit string) bool {
	if len(lit) < 4 {
		return false
	}
	for _, v := range valuePool {
		if strings.Contains(v, lit) {
			return true
		}
	}
	for _, v := range directivePool {
		if strings.Contains(v, lit) {
			return true
		}
	}
	return false
}
