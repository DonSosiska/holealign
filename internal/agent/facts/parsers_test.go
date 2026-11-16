package facts

import (
	"os"
	"reflect"
	"testing"
	"testing/fstest"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

func TestParseSSHDConfig(t *testing.T) {
	cfg := parseSSHDConfig(fixture(t, "sshd_T.txt"))
	tests := []struct {
		key, want string
	}{
		{"logingracetime", "120"},
		{"permitrootlogin", "without-password"},
		{"passwordauthentication", "no"},
		{"port", "22"},
		{"subsystem", "sftp /usr/lib/openssh/sftp-server"},
	}
	for _, tc := range tests {
		if got := cfg[tc.key]; got != tc.want {
			t.Errorf("sshd.config[%q] = %q, want %q", tc.key, got, tc.want)
		}
	}
	if _, ok := cfg["LoginGraceTime"]; ok {
		t.Error("keys must be lowercased")
	}
}

func TestParseOpenSSHVersion(t *testing.T) {
	tests := map[string]string{
		"OpenSSH_9.6p1 Ubuntu-3ubuntu13.5, OpenSSL 3.0.13 30 Jan 2024\n": "9.6p1 Ubuntu-3ubuntu13.5",
		"OpenSSH_8.7p1, OpenSSL 3.0.7\n":                                 "8.7p1",
		"garbage":                                                        "",
	}
	for in, want := range tests {
		if got := parseOpenSSHVersion([]byte(in)); got != want {
			t.Errorf("parseOpenSSHVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseNginxDirectives(t *testing.T) {
	dirs := parseNginxDirectives(fixture(t, "nginx_T_http2_on.txt"))
	tests := []struct {
		name string
		want []string
	}{
		{"http2", []string{"on"}},                         // "# http2 off;" is a comment
		{"proxy_pass", []string{"http://127.0.0.1:8080"}}, // inside a nested block
		{"server_name", []string{"_"}},
		{"add_header", []string{`X-Note ok; not a directive`}}, // quoted ';' is not a separator
		{"sendfile", []string{"on"}},
	}
	for _, tc := range tests {
		if got := dirs[tc.name]; !reflect.DeepEqual(got, tc.want) {
			t.Errorf("directive %s = %q, want %q", tc.name, got, tc.want)
		}
	}
	if _, ok := dirs["nginx:"]; ok {
		t.Error("nginx status lines must be ignored")
	}
	if _, ok := dirs["configuration"]; ok {
		t.Error("nginx status lines must be ignored")
	}
}

func TestNginxHTTP2(t *testing.T) {
	tests := []struct {
		name string
		conf string
		want bool
	}{
		{"http2 on directive", "", true},
		{"listen with http2 flag", "listen 443 ssl http2;", true},
		{"http2 off", "http2 off;", false},
		{"listen without flag", "listen 443 ssl;", false},
		{"commented out", "# listen 443 ssl http2;", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var data []byte
			if tc.conf == "" {
				data = fixture(t, "nginx_T_http2_on.txt")
			} else {
				data = []byte(tc.conf + "\n")
			}
			if got := nginxHTTP2(parseNginxDirectives(data)); got != tc.want {
				t.Errorf("nginxHTTP2 = %v, want %v", got, tc.want)
			}
		})
	}

	listen := parseNginxDirectives(fixture(t, "nginx_T_listen_http2.txt"))
	if !nginxHTTP2(listen) {
		t.Error("listen ... http2 fixture should report http2")
	}
	if got := listen["server_name"]; !reflect.DeepEqual(got, []string{"example.com www.example.com"}) {
		t.Errorf("server_name = %q", got)
	}
}

func TestParseNginxModules(t *testing.T) {
	mods := parseNginxModules(fixture(t, "nginx_V.txt"))
	for _, want := range []string{"http_v2_module", "http_ssl_module", "threads", "file-aio", "stream_ssl_preread_module"} {
		if !contains(mods, want) {
			t.Errorf("modules %v missing %q", mods, want)
		}
	}
	for _, bad := range []string{"cc-opt", "ld-opt", "autoindex_module", "prefix"} {
		if contains(mods, bad) {
			t.Errorf("modules %v must not contain %q", mods, bad)
		}
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func TestParseApacheModules(t *testing.T) {
	mods := parseApacheModules(fixture(t, "apachectl_M.txt"))
	for _, want := range []string{"http2_module", "proxy_module", "core_module"} {
		if !contains(mods, want) {
			t.Errorf("modules missing %q: %v", want, mods)
		}
	}
	if contains(mods, "Loaded") {
		t.Error("header line must not be parsed as a module")
	}
}

func TestApacheProtocolsH2(t *testing.T) {
	tests := []struct {
		name string
		text string
		want bool
	}{
		{"h2 enabled", "Protocols h2 http/1.1\n", true},
		{"h2c enabled", "Protocols h2c\n", true},
		{"http/1.1 only", "Protocols http/1.1\n", false},
		{"commented", "# Protocols h2 http/1.1\n", false},
		{"no directive", "ServerName x\n", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := protocolsEnableH2(tc.text); got != tc.want {
				t.Errorf("protocolsEnableH2 = %v, want %v", got, tc.want)
			}
		})
	}

	withFixture := fstest.MapFS{"etc/apache2/apache2.conf": {Data: fixture(t, "apache2_protocols.conf")}}
	if !apacheConfigEnablesH2(withFixture) {
		t.Error("apache config with Protocols h2 should enable http2")
	}
	commentedOnly := fstest.MapFS{"etc/httpd/conf/httpd.conf": {Data: []byte("# Protocols h2\n")}}
	if apacheConfigEnablesH2(commentedOnly) {
		t.Error("commented Protocols must not enable http2")
	}
}

func TestParsePHP(t *testing.T) {
	if got := parsePHPVersion(fixture(t, "php_v.txt")); got != "8.2.7" {
		t.Errorf("php version = %q", got)
	}
	ini := parsePHPIni(fixture(t, "php_i.txt"))
	want := map[string]string{
		"allow_url_fopen":   "On",
		"allow_url_include": "Off",
		"cgi.fix_pathinfo":  "1",
		"disable_functions": "",
		"expose_php":        "On",
		"open_basedir":      "/var/www/html:/tmp",
	}
	if !reflect.DeepEqual(ini, want) {
		t.Errorf("php.ini = %v\nwant %v", ini, want)
	}
}

func TestParseOSRelease(t *testing.T) {
	tests := []struct {
		file, id, version string
	}{
		{"os-release-debian.txt", "debian", "12"},
		{"os-release-alpine.txt", "alpine", "3.20.0"},
	}
	for _, tc := range tests {
		kv := parseOSRelease(fixture(t, tc.file))
		if kv["ID"] != tc.id || kv["VERSION_ID"] != tc.version {
			t.Errorf("%s: ID=%q VERSION_ID=%q, want %q %q", tc.file, kv["ID"], kv["VERSION_ID"], tc.id, tc.version)
		}
	}
}

func TestParseLddVersion(t *testing.T) {
	tests := []struct {
		name, file, libc, version string
		ok                        bool
	}{
		{"glibc", "ldd_glibc.txt", "glibc", "2.36", true},
		{"musl", "ldd_musl.txt", "musl", "1.2.4", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			libc, ver, ok := parseLddVersion(fixture(t, tc.file))
			if libc != tc.libc || ver != tc.version || ok != tc.ok {
				t.Errorf("got (%q, %q, %v), want (%q, %q, %v)", libc, ver, ok, tc.libc, tc.version, tc.ok)
			}
		})
	}
	if _, _, ok := parseLddVersion([]byte("bash: ldd: command not found\n")); ok {
		t.Error("unrelated output must not be detected as a libc")
	}
}

func TestParseVersionLines(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"openssl", parseOpenSSLVersion([]byte("OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)\n")), "3.0.13"},
		{"runc", parseRuncVersion([]byte("runc version 1.1.12\ncommit: v1.1.12-0-g51d5e94\n")), "1.1.12"},
		{"sudo", parseSudoVersion([]byte("Sudo version 1.9.15p5\nSudoers policy plugin version 1.9.15p5\n")), "1.9.15p5"},
		{"php", parsePHPVersion([]byte("PHP 8.2.7 (cli) (built: Jun  5 2024)\n")), "8.2.7"},
		{"nginx", nginxVersionOf([]byte("nginx version: nginx/1.24.0 (Ubuntu)\n")), "1.24.0"},
		{"missing", parseRuncVersion([]byte("usage: runc")), ""},
	}
	for _, tc := range tests {
		if tc.got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, tc.got, tc.want)
		}
	}
}

func nginxVersionOf(out []byte) string {
	if m := reNginxVersion.FindSubmatch(out); m != nil {
		return string(m[1])
	}
	return ""
}

func TestParseSystemctl(t *testing.T) {
	out := []byte(`ssh.service loaded active running OpenBSD Secure Shell server
● foo.service loaded active running Foo
cron.service loaded active running Regular background program processing daemon
dbus.socket loaded active running D-Bus Socket
`)
	got := parseSystemctl(out)
	want := []string{"ssh", "foo", "cron"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("services = %v, want %v", got, want)
	}
}

func TestParseModules(t *testing.T) {
	got := parseModules(fixture(t, "proc_modules.txt"))
	want := []string{"nf_tables", "nft_compat", "overlay", "veth"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("modules = %v, want %v", got, want)
	}
}

func TestDecodeProcAddr(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"0100007F", "127.0.0.1"},
		{"00000000", "0.0.0.0"},
		{"00000000000000000000000001000000", "::1"},
		{"00000000000000000000000000000000", "::"},
	}
	for _, tc := range tests {
		ip, err := decodeProcAddr(tc.in)
		if err != nil || ip.String() != tc.want {
			t.Errorf("decodeProcAddr(%s) = %v, %v; want %s", tc.in, ip, err, tc.want)
		}
	}
	if _, err := decodeProcAddr("0102"); err == nil {
		t.Error("expected error for bad length")
	}
}

func TestParseProcNet(t *testing.T) {
	type row struct {
		addr  string
		port  int
		inode uint64
	}
	tests := []struct {
		name  string
		file  string
		proto string
		want  []row
	}{
		{"tcp listen only", "proc_net_tcp.txt", "tcp", []row{
			{"0.0.0.0", 22, 10234},
			{"127.0.0.1", 8080, 22345},
			{"0.0.0.0", 443, 44444},
		}},
		{"tcp6 listen only", "proc_net_tcp6.txt", "tcp6", []row{
			{"::", 80, 55555},
			{"::1", 22, 66666},
		}},
		{"udp unconnected only", "proc_net_udp.txt", "udp", []row{
			{"0.0.0.0", 68, 88888},
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			entries := parseProcNet(fixture(t, tc.file), tc.proto)
			var got []row
			for _, e := range entries {
				got = append(got, row{e.addr, e.port, e.inode})
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMapInodesToProcesses(t *testing.T) {
	fsys := linkMapFS{fstest.MapFS{
		"proc/1234/comm": {Data: []byte("nginx\n")},
		"proc/1234/fd/3": {Data: []byte("socket:[22345]"), Mode: 0o777 | modeSymlink},
		"proc/1234/fd/4": {Data: []byte("pipe:[9]"), Mode: 0o777 | modeSymlink},
		"proc/777/comm":  {Data: []byte("sshd\n")},
		"proc/777/fd/4":  {Data: []byte("socket:[10234]"), Mode: 0o777 | modeSymlink},
		"proc/net/tcp":   {Data: []byte("")},
		"proc/self/comm": {Data: []byte("ignored\n")},
	}}
	got := mapInodesToProcesses(fsys, map[uint64]bool{22345: true, 10234: true, 99: true})
	want := map[uint64]string{22345: "nginx", 10234: "sshd"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("inode map = %v, want %v", got, want)
	}
}

func TestCollectSocketsEndToEnd(t *testing.T) {
	fsys := linkMapFS{fstest.MapFS{
		"proc/net/tcp":   {Data: fixture(t, "proc_net_tcp.txt")},
		"proc/net/tcp6":  {Data: fixture(t, "proc_net_tcp6.txt")},
		"proc/net/udp":   {Data: fixture(t, "proc_net_udp.txt")},
		"proc/777/comm":  {Data: []byte("sshd\n")},
		"proc/777/fd/3":  {Data: []byte("socket:[10234]"), Mode: 0o777 | modeSymlink},
		"proc/1234/comm": {Data: []byte("nginx\n")},
		"proc/1234/fd/3": {Data: []byte("socket:[22345]"), Mode: 0o777 | modeSymlink},
	}}
	f := collectSockets(t.Context(), &Env{FS: fsys})
	ports, ok := f["sockets.ports"].([]int)
	if !ok || !reflect.DeepEqual(ports, []int{22, 68, 80, 443, 8080}) {
		t.Errorf("sockets.ports = %v", f["sockets.ports"])
	}
	listening, ok := f["sockets.listening"].([]map[string]any)
	if !ok {
		t.Fatalf("sockets.listening has type %T", f["sockets.listening"])
	}
	procByPort := map[int]string{}
	for _, l := range listening {
		procByPort[l["port"].(int)] = l["process"].(string)
	}
	if procByPort[8080] != "nginx" {
		t.Errorf("port 8080 owner = %q, want nginx", procByPort[8080])
	}
	if procByPort[443] != "" {
		t.Errorf("unknown owner should be empty, got %q", procByPort[443])
	}
}
