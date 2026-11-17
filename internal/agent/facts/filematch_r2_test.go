package facts

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"testing/fstest"
)

// Values that must be masked: the output keeps the key and replaces the value by ***.
func TestMaskSecretsMustMask(t *testing.T) {
	tests := []struct{ in, want string }{
		{"DB_PASS=x", "DB_PASS=***"},
		{"MYSQL_PASS=x", "MYSQL_PASS=***"},
		{"SMTP_PASS x", "SMTP_PASS ***"},
		{"user_pass=x", "user_pass=***"},
		{"dbpass=x", "dbpass=***"},
		{"bindpw x", "bindpw ***"},
		{"ldap_bind_pw=x", "ldap_bind_pw=***"},
		{"pw=x", "pw=***"},
		{"encryption_key=x", "encryption_key=***"},
		{"cookie_key = x", "cookie_key = ***"},
		{"key=shortkey", "key=***"},
		{"password_hash=x", "password_hash=***"},
		{"snmp community x", "snmp community ***"},
		{"community = x", "community = ***"},
		{"rocommunity public", "rocommunity ***"},
		{"Bearer abc.def", "Bearer ***"},
		{"curl -H 'X: y' Bearer abc.def", "curl -H 'X: y' Bearer ***"},
		{"Authorization: Bearer abc", "Authorization: ***"},
		{"app_secret: s3", "app_secret: ***"},
		{"api_token = t", "api_token = ***"},
		{"db_pwd=p", "db_pwd=***"},
		{"wifi_psk wpa", "wifi_psk ***"},
		{"aws_credentials = c", "aws_credentials = ***"},
		{"credential x", "credential ***"},
		{`"client_secret": "abc"`, `"client_secret": ***`},
		{"'token': 'abc'", "'token': ***"},
		{"MY_AUTH tok", "MY_AUTH ***"},
		{"set $token abc", "set $token ***"},
		{"url = https://h/p?token=abc&x=1", "url = https://h/p?token=***"},
		{"x_key: 1234abcd", "x_key: ***"},
		{"pass=12345", "pass=***"},
		{"password 123456", "password ***"},
		{"requirepass redis", "requirepass ***"},
		{"dsn = postgres://u:p@h/db", "dsn = postgres://***@h/db"},
		{"sessionKey   abc", "sessionKey   ***"},
	}
	for _, tc := range tests {
		if got := maskSecrets(tc.in); got != tc.want {
			t.Errorf("maskSecrets(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// Settings that merely contain a keyword must stay visible.
func TestMaskSecretsMustNotMask(t *testing.T) {
	for _, in := range []string{
		"proxy_pass http://x",
		"proxy_pass http://127.0.0.1:8080;",
		"fastcgi_pass unix:/run/php/php-fpm.sock;",
		"passenger_enabled on",
		"passenger_max_pool_size 6",
		"keepalive_timeout 65",
		"ssl_session_tickets off",
		"auth_basic off",
		`auth_basic "Restricted"`,
		"auth_request /auth;",
		"PasswordAuthentication yes",
		"PasswordAuthentication no",
		"PermitRootLogin prohibit-password",
		"PermitEmptyPasswords no",
		"key_buffer_size 16M",
		"key_buffer_size = 128M",
		"max_pass_attempts 3",
		"password_min_length 8",
		"auth_delay 2",
		"ssl_certificate_key /etc/ssl/x.key",
		"ssl_password_file /etc/nginx/pw",
		"auth_basic_user_file /etc/nginx/htpasswd",
		"AuthorizedKeysFile .ssh/authorized_keys",
		"proxy_cache_key $scheme$host$request_uri;",
		"StrictHostKeyChecking no",
		"root /var/www/html/site;",
		"listen 443 ssl;",
		"server_name example.com;",
		"worker_processes auto;",
		"include /etc/nginx/conf.d/auth.conf;",
		"keep_alive on",
	} {
		if got := maskSecrets(in); got != in {
			t.Errorf("maskSecrets(%q) = %q, must stay visible", in, got)
		}
	}
}

// The pattern is matched against the masked text, so it cannot probe secret values.
func TestFileMatchSecretOracleClosed(t *testing.T) {
	m := fstest.MapFS{"etc/app.conf": {Data: []byte("db_password = hunter2\nname = demo\ncrypt:$6$abc$def\n"), Mode: 0o644}}
	env := &Env{FS: linkMapFS{m}}
	for _, p := range []string{`^db_password = h`, `^db_password = hunter2`, `hunter`, `\$6\$`, `^db_password = [a-z]`} {
		if got, ok := evalFileMatch(t.Context(), env, fmReq("/etc/app.conf", p)); ok && len(got) != 0 {
			t.Errorf("pattern %q matched secret text: %v", p, got)
		}
	}
	got, ok := evalFileMatch(t.Context(), env, fmReq("/etc/app.conf", `^db_password = \*\*\*$`))
	if !ok || !reflect.DeepEqual(got, []string{"/etc/app.conf:db_password = ***"}) {
		t.Errorf("masked match = %v ok=%v", got, ok)
	}
}

func TestFileMatchSniffsWholeFile(t *testing.T) {
	pad := strings.Repeat("x\n", 40<<10) // 80 KiB of clean lines before the marker
	m := fstest.MapFS{
		"etc/pem.conf": {Data: []byte("hit\n" + pad + "-----BEGIN PRIVATE KEY-----\n"), Mode: 0o644},
		"etc/nul.conf": {Data: []byte("hit\n" + pad + "a\x00b\n"), Mode: 0o644},
		"etc/ok.conf":  {Data: []byte("hit\n" + pad), Mode: 0o644},
	}
	got, ok := evalFileMatch(t.Context(), &Env{FS: linkMapFS{m}}, fmReq("/etc/*.conf", "hit"))
	if !ok || !reflect.DeepEqual(got, []string{"/etc/ok.conf:hit"}) {
		t.Errorf("got %v ok=%v", got, ok)
	}
}

func TestFileMatchLongLinesCapped(t *testing.T) {
	line := strings.Repeat("a ", 3000) + "late-marker password = hunter2"
	m := fstest.MapFS{"etc/l.conf": {Data: []byte(line + "\nshort hit\n"), Mode: 0o644}}
	env := &Env{FS: linkMapFS{m}}
	if got, _ := evalFileMatch(t.Context(), env, fmReq("/etc/l.conf", "late-marker")); len(got) != 0 {
		t.Errorf("text beyond 4 KiB was matched: %v", got)
	}
	if got, ok := evalFileMatch(t.Context(), env, fmReq("/etc/l.conf", "short hit")); !ok || len(got) != 1 {
		t.Errorf("got %v ok=%v", got, ok)
	}
}

func TestCompilePatternLimits(t *testing.T) {
	bad := []string{
		`a{101}`, `(a{50}){50}`, `a{1,101}`, `(a{100}){100}`, `((a{10}){10}){10}`,
		strings.Repeat("(a|b|c)", 800), `[a-z]{5}` + strings.Repeat("x?", 2100),
	}
	for _, p := range bad {
		if _, err := compilePattern(p); err == nil {
			t.Errorf("pattern %.40q accepted", p)
		}
	}
	for _, p := range []string{`^listen\s+(443|8443)\b`, `a{100}`, `^\s*server_name\s+.*;`, `(?i)password`, `a{2,5}b+`} {
		if _, err := compilePattern(p); err != nil {
			t.Errorf("pattern %q rejected: %v", p, err)
		}
	}
}

func TestFileMatchRequiresTraversableAncestors(t *testing.T) {
	m := linkMapFS{fstest.MapFS{
		"etc/closed":           {Mode: fs.ModeDir | 0o700},
		"etc/closed/a.conf":    {Data: []byte("hit\n"), Mode: 0o644},
		"etc/group":            {Mode: fs.ModeDir | 0o750},
		"etc/group/a.conf":     {Data: []byte("hit\n"), Mode: 0o644},
		"etc/open":             {Mode: fs.ModeDir | 0o755},
		"etc/open/a.conf":      {Data: []byte("hit\n"), Mode: 0o644},
		"etc/open/sub":         {Mode: fs.ModeDir | 0o711},
		"etc/open/sub/b.conf":  {Data: []byte("hit\n"), Mode: 0o644},
		"etc/open/sub2":        {Mode: fs.ModeDir | 0o700},
		"etc/open/sub2/c.conf": {Data: []byte("hit\n"), Mode: 0o644},
	}}
	env := &Env{FS: m}
	for p, want := range map[string]bool{
		"/etc/closed/a.conf": false, "/etc/group/a.conf": false, "/etc/open/a.conf": true,
		"/etc/open/sub/b.conf": true, "/etc/open/sub2/c.conf": false,
	} {
		_, ok := evalFileMatch(t.Context(), env, fmReq(p, "hit"))
		if ok != want {
			t.Errorf("%s: ok=%v, want %v", p, ok, want)
		}
	}
}

func TestBinaryTrustChecksEveryAncestor(t *testing.T) {
	top := t.TempDir()
	mid := filepath.Join(top, "a", "b")
	if err := os.MkdirAll(mid, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(mid, "tool")
	os.WriteFile(bin, nil, 0o755)
	os.Chmod(bin, 0o755)
	for _, d := range []string{top, filepath.Join(top, "a"), mid} {
		os.Chmod(d, 0o755)
	}
	if runtime.GOOS != "linux" || ownerIsRoot() {
		if err := binaryTrustAbove(bin, top); err != nil {
			t.Fatalf("trusted tree rejected: %v", err)
		}
	}
	// the grandparent is writable: the immediate parent looks fine but the chain is not
	os.Chmod(filepath.Join(top, "a"), 0o775)
	if err := binaryTrustAbove(bin, top); err == nil {
		t.Error("group-writable grandparent accepted")
	}
	os.Chmod(filepath.Join(top, "a"), 0o755)
	os.Chmod(top, 0o777)
	if err := binaryTrustAbove(bin, top); err == nil {
		t.Error("world-writable top accepted")
	}
}

func TestNginxSupportsErrorLogFlag(t *testing.T) {
	for v, want := range map[string]bool{"1.19.4": false, "1.19.5": true, "1.18.0": false, "1.24.0": true, "1.9.15": false,
		"2.0.0": true, "1.27.1": true, "1.20.1": true, "garbage": false, "1.24": false} {
		if got := nginxSupportsErrorLogFlag(v); got != want {
			t.Errorf("%s: %v, want %v", v, got, want)
		}
	}
}

func nginxIncludeFS() linkMapFS {
	return linkMapFS{fstest.MapFS{
		"etc/nginx/nginx.conf": {Data: []byte(`
events {}
http {
  include mime.types;
  include /etc/nginx/conf.d/*.conf;
  include "/usr/share/nginx/modules/*.conf"; # comment
  # include /evil/commented.conf;
  load_module modules/ngx_x.so;
}`), Mode: 0o644},
		"etc/nginx/mime.types":      {Data: []byte("types { text/html html; }"), Mode: 0o644},
		"etc/nginx/conf.d/a.conf":   {Data: []byte("include /srv/extra/*.conf;\nload_module /opt/mod/y.so;\n"), Mode: 0o644},
		"srv/extra/z.conf":          {Data: []byte("include /var/more/q.conf;\n"), Mode: 0o644},
		"etc/nginx/conf.d/b.conf":   {Data: []byte("server { include snippets/s.conf; }\n"), Mode: 0o644},
		"etc/nginx/snippets/s.conf": {Data: []byte("# nothing\n"), Mode: 0o644},
	}}
}

func TestNginxExternalLocations(t *testing.T) {
	got, err := nginxExternalLocations(nginxIncludeFS())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/opt/mod/y.so", "/srv/extra/*.conf", "/usr/share/nginx/modules/*.conf", "/var/more/q.conf",
		"/usr/share/nginx/modules/ngx_x.so", "/usr/lib/nginx/modules/ngx_x.so", "/usr/local/nginx/modules/ngx_x.so"}
	have := map[string]bool{}
	for _, g := range got {
		have[g] = true
	}
	for _, w := range want {
		if !have[w] {
			t.Errorf("missing external location %s in %v", w, got)
		}
	}
	for _, g := range got {
		if strings.HasPrefix(g, "/etc/nginx") || strings.Contains(g, "evil") {
			t.Errorf("unexpected location %s", g)
		}
	}
}

func TestNginxIncludeOutsideRootsMustBeTrusted(t *testing.T) {
	var ran []string
	runner := recordingRunner{ran: &ran, out: map[string]string{
		"nginx -v":                 "nginx version: nginx/1.24.0\n",
		"nginx -V":                 "nginx version: nginx/1.24.0\nconfigure arguments: --with-http_ssl_module\n",
		"nginx -T -q -e /dev/null": "http { http2 on; }\n",
	}}
	env := &Env{Runner: runner, FS: nginxIncludeFS(), TreeTrust: func(roots []string) error {
		for _, r := range roots {
			if r == "/srv/extra/*.conf" {
				return fmt.Errorf("%s writable by gid 100", r)
			}
		}
		return nil
	}}
	f := collectNginx(t.Context(), env)
	if _, ok := f["nginx.directives"]; ok {
		t.Error("nginx -T ran although an include location is untrusted")
	}
	for _, c := range ran {
		if strings.HasPrefix(c, "nginx -T") {
			t.Errorf("ran %q", c)
		}
	}
	if sk := env.skipped(); len(sk) != 1 || !strings.Contains(sk[0], "/srv/extra/*.conf") {
		t.Errorf("skipped = %v", sk)
	}
	if f["nginx.modules"] == nil {
		t.Error("nginx -V should still run (config not loaded)")
	}

	// all trusted: -T runs with the quiet flags
	ran = nil
	var checked []string
	env = &Env{Runner: runner, FS: nginxIncludeFS(), TreeTrust: func(roots []string) error { checked = append(checked, roots...); return nil }}
	f = collectNginx(t.Context(), env)
	if _, ok := f["nginx.directives"]; !ok {
		t.Errorf("nginx.directives missing; ran %v", ran)
	}
	if !reflect.DeepEqual(ran[len(ran)-1:], []string{"nginx -T -q -e /dev/null"}) {
		t.Errorf("ran %v", ran)
	}
	found := false
	for _, c := range checked {
		found = found || c == "/usr/share/nginx/modules/*.conf"
	}
	if !found {
		t.Errorf("external include not verified: %v", checked)
	}
}

func TestNginxIncludeScanBounded(t *testing.T) {
	m := fstest.MapFS{"etc/nginx/nginx.conf": {Data: []byte("include conf.d/*.conf;\n"), Mode: 0o644}}
	for i := 0; i < nginxIncMaxFiles+20; i++ {
		m[fmt.Sprintf("etc/nginx/conf.d/f%03d.conf", i)] = &fstest.MapFile{Data: []byte("# x\n"), Mode: 0o644}
	}
	if _, err := nginxExternalLocations(linkMapFS{m}); err == nil {
		t.Error("oversized include tree must fail closed")
	}
}

func TestApacheAndSudoRequireTrustedTrees(t *testing.T) {
	var ran []string
	runner := recordingRunner{ran: &ran, out: map[string]string{"apachectl -v": "Server version: Apache/2.4.58\n", "sudo -V": "Sudo version 1.9.15\n"}}
	var asked [][]string
	env := &Env{Runner: runner, FS: fstest.MapFS{}, TreeTrust: func(roots []string) error {
		asked = append(asked, roots)
		return fmt.Errorf("%s untrusted", roots[0])
	}}
	if f := collectApache(t.Context(), env); len(f) != 0 {
		t.Errorf("apache facts = %v", f)
	}
	if f := collectSudo(t.Context(), env); len(f) != 0 {
		t.Errorf("sudo facts = %v", f)
	}
	if len(ran) != 0 {
		t.Errorf("commands ran from untrusted trees: %v", ran)
	}
	wantApache := []string{"/etc/apache2", "/etc/httpd", "/usr/local/apache2/conf", "/usr/local/etc/apache24"}
	if len(asked) != 2 || !reflect.DeepEqual(asked[0], wantApache) || !reflect.DeepEqual(asked[1], []string{"/etc/sudo.conf"}) {
		t.Errorf("trust checks = %v", asked)
	}
	if sk := env.skipped(); len(sk) != 2 {
		t.Errorf("skipped = %v", sk)
	}
}
