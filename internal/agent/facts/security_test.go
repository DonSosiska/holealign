package facts

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"panoptes/internal/model"
)

func fmReq(path, pattern string) model.FactRequest {
	return model.FactRequest{Name: "file.match:t", Collector: "file.match",
		Params: map[string]string{"path": path, "pattern": pattern}}
}

func TestFileMatchDenylist(t *testing.T) {
	denied := []string{
		"/etc/shadow", "/etc/shadow-", "/etc/gshadow", "/etc/passwd-", "/etc/sudoers", "/etc/sudoers.d/x",
		"/etc/ssh/ssh_host_ed25519_key", "/etc/ssl/private/a.conf", "/etc/letsencrypt/x.conf", "/etc/pki/x",
		"/etc/panoptes/agent.yaml", "/etc/krb5.keytab", "/etc/x/a.KEY", "/etc/x/a.pem", "/etc/x/a.p12",
		"/etc/x/a.pfx", "/etc/x/a.jks", "/etc/x/a.keystore", "/etc/apache2/.htpasswd", "/etc/x/my-Secret.conf",
		"/etc/x/credentials", "/etc/x/api_token.conf", "/etc/NetworkManager/system-connections/a",
		"/etc/wireguard/wg0.conf", "/etc/openvpn/c.conf", "/etc/ppp/chap-secrets", "/etc/security/limits.conf",
		"/etc/polkit-1/x", "/etc/ipsec.conf", "/etc/strongswan.conf", "/etc/cloud/cloud.cfg",
		"/etc/mysql/debian.cnf", "/opt/app/conf/prod.env", "/opt/app/conf/.env",
	}
	for _, p := range denied {
		if !fmDenied(p) {
			t.Errorf("%s should be denied", p)
		}
	}
	for _, p := range []string{"/etc/nginx/nginx.conf", "/etc/ssh/sshd_config", "/etc/mysql/my.cnf", "/opt/app/conf/app.yml", "/etc/hosts"} {
		if fmDenied(p) {
			t.Errorf("%s should be allowed", p)
		}
	}
}

func TestFileMatchDeniedFilesNeverRead(t *testing.T) {
	m := fstest.MapFS{
		"etc/shadow":           {Data: []byte("root:$6$abc$def:19000::\n"), Mode: 0o644},
		"etc/ssh/ssh_host_rsa": {Data: []byte("x"), Mode: 0o644},
		"etc/app/token.conf":   {Data: []byte("x"), Mode: 0o644},
		"etc/to-shadow":        {Data: []byte("shadow"), Mode: 0o777 | modeSymlink},
		"etc/nginx/nginx.conf": {Data: []byte("worker 1\n"), Mode: 0o644},
	}
	env := &Env{FS: linkMapFS{m}}
	for _, p := range []string{"/etc/shadow", "/etc/ssh/ssh_host_rsa", "/etc/app/token.conf", "/etc/to-shadow"} {
		if got, ok := evalFileMatch(t.Context(), env, fmReq(p, ".")); ok {
			t.Errorf("%s: read despite denylist: %v", p, got)
		}
	}
	// a glob over a mixed directory silently skips denied entries
	got, ok := evalFileMatch(t.Context(), env, fmReq("/etc/*/*", "."))
	if !ok || !reflect.DeepEqual(got, []string{"/etc/nginx/nginx.conf:worker 1"}) {
		t.Errorf("glob result = %v ok=%v", got, ok)
	}
}

func TestFileMatchRequiresWorldReadable(t *testing.T) {
	m := fstest.MapFS{
		"etc/private.conf": {Data: []byte("hit\n"), Mode: 0o600},
		"etc/group.conf":   {Data: []byte("hit\n"), Mode: 0o640},
		"etc/public.conf":  {Data: []byte("hit\n"), Mode: 0o644},
	}
	env := &Env{FS: linkMapFS{m}}
	for _, p := range []string{"/etc/private.conf", "/etc/group.conf"} {
		if got, ok := evalFileMatch(t.Context(), env, fmReq(p, "hit")); ok {
			t.Errorf("%s read although not world-readable: %v", p, got)
		}
	}
	if _, ok := evalFileMatch(t.Context(), env, fmReq("/etc/public.conf", "hit")); !ok {
		t.Error("world-readable file must be read")
	}
}

func TestFileMatchSkipsKeyMaterialAndBinary(t *testing.T) {
	m := fstest.MapFS{
		"etc/a.conf": {Data: []byte("hit\n-----BEGIN RSA PRIVATE KEY-----\nzzz\n"), Mode: 0o644},
		"etc/b.conf": {Data: []byte("hit\x00binary\n"), Mode: 0o644},
		"etc/c.conf": {Data: []byte("hit\n"), Mode: 0o644},
	}
	env := &Env{FS: linkMapFS{m}}
	got, ok := evalFileMatch(t.Context(), env, fmReq("/etc/*.conf", "hit"))
	if !ok || !reflect.DeepEqual(got, []string{"/etc/c.conf:hit"}) {
		t.Errorf("got %v ok=%v", got, ok)
	}
}

func TestMaskSecretsTable(t *testing.T) {
	long := "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
	tests := map[string]string{
		`"password": "x"`:                  `"password": ***`,
		`{"db_password":"hunter2"}`:        `{"db_password":***`,
		"passwd=x":                         "passwd=***",
		"requirepass x":                    "requirepass ***",
		"masterauth y":                     "masterauth ***",
		"Authorization: Bearer abc":        "Authorization: ***",
		"psk = abcd":                       "psk = ***",
		"api_key: k":                       "api_key: ***",
		"postgres://u:pw@h/db":             "postgres://***@h/db",
		"dsn = mysql://root:s3@db:3306/x":  "dsn = mysql://***@db:3306/x",
		"x " + long + " y":                 "x *** y",
		"proxy_pass http://upstream:8080;": "proxy_pass http://upstream:8080;",
		"ssl_certificate_key /etc/x.k":     "ssl_certificate_key /etc/x.k",
		"pass: s":                          "pass: ***",
		"root /var/www/html/site;":         "root /var/www/html/site;",
	}
	for in, want := range tests {
		if got := maskSecrets(in); got != want {
			t.Errorf("maskSecrets(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFileMatchDropsCryptHashLines(t *testing.T) {
	m := fstest.MapFS{
		"etc/users.txt": {Data: []byte("alice:$6$salt$hashhashhash:1\nbob:x:1000\n"), Mode: 0o644},
	}
	got, ok := evalFileMatch(t.Context(), &Env{FS: linkMapFS{m}}, fmReq("/etc/users.txt", "."))
	if !ok || !reflect.DeepEqual(got, []string{"/etc/users.txt:bob:x:1000"}) {
		t.Errorf("got %v ok=%v", got, ok)
	}
	if !isCryptLine("root:$y$j9T$abc") || isCryptLine("a:b:$6$") {
		t.Error("isCryptLine wrong")
	}
}

func TestFileMatchLineTruncated(t *testing.T) {
	long := "hit " + strings.Repeat("a b ", 600)
	m := fstest.MapFS{"etc/l.conf": {Data: []byte(long + "\n"), Mode: 0o644}}
	got, ok := evalFileMatch(t.Context(), &Env{FS: linkMapFS{m}}, fmReq("/etc/l.conf", "hit"))
	if !ok || len(got) != 1 {
		t.Fatalf("got %v", got)
	}
	if n := len(strings.TrimPrefix(got[0], "/etc/l.conf:")); n > fmLineBytes {
		t.Errorf("line is %d bytes, want <= %d", n, fmLineBytes)
	}
}

func TestFileMatchBudgets(t *testing.T) {
	m := fstest.MapFS{"etc/h.conf": {Data: []byte(strings.Repeat("hit\n", 100)), Mode: 0o644}}
	env := &Env{FS: linkMapFS{m}}

	// byte budget: only the first 40 bytes are readable -> 10 lines
	b := &fmBudget{bytesLeft: 40, linesLeft: 500}
	got, ok := evalFileMatchB(t.Context(), env, fmReq("/etc/h.conf", "hit"), b)
	if !ok || len(got) != 10 || b.bytesLeft != 0 {
		t.Errorf("byte budget: %d lines ok=%v left=%d", len(got), ok, b.bytesLeft)
	}
	// budget exhausted: next request is unknown
	if _, ok := evalFileMatchB(t.Context(), env, fmReq("/etc/h.conf", "hit"), b); ok {
		t.Error("request after exhausted byte budget must be omitted")
	}

	// line budget shared across requests
	b = &fmBudget{bytesLeft: fmTotalBytes, linesLeft: 150}
	g1, _ := evalFileMatchB(t.Context(), env, fmReq("/etc/h.conf", "hit"), b)
	g2, _ := evalFileMatchB(t.Context(), env, fmReq("/etc/h.conf", "hi"), b)
	if len(g1) != 100 || len(g2) != 50 || b.linesLeft != 0 {
		t.Errorf("line budget: %d + %d (left %d)", len(g1), len(g2), b.linesLeft)
	}
}

func TestRunFileMatchRequestsTotalLines(t *testing.T) {
	m := fstest.MapFS{}
	for i := 0; i < 30; i++ {
		m[fmt.Sprintf("etc/f%02d.conf", i)] = &fstest.MapFile{Data: []byte(strings.Repeat("hit\n", 30)), Mode: 0o644}
	}
	env := &Env{FS: linkMapFS{m}}
	var reqs []model.FactRequest
	for i := 0; i < 30; i++ {
		reqs = append(reqs, model.FactRequest{Name: fmt.Sprintf("file.match:r%d", i), Collector: "file.match",
			Params: map[string]string{"path": fmt.Sprintf("/etc/f%02d.conf", i), "pattern": "hit"}})
	}
	total := 0
	for _, v := range runFileMatchRequests(t.Context(), env, reqs) {
		total += len(v.([]string))
	}
	if total != fmTotalLines {
		t.Errorf("total lines = %d, want %d", total, fmTotalLines)
	}
}

func TestFileMatchDeadline(t *testing.T) {
	m := fstest.MapFS{"etc/h.conf": {Data: []byte("hit\n"), Mode: 0o644}}
	env := &Env{FS: linkMapFS{m}}
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	if got, ok := evalFileMatch(ctx, env, fmReq("/etc/h.conf", "hit")); ok {
		t.Errorf("expired deadline must stop evaluation, got %v", got)
	}
	if got := runFileMatchRequests(ctx, env, []model.FactRequest{
		{Name: "file.match:a", Collector: "file.match", Params: map[string]string{"path": "/etc/h.conf", "pattern": "hit"}},
	}); len(got) != 0 {
		t.Errorf("got %v", got)
	}
}

func TestBoundedGlobStopsAtLimit(t *testing.T) {
	m := fstest.MapFS{}
	for i := 0; i < 500; i++ {
		m[fmt.Sprintf("etc/g/f%03d.conf", i)] = &fstest.MapFile{Data: []byte("x"), Mode: 0o644}
	}
	got := boundedGlob(t.Context(), linkMapFS{m}, "/etc/g/*.conf", 50)
	if len(got) != 50 || got[0] != "/etc/g/f000.conf" {
		t.Errorf("got %d matches, first %q", len(got), got[0])
	}
	if got := boundedGlob(t.Context(), linkMapFS{m}, "/etc/g/[", 50); len(got) != 0 {
		t.Errorf("bad pattern matched %v", got)
	}
}

func TestSelectFileMatchDedupesPathPattern(t *testing.T) {
	p := map[string]string{"path": "/etc/a", "pattern": "x"}
	reqs := []model.FactRequest{
		{Name: "file.match:one", Collector: "file.match", Params: p},
		{Name: "file.match:two", Collector: "file.match", Params: p},
		{Name: "file.match:three", Collector: "file.match", Params: map[string]string{"path": "/etc/a", "pattern": "y"}},
	}
	got := selectFileMatchRequests(reqs)
	if len(got) != 2 || got[0].Name != "file.match:one" || got[1].Name != "file.match:three" {
		t.Errorf("got %v", got)
	}
	if fmMaxRequests != 20 {
		t.Errorf("fmMaxRequests = %d", fmMaxRequests)
	}
}

// --- nginx ---

func TestNginxDirectiveSecretsMasked(t *testing.T) {
	conf := `
http {
  proxy_set_header Authorization "Bearer abcdef";
  fastcgi_param DB_PASSWORD hunter2;
  ssl_password_file /etc/nginx/pw;
  auth_basic_user_file /etc/nginx/htpasswd;
  proxy_pass http://127.0.0.1:8080;
  set $token abc;
  add_header X-Long ` + strings.Repeat("v ", 300) + `;
}
`
	d := parseNginxDirectives([]byte(conf))
	check := func(name, want string) {
		t.Helper()
		if got := d[name]; len(got) != 1 || got[0] != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	check("proxy_set_header", "Authorization ***")
	check("fastcgi_param", "DB_PASSWORD ***")
	check("ssl_password_file", "/etc/nginx/pw")
	check("auth_basic_user_file", "/etc/nginx/htpasswd")
	check("proxy_pass", "http://127.0.0.1:8080")
	check("set", "$token ***")
	if v := d["add_header"][0]; len(v) > nginxMaxValue {
		t.Errorf("value not capped: %d", len(v))
	}
}

// --- A10: config tree trust ---

func TestCollectSkipsUntrustedTrees(t *testing.T) {
	var ran []string
	runner := recordingRunner{ran: &ran, out: map[string]string{
		"nginx -v":        "nginx version: nginx/1.24.0\n",
		"sshd -V":         "OpenSSH_9.6p1\n",
		"php -n -v":       "PHP 8.2.1 (cli)\n",
		"openssl version": "OpenSSL 3.0.2\n",
	}}
	env := &Env{
		Runner: runner,
		FS:     fstest.MapFS{},
		TreeTrust: func(roots []string) error {
			return fmt.Errorf("%s/conf.d writable by gid 33", roots[0])
		},
	}
	f := collect(t.Context(), env, nil)
	skipped, _ := f["agent.skipped"].([]string)
	want := []string{"nginx: /etc/nginx/conf.d writable by gid 33", "php: /etc/php/*/cli/conf.d writable by gid 33",
		"sshd: /etc/ssh/sshd_config/conf.d writable by gid 33"}
	if !reflect.DeepEqual(skipped, want) {
		t.Errorf("agent.skipped = %q, want %q", skipped, want)
	}
	for _, c := range ran {
		switch c {
		case "nginx -T", "nginx -V", "sshd -T", "php -i", "php -v":
			t.Errorf("command %q must not run from an untrusted tree", c)
		}
	}
	if f["nginx.installed"] != true || f["sshd.installed"] != true || f["php.installed"] != true {
		t.Errorf("installed facts lost: %v %v %v", f["nginx.installed"], f["sshd.installed"], f["php.installed"])
	}
	for _, k := range []string{"nginx.directives", "nginx.modules", "sshd.config", "php.ini"} {
		if _, ok := f[k]; ok {
			t.Errorf("%s must be omitted", k)
		}
	}
	if f["php.version"] != "8.2.1" {
		t.Errorf("php.version = %v", f["php.version"])
	}
}

type recordingRunner struct {
	ran *[]string
	out map[string]string
}

func (r recordingRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	key := strings.Join(append([]string{name}, args...), " ")
	*r.ran = append(*r.ran, key)
	if o, ok := r.out[key]; ok {
		return []byte(o), nil
	}
	return nil, errMissing
}

func writeTree(t *testing.T, root string, files int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, "conf.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < files; i++ {
		p := filepath.Join(root, "conf.d", fmt.Sprintf("f%d.conf", i))
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// WriteFile is subject to the umask; make modes explicit
	_ = filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err == nil {
			if fi.IsDir() {
				os.Chmod(p, 0o755)
			} else {
				os.Chmod(p, 0o644)
			}
		}
		return nil
	})
}

func TestTreeTrusted(t *testing.T) {
	root := filepath.Join(t.TempDir(), "nginx")
	writeTree(t, root, 3)
	if os.Getuid() == 0 || ownerIsRoot() {
		if err := treeTrusted([]string{root}); err != nil {
			t.Fatalf("clean tree rejected: %v", err)
		}
	} else if err := treeTrusted([]string{root}); err != nil && !strings.Contains(err.Error(), "owned by uid") {
		t.Fatalf("clean tree: %v", err)
	}

	// missing roots are fine
	if err := treeTrusted([]string{filepath.Join(root, "nope")}); err != nil {
		t.Errorf("missing root: %v", err)
	}

	bad := filepath.Join(root, "conf.d", "f1.conf")
	if err := os.Chmod(bad, 0o666); err != nil {
		t.Fatal(err)
	}
	err := treeTrusted([]string{root})
	if err == nil || !strings.Contains(err.Error(), "f1.conf") {
		t.Errorf("writable file not reported: %v", err)
	}
	if ownerIsRoot() && !strings.Contains(err.Error(), "writable by") {
		t.Errorf("err = %v", err)
	}
}

func TestTreeTrustedEntryLimit(t *testing.T) {
	root := filepath.Join(t.TempDir(), "big")
	writeTree(t, root, maxTrustEntries+10)
	err := treeTrusted([]string{root})
	if err == nil || !strings.Contains(err.Error(), "entries") {
		// non-root owners fail earlier with "owned by uid"; both fail closed
		if err == nil {
			t.Fatal("oversized tree must fail closed")
		}
	}
}

func TestFileTrustModes(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	os.WriteFile(p, nil, 0o600)
	for mode, bad := range map[os.FileMode]bool{0o755: false, 0o775: true, 0o757: true, 0o777: true} {
		os.Chmod(p, mode)
		fi, _ := os.Stat(p)
		err := fileTrust(p, fi)
		if _, _, ok := ownerIDs(fi); ok && os.Getuid() != 0 {
			if err == nil {
				t.Errorf("mode %o: non-root owner must be rejected", mode)
			}
			continue
		}
		if (err != nil) != bad {
			t.Errorf("mode %o: err=%v, want bad=%v", mode, err, bad)
		}
	}
}

// ownerIsRoot reports whether files this test creates would be root-owned.
func ownerIsRoot() bool { return os.Getuid() == 0 }

// --- A9: binary resolution ---

func TestResolveBinaryOrderAndTrust(t *testing.T) {
	sys, local := t.TempDir(), t.TempDir()
	mk := func(dir string) string {
		p := filepath.Join(dir, "tool")
		os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755)
		os.Chmod(p, 0o755)
		resolved, _ := filepath.EvalSymlinks(p)
		return resolved
	}
	sysBin, localBin := mk(sys), mk(local)

	if !strings.HasPrefix(fixedPath, "/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin") {
		t.Errorf("fixedPath = %q", fixedPath)
	}

	trustAll := func(string) error { return nil }
	noWarn := func(string, error) {}
	if got := resolveBinaryIn("tool", []string{sys, local}, trustAll, noWarn); got != sysBin {
		t.Errorf("system dir must win: %q", got)
	}

	// untrusted system copy is skipped (warned) and the later one used
	var warned []string
	deny := func(p string) error {
		if p == sysBin {
			return fmt.Errorf("writable by gid 50")
		}
		return nil
	}
	got := resolveBinaryIn("tool", []string{sys, local}, deny, func(p string, err error) { warned = append(warned, p) })
	if got != localBin || len(warned) != 1 || warned[0] != filepath.Join(sys, "tool") {
		t.Errorf("got %q warned %v", got, warned)
	}

	// nothing trusted -> "" (never fall back to the agent's PATH)
	if got := resolveBinaryIn("tool", []string{sys, local}, func(string) error { return fmt.Errorf("x") }, noWarn); got != "" {
		t.Errorf("got %q", got)
	}
	if got := resolveBinaryIn("absent", []string{sys}, trustAll, noWarn); got != "" {
		t.Errorf("got %q", got)
	}

	// symlink: trust is judged on the resolved file
	link := filepath.Join(local, "alias")
	os.Symlink(localBin, link)
	if got := resolveBinaryIn("alias", []string{local}, trustAll, noWarn); got != localBin {
		t.Errorf("symlink not resolved: %q", got)
	}
}

func TestBinaryTrustRejectsWritable(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "b")
	os.WriteFile(p, nil, 0o755)
	os.Chmod(p, 0o775)
	if err := binaryTrust(p); err == nil {
		t.Error("group-writable binary accepted")
	}
}
