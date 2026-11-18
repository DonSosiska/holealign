//go:build unix

package facts

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// within fails the test when fn does not return in a few seconds (a blocking open on a FIFO
// would never return).
func within(t *testing.T, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("blocked on a FIFO")
	}
}

func mkfifo(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(p, 0o666); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
}

func TestBoundedGlobFIFOComponentDoesNotBlock(t *testing.T) {
	tmp, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// /<tmp>/app1/conf is a FIFO where /<tmp>/*/conf/*.xml expects a directory.
	mkfifo(t, filepath.Join(tmp, "app1", "conf"))
	if err := os.MkdirAll(filepath.Join(tmp, "app2", "conf"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "app2", "conf", "a.xml"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	var got []string
	within(t, func() {
		got = boundedGlob(context.Background(), rootFS, tmp+"/*/conf/*.xml", 10)
	})
	if len(got) != 1 || !strings.HasSuffix(got[0], "app2/conf/a.xml") {
		t.Errorf("glob = %v, want only app2/conf/a.xml", got)
	}
}

func TestReadFileFIFODoesNotBlock(t *testing.T) {
	tmp, _ := filepath.EvalSymlinks(t.TempDir())
	p := filepath.Join(tmp, "fifo")
	mkfifo(t, p)
	env := &Env{FS: rootFS}
	within(t, func() {
		if _, err := env.readFile(strings.TrimPrefix(p, "/")); err == nil {
			t.Error("reading a FIFO must fail")
		}
	})
}

func TestNginxExternalLocationsFIFODoesNotBlock(t *testing.T) {
	tmp, _ := filepath.EvalSymlinks(t.TempDir())
	root := filepath.Join(tmp, "nginx")
	fifo := filepath.Join(tmp, "app", "inc.conf")
	mkfifo(t, fifo)
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	conf := "include " + fifo + ";\ninclude " + filepath.Join(tmp, "nope.conf") + ";\n"
	if err := os.WriteFile(filepath.Join(root, "nginx.conf"), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	var locs []string
	var err error
	within(t, func() { locs, err = nginxExternalLocationsIn(rootFS, []string{root}) })
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, l := range locs {
		found = found || l == fifo
	}
	if !found {
		t.Errorf("FIFO include must still be reported for the trust check: %v", locs)
	}

	// nginx.conf itself a FIFO
	root2 := filepath.Join(tmp, "nginx2")
	mkfifo(t, filepath.Join(root2, "nginx.conf"))
	within(t, func() { _, err = nginxExternalLocationsIn(rootFS, []string{root2}) })
	if err != nil {
		t.Fatal(err)
	}
}

func TestNginxFileLoadDirectivesAreExternalLocations(t *testing.T) {
	tmp, _ := filepath.EvalSymlinks(t.TempDir())
	root := filepath.Join(tmp, "nginx")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	conf := `
init_by_lua_file /srv/app/init.lua;
content_by_lua_file "/srv/app/content.lua";
perl_modules /srv/perl;
perl_require Foo.pm;
js_import main from /srv/njs/main.js;
js_path /srv/njs;
# init_by_lua_file /srv/commented.lua;
`
	if err := os.WriteFile(filepath.Join(root, "nginx.conf"), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	locs, err := nginxExternalLocationsIn(rootFS, []string{root})
	if err != nil {
		t.Fatal(err)
	}
	set := map[string]bool{}
	for _, l := range locs {
		set[l] = true
	}
	for _, want := range []string{"/srv/app/init.lua", "/srv/app/content.lua", "/srv/perl", "/srv/njs/main.js", "/srv/njs", "/usr/share/nginx/Foo.pm"} {
		if !set[want] {
			t.Errorf("missing %s in %v", want, locs)
		}
	}
	if set["/srv/commented.lua"] {
		t.Error("commented directive scanned")
	}
}

func TestOpenPhysicalFIFOWithoutSafeOpen(t *testing.T) {
	tmp, _ := filepath.EvalSymlinks(t.TempDir())
	p := filepath.Join(tmp, "fifo")
	mkfifo(t, p)
	env := &Env{FS: rootFS}
	within(t, func() {
		if f, err := openPhysical(env, p); err == nil {
			f.Close()
			t.Error("FIFO must be rejected")
		}
	})
}

func TestExecRunnerKillsProcessGroup(t *testing.T) {
	old := commandTimeout
	commandTimeout = 500 * time.Millisecond
	defer func() { commandTimeout = old }()
	out, err := execRunner{}.Run(context.Background(), "sh", "-c", "sleep 60 & echo $!; wait")
	if err == nil {
		t.Fatal("expected a timeout error")
	}
	var pid int
	for _, c := range strings.TrimSpace(string(out)) {
		if c < '0' || c > '9' {
			break
		}
		pid = pid*10 + int(c-'0')
	}
	if pid == 0 {
		t.Skipf("no pid in output %q (sh not resolvable?)", out)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if syscall.Kill(pid, 0) != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	syscall.Kill(pid, syscall.SIGKILL)
	t.Errorf("background child %d survived the timeout", pid)
}
