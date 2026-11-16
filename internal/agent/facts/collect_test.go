package facts

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"panoptes/internal/model"
)

// fakeRunner answers commands from a table keyed by "name arg1 arg2".
// Unknown commands report exec.ErrNotFound, like a missing binary.
type fakeRunner struct {
	out     map[string]string
	errs    map[string]error
	panicOn string
}

func (f fakeRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	key := strings.Join(append([]string{name}, args...), " ")
	if key == f.panicOn {
		panic("simulated collector failure")
	}
	if e, ok := f.errs[key]; ok {
		return []byte(f.out[key]), e
	}
	if o, ok := f.out[key]; ok {
		return []byte(o), nil
	}
	return nil, errMissing
}

// errMissing mirrors what os/exec reports for an unknown binary.
var errMissing = exec.ErrNotFound

func TestCollectMissingBinaries(t *testing.T) {
	env := &Env{
		Runner:       fakeRunner{},
		FS:           fstest.MapFS{},
		DockerSocket: filepath.Join(t.TempDir(), "absent.sock"),
	}
	f := collect(t.Context(), env, nil)

	for _, key := range []string{"sshd.installed", "nginx.installed", "apache.installed", "php.installed", "docker.installed"} {
		if v, ok := f[key]; !ok || v != false {
			t.Errorf("%s = %v (present=%v), want false", key, v, ok)
		}
	}
	for _, key := range []string{"sshd.config", "nginx.directives", "nginx.http2", "apache.modules", "php.ini", "openssl.version", "os.id"} {
		if _, ok := f[key]; ok {
			t.Errorf("%s must be absent when the software is missing or unknown", key)
		}
	}
}

func TestCollectSSHDAndNginx(t *testing.T) {
	env := &Env{
		Runner: fakeRunner{
			out: map[string]string{
				"sshd -T":  string(fixture(t, "sshd_T.txt")),
				"ssh -V":   "OpenSSH_9.6p1 Ubuntu-3ubuntu13.5, OpenSSL 3.0.13 30 Jan 2024\n",
				"nginx -v": "nginx version: nginx/1.24.0 (Ubuntu)\n",
				"nginx -V": string(fixture(t, "nginx_V.txt")),
				"nginx -T": string(fixture(t, "nginx_T_http2_on.txt")),
			},
			errs: map[string]error{"sshd -V": errMissing},
		},
		FS:           fstest.MapFS{},
		DockerSocket: filepath.Join(t.TempDir(), "absent.sock"),
	}
	f := collect(t.Context(), env, nil)

	if f["sshd.installed"] != true || f["sshd.version"] != "9.6p1 Ubuntu-3ubuntu13.5" {
		t.Errorf("sshd: installed=%v version=%v", f["sshd.installed"], f["sshd.version"])
	}
	cfg, ok := f["sshd.config"].(map[string]string)
	if !ok || cfg["logingracetime"] != "120" {
		t.Errorf("sshd.config = %T %v", f["sshd.config"], f["sshd.config"])
	}
	if f["nginx.version"] != "1.24.0" || f["nginx.http2"] != true {
		t.Errorf("nginx: version=%v http2=%v", f["nginx.version"], f["nginx.http2"])
	}
	mods, ok := f["nginx.modules"].([]string)
	if !ok || !contains(mods, "http_v2_module") {
		t.Errorf("nginx.modules = %v", f["nginx.modules"])
	}
	if _, ok := f["nginx.directives"].(map[string][]string); !ok {
		t.Errorf("nginx.directives has type %T", f["nginx.directives"])
	}
}

func TestCollectNginxConfigTestFailureOmitsDirectives(t *testing.T) {
	env := &Env{
		Runner: fakeRunner{
			out:  map[string]string{"nginx -v": "nginx version: nginx/1.24.0\n", "nginx -T": "nginx: [emerg] bad\n"},
			errs: map[string]error{"nginx -T": errMissing},
		},
		FS: fstest.MapFS{},
	}
	f := collect(t.Context(), env, nil)
	if f["nginx.installed"] != true {
		t.Errorf("nginx.installed = %v", f["nginx.installed"])
	}
	if _, ok := f["nginx.http2"]; ok {
		t.Error("nginx.http2 must be omitted when nginx -T fails")
	}
	if _, ok := f["nginx.directives"]; ok {
		t.Error("nginx.directives must be omitted when nginx -T fails")
	}
}

func TestCollectOSLibcAndKernel(t *testing.T) {
	env := &Env{
		Runner: fakeRunner{
			out: map[string]string{
				"uname -r":      "6.8.0-45-generic\n",
				"ldd --version": string(fixture(t, "ldd_musl.txt")),
			},
			errs: map[string]error{"ldd --version": errMissing},
		},
		FS: fstest.MapFS{
			"etc/os-release":                    {Data: fixture(t, "os-release-alpine.txt")},
			"proc/modules":                      {Data: fixture(t, "proc_modules.txt")},
			"proc/sys/kernel/yama/ptrace_scope": {Data: []byte("1\n")},
			"proc/sys/kernel/apparmor_restrict_unprivileged_userns": {Data: []byte("1\n")},
		},
	}
	f := collect(t.Context(), env, nil)

	if f["os.id"] != "alpine" || f["os.version_id"] != "3.20.0" {
		t.Errorf("os: id=%v version=%v", f["os.id"], f["os.version_id"])
	}
	if f["os.libc"] != "musl" || f["os.libc_version"] != "1.2.4" {
		t.Errorf("libc: %v %v", f["os.libc"], f["os.libc_version"])
	}
	if f["kernel.release"] != "6.8.0-45-generic" {
		t.Errorf("kernel.release = %v", f["kernel.release"])
	}
	if mods, ok := f["kernel.modules"].([]string); !ok || len(mods) != 4 {
		t.Errorf("kernel.modules = %v", f["kernel.modules"])
	}
	want := map[string]string{
		"kernel.yama.ptrace_scope":                     "1",
		"kernel.apparmor_restrict_unprivileged_userns": "1",
	}
	if sysctl, ok := f["kernel.sysctl"].(map[string]string); !ok || !reflect.DeepEqual(sysctl, want) {
		t.Errorf("kernel.sysctl = %v, want %v", f["kernel.sysctl"], want)
	}
}

func TestCollectPanicIsIsolated(t *testing.T) {
	env := &Env{
		Runner: fakeRunner{
			out: map[string]string{
				"nginx -v": "nginx version: nginx/1.24.0\n",
			},
			panicOn: "sshd -T",
		},
		FS: fstest.MapFS{"etc/os-release": {Data: fixture(t, "os-release-debian.txt")}},
	}
	f := collect(t.Context(), env, nil)
	if f["os.id"] != "debian" {
		t.Errorf("os.id lost after a sibling collector panicked: %v", f["os.id"])
	}
	if f["nginx.version"] != "1.24.0" {
		t.Errorf("nginx.version lost after a sibling collector panicked: %v", f["nginx.version"])
	}
	if _, ok := f["sshd.config"]; ok {
		t.Error("sshd.config must be absent when its collector panicked")
	}
}

func TestCollectFileMatchRequests(t *testing.T) {
	env := &Env{
		Runner: fakeRunner{},
		FS: linkMapFS{fstest.MapFS{
			"etc/nginx/conf.d/app.conf": {Data: []byte("password = hunter2\n"), Mode: 0o644},
		}},
	}
	reqs := []model.FactRequest{
		{Name: "file.match:pw", Collector: "file.match", Params: map[string]string{"path": "/etc/nginx/conf.d/*.conf", "pattern": "password"}},
		{Name: "file.match:bad", Collector: "file.match", Params: map[string]string{"path": "/root/x", "pattern": "."}},
		{Name: "file.match:other", Collector: "exec", Params: map[string]string{"path": "/etc/passwd", "pattern": "."}},
	}
	f := collect(t.Context(), env, reqs)
	got, ok := f["file.match:pw"].([]string)
	if !ok || !reflect.DeepEqual(got, []string{"/etc/nginx/conf.d/app.conf:password = ***"}) {
		t.Errorf("file.match:pw = %v", f["file.match:pw"])
	}
	if _, ok := f["file.match:bad"]; ok {
		t.Error("disallowed path must not produce a fact")
	}
	if _, ok := f["file.match:other"]; ok {
		t.Error("unknown collector must not produce a fact")
	}
}

func TestCollectDockerOverUnixSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "pdk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "d.sock")

	version := fixture(t, "docker_version.json")
	containers := fixture(t, "docker_containers.json")
	webInspect := fixture(t, "docker_inspect_web.json")
	agentInspect := fixture(t, "docker_inspect_agent.json")

	mux := http.NewServeMux()
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(version) })
	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(containers) })
	mux.HandleFunc("/containers/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/containers/3f9c"):
			_, _ = w.Write(webInspect)
		case strings.HasPrefix(r.URL.Path, "/containers/a1b2"):
			_, _ = w.Write(agentInspect)
		default:
			http.NotFound(w, r)
		}
	})

	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })

	f := collectDocker(t.Context(), &Env{DockerSocket: sock})
	if f["docker.installed"] != true || f["docker.version"] != "26.1.4" {
		t.Fatalf("docker installed/version = %v / %v", f["docker.installed"], f["docker.version"])
	}
	list, ok := f["docker.containers"].([]map[string]any)
	if !ok || len(list) != 2 {
		t.Fatalf("docker.containers = %T %v", f["docker.containers"], f["docker.containers"])
	}
	web := list[0]
	if web["name"] != "web" || web["image"] != "nginx:1.25" || web["privileged"] != false {
		t.Errorf("web container = %v", web)
	}
	wantPorts := []string{"0.0.0.0:8080->80/tcp", "443/tcp"}
	if !reflect.DeepEqual(web["ports"], wantPorts) {
		t.Errorf("web ports = %v, want %v", web["ports"], wantPorts)
	}
	agent := list[1]
	if agent["privileged"] != true || agent["name"] != "agent" {
		t.Errorf("agent container = %v", agent)
	}
	if ports, ok := agent["ports"].([]string); !ok || len(ports) != 0 {
		t.Errorf("agent ports = %#v", agent["ports"])
	}
}

func TestCollectDockerMissingSocket(t *testing.T) {
	f := collectDocker(t.Context(), &Env{DockerSocket: filepath.Join(t.TempDir(), "none.sock")})
	if f["docker.installed"] != false {
		t.Errorf("docker.installed = %v, want false", f["docker.installed"])
	}
	if _, ok := f["docker.version"]; ok {
		t.Error("docker.version must be absent without a socket")
	}
}
