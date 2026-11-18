package facts

import (
	"reflect"
	"testing"
	"testing/fstest"
)

const systemctlRunning = "systemctl list-units --type=service --state=running --no-legend"

func procFS() fstest.MapFS {
	return fstest.MapFS{
		"proc/1/comm":    {Data: []byte("sshd\n")},
		"proc/812/comm":  {Data: []byte("nginx\n")},
		"proc/900/comm":  {Data: []byte("bash\n")},
		"proc/2/comm":    {Data: []byte("[kthreadd]\n")},
		"proc/3/comm":    {Data: []byte("\n")},
		"proc/meminfo":   {Data: []byte("MemTotal: 1 kB\n")},
		"proc/self/comm": {Data: []byte("cat\n")},
		"proc/1500/comm": {Data: []byte("sshd\n")}, // duplicate of pid 1
		"proc/1600/comm": {Data: []byte("myapp\n")},
	}
}

func TestServicesFallbackWhenSystemctlMissing(t *testing.T) {
	env := &Env{Runner: fakeRunner{}, FS: procFS()}
	f := collectServices(t.Context(), env)

	want := []string{"myapp", "nginx", "ssh", "sshd"}
	if got := f["services.active"]; !reflect.DeepEqual(got, want) {
		t.Errorf("services.active = %v, want %v", got, want)
	}
	if f["services.source"] != "proc" {
		t.Errorf("services.source = %v, want proc", f["services.source"])
	}
}

func TestServicesFallbackWhenSystemctlFails(t *testing.T) {
	env := &Env{
		Runner: fakeRunner{
			out:  map[string]string{systemctlRunning: "System has not been booted with systemd as init system (PID 1). Can't operate.\n"},
			errs: map[string]error{systemctlRunning: errMissing},
		},
		FS: procFS(),
	}
	f := collectServices(t.Context(), env)
	if f["services.source"] != "proc" {
		t.Errorf("services.source = %v, want proc", f["services.source"])
	}
	if !reflect.DeepEqual(f["services.active"], []string{"myapp", "nginx", "ssh", "sshd"}) {
		t.Errorf("services.active = %v", f["services.active"])
	}
}

func TestServicesFromSystemd(t *testing.T) {
	env := &Env{
		Runner: fakeRunner{
			out: map[string]string{
				systemctlRunning: "ssh.service loaded active running OpenBSD Secure Shell server\n" +
					"cron.service loaded active running Regular background program processing daemon\n",
			},
		},
		FS: procFS(), // present but must not be used
	}
	f := collectServices(t.Context(), env)
	if !reflect.DeepEqual(f["services.active"], []string{"ssh", "cron"}) {
		t.Errorf("services.active = %v", f["services.active"])
	}
	if f["services.source"] != "systemd" {
		t.Errorf("services.source = %v, want systemd", f["services.source"])
	}
}

func TestServicesAbsentWithoutProc(t *testing.T) {
	env := &Env{Runner: fakeRunner{}, FS: fstest.MapFS{}}
	f := collectServices(t.Context(), env)
	if _, ok := f["services.active"]; ok {
		t.Errorf("services.active must be absent, got %v", f["services.active"])
	}
	if _, ok := f["services.source"]; ok {
		t.Errorf("services.source must be absent")
	}
	if got := collectServices(t.Context(), &Env{Runner: fakeRunner{}}); len(got) != 0 {
		t.Errorf("nil FS: got %v, want no facts", got)
	}
}

func TestServiceNamesFromComms(t *testing.T) {
	comms := []string{
		"apache2\n", "php-fpm8.2\n", "mariadbd\n", "postgres", "redis-server",
		"[kworker/0:1]", "", "bash", "sleep", "holealign-agent", "Dockerd\n", "named",
	}
	want := []string{
		"apache2", "bind9", "docker", "httpd", "mariadb", "mysql",
		"named", "php-fpm", "postgresql", "redis-server",
	}
	if got := serviceNamesFromComms(comms); !reflect.DeepEqual(got, want) {
		t.Errorf("serviceNamesFromComms = %v, want %v", got, want)
	}
}

func TestServiceNamesFromCommsEmpty(t *testing.T) {
	if got := serviceNamesFromComms(nil); got == nil || len(got) != 0 {
		t.Errorf("got %#v, want empty non-nil slice", got)
	}
}
