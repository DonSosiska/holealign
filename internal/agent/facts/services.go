package facts

import (
	"context"
	"io/fs"
	"sort"
	"strings"

	"panoptes/internal/model"
)

// Values of services.source.
const (
	servicesSourceSystemd = "systemd"
	servicesSourceProc    = "proc"
)

// procServiceNames maps well-known daemon process names (/proc/<pid>/comm) to the
// service names they are usually run as. Only exact names are mapped (plus the
// php-fpm prefix); anything else is reported under its own lowercase name.
var procServiceNames = map[string][]string{
	"sshd":         {"ssh", "sshd"},
	"nginx":        {"nginx"},
	"apache2":      {"apache2", "httpd"},
	"httpd":        {"apache2", "httpd"},
	"dockerd":      {"docker"},
	"containerd":   {"containerd"},
	"kubelet":      {"kubelet"},
	"crio":         {"crio"},
	"podman":       {"podman"},
	"mysqld":       {"mysql"},
	"mariadbd":     {"mysql", "mariadb"},
	"mariadb":      {"mariadb"},
	"postgres":     {"postgresql"},
	"redis-server": {"redis-server"},
	"named":        {"named", "bind9"},
	"krb5kdc":      {"krb5-kdc"},
	"kadmind":      {"krb5-admin-server"},
	"exim4":        {"exim4"},
	"postfix":      {"postfix"},
	"dovecot":      {"dovecot"},
	"smbd":         {"smbd"},
	"vsftpd":       {"vsftpd"},
	"cupsd":        {"cups"},
	"chronyd":      {"chrony"},
	"ntpd":         {"ntp"},
	"rpcbind":      {"rpcbind"},
	"slapd":        {"slapd"},
	"haproxy":      {"haproxy"},
	"squid":        {"squid"},
	"memcached":    {"memcached"},
	"mongod":       {"mongod"},
}

// procIgnoredNames are shells and tools that are never reported as services.
var procIgnoredNames = map[string]bool{
	"bash":           true,
	"sh":             true,
	"zsh":            true,
	"sleep":          true,
	"ps":             true,
	"cat":            true,
	"panoptes-agent": true,
}

// parseSystemctl extracts unit names (without ".service") from
// `systemctl list-units --type=service --state=running --no-legend`.
func parseSystemctl(out []byte) []string {
	names := []string{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name := fields[0]
		if name == "●" && len(fields) > 1 {
			name = fields[1]
		}
		if !strings.HasSuffix(name, ".service") {
			continue
		}
		names = append(names, strings.TrimSuffix(name, ".service"))
	}
	return names
}

// serviceNamesFromComms maps process names (contents of /proc/<pid>/comm) to a
// sorted, deduplicated list of service-like names. Kernel threads (empty or
// bracketed names) and ignored shells/tools are skipped.
func serviceNamesFromComms(comms []string) []string {
	set := map[string]bool{}
	for _, raw := range comms {
		comm := strings.ToLower(strings.TrimSpace(raw))
		if comm == "" || strings.HasPrefix(comm, "[") || procIgnoredNames[comm] {
			continue
		}
		if names, ok := procServiceNames[comm]; ok {
			for _, n := range names {
				set[n] = true
			}
			continue
		}
		if strings.HasPrefix(comm, "php-fpm") {
			set["php-fpm"] = true
			continue
		}
		set[comm] = true
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// scanProcComms reads /proc/<pid>/comm for every numeric pid directory.
func scanProcComms(env *Env) ([]string, error) {
	if env.FS == nil {
		return nil, fs.ErrNotExist
	}
	entries, err := fs.ReadDir(env.FS, "proc")
	if err != nil {
		return nil, err
	}
	var comms []string
	for _, e := range entries {
		if !e.IsDir() || !isPID(e.Name()) {
			continue
		}
		data, err := env.readFile("proc/" + e.Name() + "/comm")
		if err != nil {
			continue // process exited or not readable
		}
		comms = append(comms, string(data))
	}
	return comms, nil
}

func isPID(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func collectServices(ctx context.Context, env *Env) model.Facts {
	out, err := env.run(ctx, "systemctl", "list-units", "--type=service", "--state=running", "--no-legend")
	if err == nil {
		return model.Facts{
			"services.active": parseSystemctl(out),
			"services.source": servicesSourceSystemd,
		}
	}
	// systemctl missing or failed (no systemd running): fall back to the process list.
	comms, err := scanProcComms(env)
	if err != nil {
		return model.Facts{}
	}
	return model.Facts{
		"services.active": serviceNamesFromComms(comms),
		"services.source": servicesSourceProc,
	}
}
