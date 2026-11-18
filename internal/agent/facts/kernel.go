package facts

import (
	"context"
	"strings"

	"github.com/DonSosiska/holealign/internal/model"
)

// sysctlAllowlist is the set of kernel parameters exposed as kernel.sysctl.
var sysctlAllowlist = []string{
	"kernel.unprivileged_userns_clone",
	"user.max_user_namespaces",
	"kernel.unprivileged_bpf_disabled",
	"kernel.kptr_restrict",
	"kernel.yama.ptrace_scope",
	"kernel.dmesg_restrict",
	"net.ipv4.ip_forward",
	"net.ipv6.conf.all.disable_ipv6",
	"fs.protected_symlinks",
	"fs.protected_hardlinks",
	"vm.unprivileged_userfaultfd",
	"kernel.io_uring_disabled",
	"kernel.apparmor_restrict_unprivileged_userns",
}

// parseModules returns the module names from /proc/modules.
func parseModules(data []byte) []string {
	names := []string{}
	for _, line := range strings.Split(string(data), "\n") {
		if fields := strings.Fields(line); len(fields) > 0 {
			names = append(names, fields[0])
		}
	}
	return names
}

func collectKernel(ctx context.Context, env *Env) model.Facts {
	f := model.Facts{}

	if out, err := env.run(ctx, "uname", "-r"); err == nil {
		if v := strings.TrimSpace(string(out)); v != "" {
			f["kernel.release"] = v
		}
	} else if data, err := env.readFile("proc/sys/kernel/osrelease"); err == nil {
		f["kernel.release"] = strings.TrimSpace(string(data))
	}

	if data, err := env.readFile("proc/modules"); err == nil {
		f["kernel.modules"] = parseModules(data)
	}

	sysctl := map[string]string{}
	for _, name := range sysctlAllowlist {
		data, err := env.readFile("proc/sys/" + strings.ReplaceAll(name, ".", "/"))
		if err != nil {
			continue // missing on this kernel: omit the key
		}
		sysctl[name] = strings.TrimSpace(string(data))
	}
	if len(sysctl) > 0 {
		f["kernel.sysctl"] = sysctl
	}
	return f
}
