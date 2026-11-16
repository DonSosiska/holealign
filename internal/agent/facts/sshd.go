package facts

import (
	"context"
	"regexp"
	"strings"

	"panoptes/internal/model"
)

var reOpenSSHVersion = regexp.MustCompile(`OpenSSH_([^,\n]+)`)

// parseSSHDConfig parses `sshd -T` output ("keyword value" per line). Keys are
// lowercased; the first occurrence of a keyword wins.
func parseSSHDConfig(out []byte) map[string]string {
	cfg := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, _ := strings.Cut(line, " ")
		key = strings.ToLower(key)
		if _, seen := cfg[key]; seen {
			continue
		}
		cfg[key] = strings.TrimSpace(value)
	}
	return cfg
}

// parseOpenSSHVersion extracts e.g. "9.6p1 Ubuntu-3ubuntu13.5" from `ssh -V` output.
func parseOpenSSHVersion(out []byte) string {
	if m := reOpenSSHVersion.FindSubmatch(out); m != nil {
		return strings.TrimSpace(string(m[1]))
	}
	return ""
}

func collectSSHD(ctx context.Context, env *Env) model.Facts {
	f := model.Facts{}

	out, err := env.run(ctx, "sshd", "-T")
	if isMissing(err) {
		f["sshd.installed"] = false
		return f
	}
	f["sshd.installed"] = true
	if err == nil {
		f["sshd.config"] = parseSSHDConfig(out)
	}

	if v, err := env.run(ctx, "sshd", "-V"); err == nil || len(v) > 0 {
		if ver := parseOpenSSHVersion(v); ver != "" {
			f["sshd.version"] = ver
			return f
		}
	}
	if v, err := env.run(ctx, "ssh", "-V"); err == nil || len(v) > 0 {
		if ver := parseOpenSSHVersion(v); ver != "" {
			f["sshd.version"] = ver
		}
	}
	return f
}
