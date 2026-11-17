package facts

import (
	"context"

	"panoptes/internal/model"
)

// parseSudoVersion extracts the version from `sudo -V` output.
func parseSudoVersion(out []byte) string {
	if m := reSudoVersion.FindSubmatch(out); m != nil {
		return string(m[1])
	}
	return ""
}

func collectSudo(ctx context.Context, env *Env) model.Facts {
	// sudo -V reads /etc/sudo.conf, which can name plugins to load as root: it must be
	// root-owned and not group/world-writable (a missing file is fine).
	if !env.treeOK("sudo", "/etc/sudo.conf") {
		return model.Facts{}
	}
	out, err := env.run(ctx, "sudo", "-V")
	if err != nil {
		return model.Facts{}
	}
	if v := parseSudoVersion(out); v != "" {
		return model.Facts{"sudo.version": v}
	}
	return model.Facts{}
}
