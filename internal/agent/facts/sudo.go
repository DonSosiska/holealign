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
	out, err := env.run(ctx, "sudo", "-V")
	if err != nil {
		return model.Facts{}
	}
	if v := parseSudoVersion(out); v != "" {
		return model.Facts{"sudo.version": v}
	}
	return model.Facts{}
}
