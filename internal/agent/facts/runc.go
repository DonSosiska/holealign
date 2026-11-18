package facts

import (
	"context"
	"regexp"

	"github.com/DonSosiska/holealign/internal/model"
)

var (
	reRuncVersion = regexp.MustCompile(`runc version (\S+)`)
	reSudoVersion = regexp.MustCompile(`Sudo version (\S+)`)
)

// parseRuncVersion extracts the version from `runc --version` output.
func parseRuncVersion(out []byte) string {
	if m := reRuncVersion.FindSubmatch(out); m != nil {
		return string(m[1])
	}
	return ""
}

func collectRunc(ctx context.Context, env *Env) model.Facts {
	out, err := env.run(ctx, "runc", "--version")
	if err != nil {
		return model.Facts{}
	}
	if v := parseRuncVersion(out); v != "" {
		return model.Facts{"runc.version": v}
	}
	return model.Facts{}
}
