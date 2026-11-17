package facts

import (
	"context"
	"regexp"

	"github.com/DonSosiska/panoptes/internal/model"
)

var reOpenSSLVersion = regexp.MustCompile(`(?m)^OpenSSL (\S+)`)

// parseOpenSSLVersion extracts "3.0.13" from `openssl version` output.
func parseOpenSSLVersion(out []byte) string {
	if m := reOpenSSLVersion.FindSubmatch(out); m != nil {
		return string(m[1])
	}
	return ""
}

func collectOpenSSL(ctx context.Context, env *Env) model.Facts {
	out, err := env.run(ctx, "openssl", "version")
	if err != nil {
		return model.Facts{}
	}
	if v := parseOpenSSLVersion(out); v != "" {
		return model.Facts{"openssl.version": v}
	}
	return model.Facts{}
}
