package facts

import (
	"context"
	"io/fs"
	"regexp"
	"strings"

	"github.com/DonSosiska/holealign/internal/model"
)

var (
	reLastVersion = regexp.MustCompile(`(\d+\.\d+(?:\.\d+)?)\s*$`)
	reMuslVersion = regexp.MustCompile(`(?m)^Version (\S+)`)
)

// parseOSRelease parses KEY=VALUE lines of /etc/os-release.
func parseOSRelease(data []byte) map[string]string {
	kv := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		kv[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
	}
	return kv
}

// parseLddVersion detects the libc from `ldd --version` output. musl prints to
// stderr and exits non-zero, so the output is inspected regardless of the error.
func parseLddVersion(out []byte) (libc, version string, ok bool) {
	s := string(out)
	lower := strings.ToLower(s)
	switch {
	case strings.Contains(lower, "musl libc"):
		libc = "musl"
		if m := reMuslVersion.FindStringSubmatch(s); m != nil {
			version = m[1]
		}
		return libc, version, true
	case strings.Contains(s, "GLIBC") || strings.Contains(s, "GNU libc"):
		first := strings.SplitN(s, "\n", 2)[0]
		if m := reLastVersion.FindStringSubmatch(first); m != nil {
			version = m[1]
		}
		return "glibc", version, true
	}
	return "", "", false
}

func collectOS(ctx context.Context, env *Env) model.Facts {
	f := model.Facts{}

	if data, err := env.readFirstFile("etc/os-release", "usr/lib/os-release"); err == nil {
		kv := parseOSRelease(data)
		if v, ok := kv["ID"]; ok {
			f["os.id"] = v
		}
		if v, ok := kv["VERSION_ID"]; ok {
			f["os.version_id"] = v
		}
	}

	out, err := env.run(ctx, "ldd", "--version")
	if libc, ver, ok := parseLddVersion(out); ok {
		f["os.libc"] = libc
		if ver != "" {
			f["os.libc_version"] = ver
		}
	} else if err != nil {
		// ldd missing or unusable: detect the musl loader by its file name.
		if hasMuslLoader(env) {
			f["os.libc"] = "musl"
		}
	}
	return f
}

func hasMuslLoader(env *Env) bool {
	if env.FS == nil {
		return false
	}
	for _, pat := range []string{"lib/ld-musl-*.so.1", "usr/lib/ld-musl-*.so.1"} {
		if m, err := fs.Glob(env.FS, pat); err == nil && len(m) > 0 {
			return true
		}
	}
	return false
}
