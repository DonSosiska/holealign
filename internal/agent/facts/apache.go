package facts

import (
	"context"
	"io/fs"
	"regexp"
	"strings"

	"github.com/DonSosiska/panoptes/internal/model"
)

const (
	apacheMaxConfFiles = 200
	apacheMaxConfBytes = 1 << 20
)

var (
	reApacheVersion = regexp.MustCompile(`Apache/(\S+)`)
	reApacheModule  = regexp.MustCompile(`^\s*([A-Za-z0-9_]+_module)\s+\(`)
	reProtocols     = regexp.MustCompile(`(?im)^\s*Protocols\s+(.+)$`)
)

// parseApacheModules extracts module names from `apachectl -M` output
// (lines like " http2_module (shared)").
func parseApacheModules(out []byte) []string {
	names := []string{}
	for _, line := range strings.Split(string(out), "\n") {
		if m := reApacheModule.FindStringSubmatch(line); m != nil {
			names = append(names, m[1])
		}
	}
	return names
}

// protocolsEnableH2 reports whether any Protocols directive in the given config
// text enables h2 or h2c.
func protocolsEnableH2(text string) bool {
	for _, m := range reProtocols.FindAllStringSubmatch(text, -1) {
		for _, tok := range strings.Fields(m[1]) {
			if t := strings.ToLower(tok); t == "h2" || t == "h2c" {
				return true
			}
		}
	}
	return false
}

// apacheConfigEnablesH2 scans the Apache config trees for Protocols directives.
// Bounded: at most apacheMaxConfFiles *.conf files, each read up to 1 MiB.
func apacheConfigEnablesH2(fsys fs.FS) bool {
	if fsys == nil {
		return false
	}
	files := 0
	found := false
	for _, root := range []string{"etc/apache2", "etc/httpd"} {
		_ = fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || found || files >= apacheMaxConfFiles {
				if found {
					return fs.SkipAll
				}
				return nil
			}
			if d.IsDir() || !strings.HasSuffix(p, ".conf") {
				return nil
			}
			files++
			data, err := readFileGuarded(fsys, "/"+p)
			if err != nil {
				return nil
			}
			if len(data) > apacheMaxConfBytes {
				data = data[:apacheMaxConfBytes]
			}
			if protocolsEnableH2(string(data)) {
				found = true
				return fs.SkipAll
			}
			return nil
		})
		if found {
			return true
		}
	}
	return found
}

// apacheConfigRoots are the trees apachectl/httpd read (envvars and LoadModule included).
var apacheConfigRoots = []string{"/etc/apache2", "/etc/httpd", "/usr/local/apache2/conf", "/usr/local/etc/apache24"}

func collectApache(ctx context.Context, env *Env) model.Facts {
	f := model.Facts{}

	// apachectl is a shell script that sources envvars, and httpd -M loads every configured
	// module: both execute as root what the config trees say. Verify them first.
	if !env.treeOK("apache", apacheConfigRoots...) {
		return f
	}

	bin := ""
	var verOut []byte
	for _, cand := range []string{"apachectl", "httpd", "apache2ctl"} {
		out, err := env.run(ctx, cand, "-v")
		if isMissing(err) {
			continue
		}
		bin = cand
		verOut = out
		break
	}
	if bin == "" {
		f["apache.installed"] = false
		return f
	}
	f["apache.installed"] = true
	if m := reApacheVersion.FindSubmatch(verOut); m != nil {
		f["apache.version"] = string(m[1])
	}

	out, err := env.run(ctx, bin, "-M")
	if err != nil {
		return f
	}
	modules := parseApacheModules(out)
	f["apache.modules"] = modules

	hasH2Module := false
	for _, m := range modules {
		if m == "http2_module" {
			hasH2Module = true
			break
		}
	}
	f["apache.http2"] = hasH2Module && apacheConfigEnablesH2(env.FS)
	return f
}
