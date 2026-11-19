package facts

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/DonSosiska/holealign/internal/model"
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

// apacheExternalLocations statically scans Apache config files under apacheConfigRoots for
// Include, IncludeOptional, LoadModule, and LoadFile targets outside those roots.
func apacheExternalLocations(fsys fs.FS) ([]string, error) {
	return apacheExternalLocationsIn(fsys, apacheConfigRoots)
}

func apacheExternalLocationsIn(fsys fs.FS, roots []string) ([]string, error) {
	if fsys == nil {
		return nil, nil
	}
	var queue []string
	for _, r := range roots {
		rel := relPath(r)
		_ = fs.WalkDir(fsys, rel, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if !d.IsDir() && strings.HasSuffix(p, ".conf") {
				queue = append(queue, "/"+p)
				if len(queue) > 4*apacheMaxConfFiles {
					return fs.SkipAll
				}
			}
			return nil
		})
	}
	if len(queue) > 4*apacheMaxConfFiles {
		return nil, errors.New("config tree too large, includes not verified")
	}
	rootOf := func(file string) string {
		for _, r := range roots {
			if strings.HasPrefix(file, r+"/") {
				return r
			}
		}
		return path.Dir(file)
	}
	visited := map[string]bool{}
	external := map[string]bool{}
	for len(queue) > 0 {
		file := queue[0]
		queue = queue[1:]
		if visited[file] {
			continue
		}
		visited[file] = true
		f, err := openGuarded(fsys, file, false)
		if err != nil {
			continue
		}
		if len(visited) > apacheMaxConfFiles {
			f.Close()
			return nil, fmt.Errorf("more than %d config files, includes not verified", apacheMaxConfFiles)
		}
		data, err := io.ReadAll(io.LimitReader(f, apacheMaxConfBytes+1))
		f.Close()
		if err != nil || len(data) > apacheMaxConfBytes {
			return nil, fmt.Errorf("%s exceeds %d bytes, includes not verified", file, apacheMaxConfBytes)
		}
		for _, line := range strings.Split(string(data), "\n") {
			if idx := strings.IndexByte(line, '#'); idx >= 0 {
				line = line[:idx]
			}
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			fields := splitQuotedFields(line)
			if len(fields) < 2 {
				continue
			}
			dir := strings.ToLower(fields[0])
			switch dir {
			case "include", "includeoptional":
				arg := fields[1]
				if arg == "" || strings.ContainsAny(arg, "$\x00") {
					continue
				}
				p := arg
				if !strings.HasPrefix(p, "/") {
					p = path.Join(rootOf(file), p)
				}
				p = path.Clean(p)
				if !underAnyRoot(p, roots) {
					external[p] = true
				}
				matches := []string{p}
				if hasMeta(p) {
					ms, _ := fs.Glob(fsys, relPath(p))
					matches = matches[:0]
					for _, x := range ms {
						matches = append(matches, "/"+x)
					}
				}
				for _, x := range matches {
					if !visited[x] {
						queue = append(queue, x)
					}
				}
				if len(queue)+len(visited) > 4*apacheMaxConfFiles {
					return nil, errors.New("include graph too large, not verified")
				}
			case "loadmodule":
				if len(fields) < 3 {
					continue
				}
				arg := fields[2]
				if arg != "" && !strings.ContainsAny(arg, "$\x00") {
					p := arg
					if !strings.HasPrefix(p, "/") {
						p = path.Join(rootOf(file), p)
					}
					if p = path.Clean(p); !underAnyRoot(p, roots) {
						external[p] = true
					}
				}
			case "loadfile":
				for _, arg := range fields[1:] {
					if arg != "" && !strings.ContainsAny(arg, "$\x00") {
						p := arg
						if !strings.HasPrefix(p, "/") {
							p = path.Join(rootOf(file), p)
						}
						if p = path.Clean(p); !underAnyRoot(p, roots) {
							external[p] = true
						}
					}
				}
			}
		}
	}
	out := make([]string, 0, len(external))
	for p := range external {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}

func (env *Env) apacheIncludesTrusted() bool {
	locs, err := apacheExternalLocations(env.FS)
	if err != nil {
		env.skip("apache: " + err.Error())
		return false
	}
	for _, l := range locs {
		if !env.treeOK("apache include", l) {
			return false
		}
	}
	return true
}

func collectApache(ctx context.Context, env *Env) model.Facts {
	f := model.Facts{}

	// apachectl is a shell script that sources envvars, and httpd -M loads every configured
	// module: both execute as root what the config trees say. Verify them first.
	if !env.treeOK("apache", apacheConfigRoots...) || !env.apacheIncludesTrusted() {
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
