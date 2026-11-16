package facts

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"panoptes/internal/model"
)

const (
	fmPrefix          = "file.match:"
	fmMaxRequests     = 100
	fmMaxPatternLen   = 512
	fmMaxPathLen      = 512
	fmMaxFiles        = 50
	fmMaxFileBytes    = 1 << 20
	fmMaxLines        = 200
	fmMaxSymlinkDepth = 40
)

// fmAllowedRoots are the allowed locations as component patterns. A path is
// allowed when it lies strictly below a root (the root itself is not a file).
var fmAllowedRoots = [][]string{
	{"etc"},
	{"opt", "*", "conf"},
	{"opt", "*", "etc"},
	{"usr", "local", "etc"},
}

var fmSecretRe = regexp.MustCompile(`(?i)((?:pass(?:word)?|secret|token|key|credential|auth)\s*[:=]\s*)\S.*$`)

var errSymlinkLoop = errors.New("facts: too many symbolic links")

// selectFileMatchRequests keeps the file.match requests that may be evaluated:
// right collector, a usable name, no duplicates, at most fmMaxRequests.
func selectFileMatchRequests(reqs []model.FactRequest) []model.FactRequest {
	seen := map[string]bool{}
	var out []model.FactRequest
	for _, r := range reqs {
		if r.Collector != "file.match" || !strings.HasPrefix(r.Name, fmPrefix) || seen[r.Name] {
			continue
		}
		seen[r.Name] = true
		out = append(out, r)
		if len(out) == fmMaxRequests {
			break
		}
	}
	return out
}

// splitAbs splits a cleaned absolute path into its components.
func splitAbs(p string) []string {
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// underAllowedRoot reports whether a cleaned absolute path lies strictly below
// one of the allowed roots. Patterns may contain "*" for one component.
func underAllowedRoot(abs string) bool {
	comps := splitAbs(abs)
	for _, root := range fmAllowedRoots {
		if len(comps) <= len(root) {
			continue
		}
		ok := true
		for i, pat := range root {
			m, err := path.Match(pat, comps[i])
			if err != nil || !m {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// relPath converts an absolute path into the form expected by io/fs.
func relPath(abs string) string {
	if abs == "/" {
		return "."
	}
	return strings.TrimPrefix(abs, "/")
}

// resolveSymlinks returns the physical absolute path of a cleaned absolute path,
// following every symbolic link component by component. Any failure to read a
// link is an error, so the caller fails closed.
func resolveSymlinks(fsys fs.FS, abs string, depth int) (string, error) {
	if depth > fmMaxSymlinkDepth {
		return "", errSymlinkLoop
	}
	parts := splitAbs(abs)
	cur := "/"
	for i, part := range parts {
		next := path.Join(cur, part)
		info, err := fs.Lstat(fsys, relPath(next))
		if err != nil {
			return "", err
		}
		if info.Mode()&fs.ModeSymlink == 0 {
			cur = next
			continue
		}
		target, err := fs.ReadLink(fsys, relPath(next))
		if err != nil {
			return "", err
		}
		if !strings.HasPrefix(target, "/") {
			target = path.Join(cur, target)
		}
		rest := path.Join(parts[i+1:]...)
		return resolveSymlinks(fsys, path.Join(target, rest), depth+1)
	}
	return cur, nil
}

// maskSecrets replaces the value after a secret-like key with "***".
func maskSecrets(line string) string {
	return fmSecretRe.ReplaceAllString(line, "${1}***")
}

// evalFileMatch evaluates one file.match request. ok is false when the fact
// must be omitted (invalid request, disallowed path, no file matched).
func evalFileMatch(ctx context.Context, env *Env, req model.FactRequest) (lines []string, ok bool) {
	if env.FS == nil {
		return nil, false
	}
	rawPath := req.Params["path"]
	pattern := req.Params["pattern"]
	if rawPath == "" || pattern == "" || len(pattern) > fmMaxPatternLen || len(rawPath) > fmMaxPathLen {
		return nil, false
	}
	if !strings.HasPrefix(rawPath, "/") || strings.ContainsRune(rawPath, 0) {
		return nil, false
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, false
	}

	glob := filepath.ToSlash(filepath.Clean(rawPath))
	if !underAllowedRoot(glob) {
		return nil, false
	}
	matches, err := fs.Glob(env.FS, relPath(glob))
	if err != nil || len(matches) == 0 {
		return nil, false // no file: unknown
	}
	if len(matches) > fmMaxFiles {
		matches = matches[:fmMaxFiles]
	}

	lines = []string{}
	for _, m := range matches {
		if err := ctx.Err(); err != nil {
			break
		}
		if len(lines) >= fmMaxLines {
			break
		}
		logical := "/" + m
		physical, err := resolveSymlinks(env.FS, logical, 0)
		if err != nil || !underAllowedRoot(physical) {
			// A match that escapes the allowed roots (or cannot be resolved)
			// rejects the whole request: fail closed.
			return nil, false
		}
		info, err := fs.Stat(env.FS, relPath(physical))
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		data, err := readCapped(env.FS, relPath(physical), fmMaxFileBytes)
		if err != nil {
			continue
		}
		lines = appendMatches(lines, logical, data, re)
	}
	return lines, true
}

// readCapped reads at most limit bytes of the named file.
func readCapped(fsys fs.FS, name string, limit int64) ([]byte, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, limit))
}

// appendMatches adds the matching, masked, trimmed lines of data to out (prefixed
// with the file name) until fmMaxLines is reached.
func appendMatches(out []string, file string, data []byte, re *regexp.Regexp) []string {
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 0, 64*1024), fmMaxFileBytes)
	for sc.Scan() {
		if len(out) >= fmMaxLines {
			break
		}
		line := sc.Text()
		if !re.MatchString(line) {
			continue
		}
		out = append(out, fmt.Sprintf("%s:%s", file, maskSecrets(strings.TrimSpace(line))))
	}
	return out
}
