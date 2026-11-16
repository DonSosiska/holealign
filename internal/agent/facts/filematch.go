package facts

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"panoptes/internal/model"
)

const (
	fmPrefix          = "file.match:"
	fmMaxRequests     = 20
	fmMaxPatternLen   = 512
	fmMaxPathLen      = 512
	fmMaxFiles        = 50
	fmMaxFileBytes    = 1 << 20
	fmMaxLines        = 200 // per request
	fmMaxSymlinkDepth = 40

	// Per check-in budgets across all requests.
	fmTotalBytes    = 2 << 20
	fmTotalLines    = 500
	fmLineBytes     = 512
	fmDeadline      = 5 * time.Second
	fmSniffBytes    = 64 << 10
	fmMaxDirEntries = 4096 // entries examined per directory while globbing
	fmMaxWalkSteps  = 20000
)

// fmAllowedRoots are the allowed locations as component patterns. A path is
// allowed when it lies strictly below a root (the root itself is not a file).
var fmAllowedRoots = [][]string{
	{"etc"},
	{"opt", "*", "conf"},
	{"opt", "*", "etc"},
	{"usr", "local", "etc"},
}

// fmDenyPatterns are component sequences (lower case, path.Match syntax) that
// are never read, wherever they appear in the logical or physical path.
// The server enforces the same list; this copy keeps the agent self-contained.
var fmDenyPatterns = [][]string{
	{"shadow*"}, {"gshadow*"}, {"passwd-"}, {"sudoers*"},
	{"ssh", "ssh_host_*"}, {"ssl", "private"},
	{"letsencrypt"}, {"pki"}, {"panoptes"}, {"krb5.keytab"},
	{"*.key"}, {"*.pem"}, {"*.p12"}, {"*.pfx"}, {"*.jks"}, {"*.keystore"},
	{".htpasswd"}, {"*secret*"}, {"*credential*"}, {"*token*"},
	{"networkmanager"}, {"wireguard"}, {"openvpn"}, {"ppp"}, {"security"}, {"polkit-1"},
	{"ipsec*"}, {"strongswan*"}, {"cloud"}, {"mysql", "debian.cnf"}, {"*.env"},
}

// fmDenied reports whether a cleaned absolute path hits the hard denylist.
func fmDenied(abs string) bool {
	comps := splitAbs(strings.ToLower(abs))
	for _, pat := range fmDenyPatterns {
		for i := 0; i+len(pat) <= len(comps); i++ {
			ok := true
			for j, p := range pat {
				if m, err := path.Match(p, comps[i+j]); err != nil || !m {
					ok = false
					break
				}
			}
			if ok {
				return true
			}
		}
	}
	return false
}

var (
	fmSecretRe = regexp.MustCompile(`(?i)(["']?(?:pass(?:wd|word|phrase)|pwd|psk|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth(?:orization)?|requirepass|masterauth)["']?\s*[:=\s]\s*)\S.*$`)
	fmBarePass = regexp.MustCompile(`(?i)(\bpass["']?\s*[:=]\s*)\S.*$`)
	fmUserinfo = regexp.MustCompile(`://[^/\s@]+@`)
	fmCryptRe  = regexp.MustCompile(`^[^:]+:\$[0-9a-z]+\$`)
	fmEntropy  = regexp.MustCompile(`[A-Za-z0-9+/=_-]{32,}`)
)

var errSymlinkLoop = errors.New("facts: too many symbolic links")

// fmBudget is shared by all file.match requests of one check-in.
type fmBudget struct {
	bytesLeft int64
	linesLeft int
}

func newFMBudget() *fmBudget {
	return &fmBudget{bytesLeft: fmTotalBytes, linesLeft: fmTotalLines}
}

// selectFileMatchRequests keeps the file.match requests that may be evaluated:
// right collector, a usable name, no duplicates by name or by (path, pattern),
// at most fmMaxRequests.
func selectFileMatchRequests(reqs []model.FactRequest) []model.FactRequest {
	seen := map[string]bool{}
	seenPP := map[string]bool{}
	var out []model.FactRequest
	for _, r := range reqs {
		if r.Collector != "file.match" || !strings.HasPrefix(r.Name, fmPrefix) || seen[r.Name] {
			continue
		}
		pp := r.Params["path"] + "\x00" + r.Params["pattern"]
		if seenPP[pp] {
			continue
		}
		seen[r.Name] = true
		seenPP[pp] = true
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

// isCryptLine reports whether a line looks like a shadow-style crypt hash entry.
func isCryptLine(line string) bool { return fmCryptRe.MatchString(line) }

// maskSecrets masks secret values in a line: values after secret-like keys,
// URL userinfo and long high-entropy tokens.
func maskSecrets(line string) string {
	line = fmUserinfo.ReplaceAllString(line, "://***@")
	line = fmSecretRe.ReplaceAllString(line, "${1}***")
	line = fmBarePass.ReplaceAllString(line, "${1}***")
	line = fmEntropy.ReplaceAllStringFunc(line, func(tok string) string {
		hasDigit, hasLower, hasUpper := false, false, false
		for _, c := range tok {
			switch {
			case c >= '0' && c <= '9':
				hasDigit = true
			case c >= 'a' && c <= 'z':
				hasLower = true
			case c >= 'A' && c <= 'Z':
				hasUpper = true
			}
		}
		if (hasLower || hasUpper) && (hasDigit || (hasLower && hasUpper)) {
			return "***"
		}
		return tok
	})
	return line
}

func hasMeta(s string) bool { return strings.ContainsAny(s, `*?[\`) }

// boundedGlob expands an absolute glob without materialising more than limit
// matches (and examining at most fmMaxDirEntries entries per directory and
// fmMaxWalkSteps overall). Wildcard components only descend into real
// directories, never through symbolic links.
func boundedGlob(ctx context.Context, fsys fs.FS, glob string, limit int) []string {
	comps := splitAbs(glob)
	var out []string
	steps := 0
	var walk func(dir string, idx int)
	walk = func(dir string, idx int) {
		if len(out) >= limit || ctx.Err() != nil || steps > fmMaxWalkSteps {
			return
		}
		steps++
		last := idx == len(comps)-1
		comp := comps[idx]
		if !hasMeta(comp) {
			next := path.Join(dir, comp)
			if last {
				if _, err := fs.Lstat(fsys, relPath(next)); err == nil {
					out = append(out, next)
				}
				return
			}
			walk(next, idx+1)
			return
		}
		if _, err := path.Match(comp, ""); err != nil {
			return
		}
		f, err := fsys.Open(relPath(dir))
		if err != nil {
			return
		}
		defer f.Close()
		var entries []fs.DirEntry
		if rd, ok := f.(fs.ReadDirFile); ok {
			for len(entries) < fmMaxDirEntries {
				batch, err := rd.ReadDir(256)
				entries = append(entries, batch...)
				if err != nil || len(batch) == 0 {
					break
				}
			}
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, e := range entries {
			steps++
			if len(out) >= limit || ctx.Err() != nil || steps > fmMaxWalkSteps {
				return
			}
			if m, _ := path.Match(comp, e.Name()); !m {
				continue
			}
			if last {
				out = append(out, path.Join(dir, e.Name()))
			} else if e.IsDir() {
				walk(path.Join(dir, e.Name()), idx+1)
			}
		}
	}
	if len(comps) > 0 {
		walk("/", 0)
	}
	return out
}

// evalFileMatch evaluates one file.match request with a fresh budget.
func evalFileMatch(ctx context.Context, env *Env, req model.FactRequest) (lines []string, ok bool) {
	return evalFileMatchB(ctx, env, req, newFMBudget())
}

// evalFileMatchB evaluates one file.match request against a shared budget. ok
// is false when the fact must be omitted (invalid request, disallowed path, no
// readable file matched, budget exhausted before any file was read).
func evalFileMatchB(ctx context.Context, env *Env, req model.FactRequest, bud *fmBudget) (lines []string, ok bool) {
	if env.FS == nil || ctx.Err() != nil {
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
	matches := boundedGlob(ctx, env.FS, glob, fmMaxFiles)
	if len(matches) == 0 {
		return nil, false // no file: unknown
	}

	lines = []string{}
	considered := 0
	for _, logical := range matches {
		if ctx.Err() != nil || len(lines) >= fmMaxLines || bud.linesLeft <= 0 || bud.bytesLeft <= 0 {
			break
		}
		physical, err := resolveSymlinks(env.FS, logical, 0)
		if err != nil || !underAllowedRoot(physical) {
			// A match that escapes the allowed roots (or cannot be resolved)
			// rejects the whole request: fail closed.
			return nil, false
		}
		if fmDenied(logical) || fmDenied(physical) {
			continue
		}
		f, err := openPhysical(env, physical)
		if err != nil {
			continue
		}
		data, rerr := readChecked(f, bud)
		f.Close()
		if rerr != nil {
			continue
		}
		considered++
		lines = appendMatches(ctx, lines, logical, data, re, bud)
	}
	if considered == 0 {
		return nil, false
	}
	return lines, true
}

// openPhysical opens a resolved physical path without following symlinks (when
// the environment supports it) and verifies on the opened handle that it is a
// regular, world-readable file.
func openPhysical(env *Env, physical string) (fs.File, error) {
	var (
		f   fs.File
		err error
	)
	if env.SafeOpen != nil {
		f, err = env.SafeOpen(physical)
	} else {
		f, err = env.FS.Open(relPath(physical))
	}
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o004 == 0 {
		f.Close()
		return nil, errors.New("facts: not a world-readable regular file")
	}
	return f, nil
}

// readChecked reads at most the per-file and remaining total byte budget and
// rejects files that contain NUL bytes or PEM blocks in their first 64 KiB.
func readChecked(f io.Reader, bud *fmBudget) ([]byte, error) {
	limit := int64(fmMaxFileBytes)
	if bud.bytesLeft < limit {
		limit = bud.bytesLeft
	}
	data, err := io.ReadAll(io.LimitReader(f, limit))
	bud.bytesLeft -= int64(len(data))
	if err != nil {
		return nil, err
	}
	head := data
	if len(head) > fmSniffBytes {
		head = head[:fmSniffBytes]
	}
	if bytes.IndexByte(head, 0) >= 0 || bytes.Contains(head, []byte("-----BEGIN ")) {
		return nil, errors.New("facts: binary or key material")
	}
	return data, nil
}

func truncateBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// appendMatches adds the matching, masked, trimmed lines of data to out (prefixed
// with the file name) until a line budget is reached.
func appendMatches(ctx context.Context, out []string, file string, data []byte, re *regexp.Regexp, bud *fmBudget) []string {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), fmMaxFileBytes)
	for sc.Scan() {
		if len(out) >= fmMaxLines || bud.linesLeft <= 0 || ctx.Err() != nil {
			break
		}
		line := sc.Text()
		if !re.MatchString(line) || isCryptLine(strings.TrimSpace(line)) {
			continue
		}
		masked := truncateBytes(maskSecrets(strings.TrimSpace(line)), fmLineBytes)
		out = append(out, fmt.Sprintf("%s:%s", file, masked))
		bud.linesLeft--
	}
	return out
}
