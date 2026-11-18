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
	"regexp/syntax"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/DonSosiska/panoptes/internal/model"
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

	// Pattern limits: bound the work a server-chosen regexp can cause.
	fmMaxProgInsts = 2000 // compiled program size (regexp/syntax instructions)
	fmMaxRepeat    = 100  // largest {n} / {n,m} count

	// Per check-in budgets across all requests.
	fmTotalBytes    = 2 << 20
	fmTotalLines    = 500
	fmLineBytes     = 512     // output cap per line
	fmMatchBytes    = 4 << 10 // longer lines are truncated before masking and matching
	fmDeadline      = 5 * time.Second
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
	fmUserinfo = regexp.MustCompile(`://[^/\s@]+@`)
	fmCryptRe  = regexp.MustCompile(`^[^:]+:\$[0-9a-z]+\$`)
	fmEntropy  = regexp.MustCompile(`[A-Za-z0-9+/=_-]{32,}`)
	fmBearerRe = regexp.MustCompile(`(?i)(\bbearer\s+)\S.*$`)

	// fmKeyRe finds "<key><sep>" where the key (letters, digits, _ . -) contains a secret-like
	// keyword anywhere (substring, case-insensitive), optionally quoted, and the separator is
	// ":" / "=" or whitespace. Everything after the separator is the value.
	fmKeyRe = regexp.MustCompile(`(?i)([A-Za-z0-9_.\-]*(?:key|secret|token|pass|pw|psk|credential|auth|community)[A-Za-z0-9_.\-]*)(["']?)(\s*[:=]\s*|\s+)`)

	fmStrongKeyRe = regexp.MustCompile(`(?i)pass|pw|secret|token|psk|credential|community`)
	fmTuningRe    = regexp.MustCompile(`(?i)(size|timeout|count|max|min|limit|length|len|interval|retries|attempts|tries|time|port|bytes|buffers?|lifetime|age|delay|rounds|ttl|depth|level)$`)
	fmNumberRe    = regexp.MustCompile(`(?i)^\d+(?:\.\d+)?(?:k|m|g|t|kb|mb|gb|tb|b|s|ms|min|h|d)?$`)
	fmSysPathRe   = regexp.MustCompile(`^/(?:etc|var|usr|run|opt|srv)/[A-Za-z0-9_./@+-]+$`)
)

// fmNotSecretKeys are directives whose name contains a secret-like keyword but whose value
// is configuration, not a secret (lower case, exact match).
var fmNotSecretKeys = map[string]bool{
	"proxy_pass": true, "fastcgi_pass": true, "uwsgi_pass": true, "scgi_pass": true,
	"grpc_pass": true, "memcached_pass": true, "auth_basic": true, "auth_request": true,
	"proxy_cache_key": true, "fastcgi_cache_key": true, "uwsgi_cache_key": true, "scgi_cache_key": true,
	"authorizedkeysfile": true, "authorizedprincipalsfile": true,
}

var fmBoolWords = map[string]bool{
	"on": true, "off": true, "yes": true, "no": true, "true": true, "false": true,
	"enabled": true, "disabled": true,
}

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

// fmValueIsSetting reports whether the value following a secret-like key is a plain
// setting rather than a secret: a boolean word, a number for tuning keys, a well-known
// system path (key files are referenced by path), or a known non-secret directive.
func fmValueIsSetting(key, rest string) bool {
	lk := strings.ToLower(key)
	if fmNotSecretKeys[lk] || strings.HasPrefix(lk, "passenger") {
		return true
	}
	tok := rest
	if i := strings.IndexAny(tok, " \t"); i >= 0 {
		tok = tok[:i]
	}
	tok = strings.Trim(tok, `;,"'`)
	if fmBoolWords[strings.ToLower(tok)] {
		return true
	}
	if fmSysPathRe.MatchString(tok) {
		return true
	}
	if fmNumberRe.MatchString(tok) && (!fmStrongKeyRe.MatchString(lk) || fmTuningRe.MatchString(lk)) {
		return true
	}
	return false
}

// maskKeyed masks the value after the first secret-like key whose value is not a plain
// setting; the rest of the line is the value.
func maskKeyed(line string) string {
	var b strings.Builder
	pos := 0
	for pos < len(line) {
		loc := fmKeyRe.FindStringSubmatchIndex(line[pos:])
		if loc == nil {
			break
		}
		key := line[pos+loc[2] : pos+loc[3]]
		sepEnd := pos + loc[1]
		rest := line[sepEnd:]
		if strings.TrimSpace(rest) == "" {
			break
		}
		b.WriteString(line[pos:sepEnd])
		pos = sepEnd
		if fmValueIsSetting(key, rest) {
			continue
		}
		b.WriteString("***")
		return b.String()
	}
	b.WriteString(line[pos:])
	return b.String()
}

// maskSecrets masks secret values in a line: values after secret-like keys, bearer
// credentials, URL userinfo and long high-entropy tokens.
func maskSecrets(line string) string {
	line = fmUserinfo.ReplaceAllString(line, "://***@")
	line = maskKeyed(line)
	line = fmBearerRe.ReplaceAllString(line, "${1}***")
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

// regexCost estimates the compiled size of a parsed expression without expanding
// repetitions first (Simplify would materialise them), saturating at limit+1.
func regexCost(re *syntax.Regexp, limit int) int {
	sat := func(n int) int {
		if n > limit {
			return limit + 1
		}
		return n
	}
	cost := 1
	if re.Op == syntax.OpLiteral {
		cost = len(re.Rune)
	}
	for _, sub := range re.Sub {
		cost = sat(cost + regexCost(sub, limit))
	}
	if re.Op == syntax.OpRepeat {
		n := re.Max
		if n < 0 {
			n = re.Min
		}
		if n < 1 {
			n = 1
		}
		cost = sat(cost * n)
	}
	return sat(cost)
}

// compilePattern compiles a server-chosen pattern, rejecting expressions whose repeat
// counts or compiled programs are large (CPU bound for the root collector).
func compilePattern(pattern string) (*regexp.Regexp, error) {
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, err
	}
	var bad error
	var walk func(*syntax.Regexp)
	walk = func(r *syntax.Regexp) {
		if r.Op == syntax.OpRepeat && (r.Min > fmMaxRepeat || r.Max > fmMaxRepeat) {
			bad = errors.New("facts: repeat count too large")
		}
		for _, sub := range r.Sub {
			walk(sub)
		}
	}
	walk(parsed)
	if bad != nil {
		return nil, bad
	}
	if regexCost(parsed, fmMaxProgInsts) > fmMaxProgInsts {
		return nil, errors.New("facts: pattern too complex")
	}
	prog, err := syntax.Compile(parsed.Simplify())
	if err != nil {
		return nil, err
	}
	if len(prog.Inst) > fmMaxProgInsts {
		return nil, errors.New("facts: pattern too complex")
	}
	return regexp.Compile(pattern)
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
		f, err := openGuarded(fsys, dir, true)
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
	re, err := compilePattern(pattern)
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
		f, err = env.SafeOpen(physical) // checks the ancestors itself (safeOpen)
	} else {
		if err = ancestorsTraversable(physical, func(abs string) (fs.FileInfo, error) {
			return fs.Lstat(env.FS, relPath(abs))
		}); err != nil {
			return nil, err
		}
		f, err = openGuarded(env.FS, physical, false)
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

// ancestorsTraversable requires every ancestor directory of a physical path to be a real
// directory with the "other" execute bit, so that an unprivileged user could reach the file
// (a 0644 file below a 0700 directory is not world-readable in practice).
func ancestorsTraversable(physical string, lstat func(abs string) (fs.FileInfo, error)) error {
	for d := path.Dir(physical); ; d = path.Dir(d) {
		fi, err := lstat(d)
		if err != nil {
			return err
		}
		if !fi.IsDir() || fi.Mode().Perm()&0o001 == 0 {
			return fmt.Errorf("facts: %s is not traversable by others", d)
		}
		if d == "/" || d == "." {
			return nil
		}
	}
}

// readChecked reads at most the per-file and remaining total byte budget and
// rejects files that contain NUL bytes or PEM blocks anywhere in what was read.
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
	if bytes.IndexByte(data, 0) >= 0 || bytes.Contains(data, []byte("-----BEGIN ")) {
		return nil, errors.New("facts: binary or key material")
	}
	return data, nil
}

// truncateBytes cuts s to at most n bytes without leaving a partial UTF-8 sequence.
func truncateBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	i := len(s) - 1
	for i > 0 && !utf8.RuneStart(s[i]) {
		i--
	}
	if i >= 0 && !utf8.FullRuneInString(s[i:]) {
		s = s[:i]
	}
	return s
}

// appendMatches adds the matching lines of data to out (prefixed with the file name)
// until a line budget is reached. Each line is cut to fmMatchBytes, crypt-hash lines are
// dropped, secrets are masked and only THEN the pattern is matched, against the masked
// text, so a server-chosen pattern cannot probe secret values character by character.
// The masked text is what is returned.
func appendMatches(ctx context.Context, out []string, file string, data []byte, re *regexp.Regexp, bud *fmBudget) []string {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), fmMaxFileBytes)
	for sc.Scan() {
		if len(out) >= fmMaxLines || bud.linesLeft <= 0 || ctx.Err() != nil {
			break
		}
		raw := sc.Bytes()
		if len(raw) > fmMatchBytes {
			raw = raw[:fmMatchBytes]
		}
		line := truncateBytes(string(raw), fmMatchBytes)
		if isCryptLine(strings.TrimSpace(line)) {
			continue
		}
		masked := maskSecrets(line)
		if !re.MatchString(masked) {
			continue
		}
		out = append(out, fmt.Sprintf("%s:%s", file, truncateBytes(strings.TrimSpace(masked), fmLineBytes)))
		bud.linesLeft--
	}
	return out
}
