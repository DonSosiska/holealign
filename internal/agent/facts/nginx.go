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
	"strconv"
	"strings"

	"github.com/DonSosiska/panoptes/internal/model"
)

var (
	reNginxVersion  = regexp.MustCompile(`nginx/(\S+)`)
	reNginxWithFlag = regexp.MustCompile(`--with-([A-Za-z0-9_-]+)(?:\s|$)`)
)

// parseNginxModules extracts the --with-<name> flags from `nginx -V` output
// (names without the "--with-" prefix). Flags with values (--with-cc-opt=...)
// are not modules and are skipped.
func parseNginxModules(out []byte) []string {
	seen := map[string]bool{}
	names := []string{}
	for _, m := range reNginxWithFlag.FindAllSubmatch(out, -1) {
		name := string(m[1])
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	return names
}

// parseNginxDirectives tokenises `nginx -T` output into directive -> list of
// argument strings (arguments joined with a single space), one entry per
// occurrence. Comments and the "nginx: ..." status lines are dropped. Block
// openers are recorded with the arguments before "{".
func parseNginxDirectives(data []byte) map[string][]string {
	out := map[string][]string{}
	var tokens []string
	var word strings.Builder
	inWord := false
	var quote byte

	flushWord := func() {
		if inWord {
			tokens = append(tokens, word.String())
			word.Reset()
			inWord = false
		}
	}
	endStatement := func() {
		flushWord()
		if len(tokens) > 0 {
			// The key is masked too: a statement that is not a directive (data in a
			// block this parser does not know) must not leak its first token.
			key := tokens[0]
			if !plausibleDirectiveName(key) || maskSecrets(key) != key {
				key = "***"
			}
			out[key] = append(out[key], maskDirective(key, strings.Join(tokens[1:], " ")))
		}
		tokens = tokens[:0]
	}

	// inTypes/typesDepth track a data block (`types`, `map`, `geo`, ...): the first token of
	// each statement inside is data (MIME types, map keys such as API keys), not a
	// directive name, so everything inside is skipped. The opener itself is kept, except for
	// `types`, whose bare opener carries no information.
	inTypes := false
	typesDepth := 0

	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "nginx:") || strings.HasPrefix(trimmed, "# configuration file ") {
			continue
		}
		for i := 0; i < len(line); i++ {
			c := line[i]
			if quote != 0 {
				if c == quote {
					quote = 0
				} else {
					word.WriteByte(c)
				}
				continue
			}
			switch c {
			case '#':
				i = len(line) // comment to end of line
			case ' ', '\t', '\r':
				flushWord()
			case ';':
				if inTypes {
					flushWord()
					tokens = tokens[:0]
				} else {
					endStatement()
				}
			case '{':
				if inTypes {
					typesDepth++
					flushWord()
					tokens = tokens[:0]
				} else {
					flushWord()
					if len(tokens) > 0 && nginxDataBlocks[tokens[0]] {
						inTypes = true
						typesDepth = 1
						if tokens[0] == "types" {
							tokens = tokens[:0]
						} else {
							endStatement()
						}
					} else {
						endStatement()
					}
				}
			case '}':
				if inTypes {
					flushWord()
					tokens = tokens[:0]
					typesDepth--
					if typesDepth == 0 {
						inTypes = false
					}
				} else {
					endStatement()
				}
			case '"', '\'':
				quote = c
				inWord = true
			default:
				word.WriteByte(c)
				inWord = true
			}
		}
		flushWord()
	}
	endStatement()
	return out
}

var reDirectiveName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

var reLongDigits = regexp.MustCompile(`[0-9]{4,}`)

// plausibleDirectiveName reports whether s can be a directive name: lower-case words, digits
// and underscores, without long digit runs (which look like keys and tokens).
func plausibleDirectiveName(s string) bool {
	return reDirectiveName.MatchString(s) && !reLongDigits.MatchString(s)
}

// nginxDataBlocks are block directives whose body is data rather than directives.
var nginxDataBlocks = map[string]bool{
	"types": true, "map": true, "geo": true, "split_clients": true, "charset_map": true, "match": true,
}

const nginxMaxValue = 256

// maskDirective masks secrets in a directive value: the directive name and its
// arguments are scanned together, so `proxy_set_header Authorization Bearer x`
// and `fastcgi_param DB_PASSWORD x` lose their secret part. Values are capped.
func maskDirective(name, value string) string {
	if value != "" {
		full := name + " " + value
		if masked := maskSecrets(full); masked != full && strings.HasPrefix(masked, name+" ") {
			value = masked[len(name)+1:]
		} else if masked != full {
			value = "***"
		}
	}
	return truncateBytes(value, nginxMaxValue)
}

// nginxHTTP2 reports whether `http2 on;` or a `listen ... http2` flag is present.
func nginxHTTP2(d map[string][]string) bool {
	for _, v := range d["http2"] {
		if strings.TrimSpace(v) == "on" {
			return true
		}
	}
	for _, v := range d["listen"] {
		for _, tok := range strings.Fields(v) {
			if tok == "http2" {
				return true
			}
		}
	}
	return false
}

// nginxConfigRoots are the config trees nginx -T/-V may load (load_module
// directives run arbitrary shared objects as root).
var nginxConfigRoots = []string{"/etc/nginx", "/usr/local/etc/nginx", "/usr/local/nginx/conf"}

const (
	nginxIncMaxFiles = 200     // config files followed while scanning include directives
	nginxIncMaxBytes = 1 << 20 // bytes read per file
)

var reNginxIncludeDir = regexp.MustCompile(`(?:^|[\s;{}])(include|load_module)\s+("[^"]*"|'[^']*'|[^\s;{}]+)\s*;`)

// reNginxFileLoad matches directives (lua, perl and njs modules) that load a file or search
// directory the agent's tree check would otherwise not see. Group 2 is the argument list.
var reNginxFileLoad = regexp.MustCompile(`(?:^|[\s;{}])([A-Za-z0-9_]+_by_lua_file|perl_modules|perl_require|js_import|js_path)\s+([^;{}]*);`)

// addExternalFile records the location(s) an absolute or prefix-relative path may denote when
// they lie outside the verified config roots.
func addExternalFile(external map[string]bool, roots []string, arg string) {
	if arg == "" || strings.ContainsAny(arg, "$\x00") {
		return
	}
	if strings.HasPrefix(arg, "/") {
		if p := path.Clean(arg); !underAnyRoot(p, roots) {
			external[p] = true
		}
		return
	}
	for _, b := range loadModuleBases {
		if p := path.Join(b, arg); !underAnyRoot(p, roots) {
			external[p] = true
		}
	}
}

// loadModuleBases are the prefixes a relative load_module path may resolve against (the
// compile-time --prefix differs between distributions).
var loadModuleBases = []string{"/usr/share/nginx", "/usr/lib/nginx", "/etc/nginx", "/usr/local/nginx"}

// stripNginxComments removes "#" comments that are not inside quotes.
func stripNginxComments(text string) string {
	var b strings.Builder
	for _, line := range strings.Split(text, "\n") {
		var q byte
		cut := len(line)
		for i := 0; i < len(line); i++ {
			c := line[i]
			switch {
			case q != 0:
				if c == q {
					q = 0
				}
			case c == '"' || c == '\'':
				q = c
			case c == '#':
				cut = i
			}
			if cut != len(line) {
				break
			}
		}
		b.WriteString(line[:cut])
		b.WriteByte('\n')
	}
	return b.String()
}

func underAnyRoot(p string, roots []string) bool {
	for _, r := range roots {
		if p == r || strings.HasPrefix(p, r+"/") {
			return true
		}
	}
	return false
}

// nginxExternalLocations statically follows the include directives (and collects
// load_module paths) of the nginx config under the verified roots and returns the
// locations OUTSIDE those roots that nginx -T would read or load as root. Bounded to
// nginxIncMaxFiles files of nginxIncMaxBytes each; more is an error (fail closed).
func nginxExternalLocations(fsys fs.FS) ([]string, error) {
	return nginxExternalLocationsIn(fsys, nginxConfigRoots)
}

func nginxExternalLocationsIn(fsys fs.FS, roots []string) ([]string, error) {
	if fsys == nil {
		return nil, nil
	}
	var queue []string
	for _, root := range roots {
		queue = append(queue, root+"/nginx.conf")
	}
	prefixOf := func(file string) string {
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
		if len(visited) > nginxIncMaxFiles {
			f.Close()
			return nil, fmt.Errorf("more than %d config files, includes not verified", nginxIncMaxFiles)
		}
		data, _ := io.ReadAll(io.LimitReader(f, nginxIncMaxBytes))
		f.Close()
		text := stripNginxComments(string(data))
		// Directives that make nginx load code or data from a file or directory: the
		// location must pass the same trust check as an include.
		for _, m := range reNginxFileLoad.FindAllStringSubmatch(text, -1) {
			fields := strings.Fields(m[2])
			if len(fields) == 0 {
				continue
			}
			arg := fields[0]
			if m[1] == "js_import" {
				arg = fields[len(fields)-1] // `js_import name from path;`
			}
			addExternalFile(external, roots, strings.Trim(arg, `"'`))
		}
		for _, m := range reNginxIncludeDir.FindAllStringSubmatch(text, -1) {
			arg := strings.Trim(m[2], `"'`)
			if arg == "" || strings.ContainsAny(arg, "$\x00") {
				continue
			}
			if m[1] == "load_module" {
				addExternalFile(external, roots, arg)
				continue
			}
			p := arg
			if !strings.HasPrefix(p, "/") {
				p = path.Join(prefixOf(file), p)
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
			if len(queue)+len(visited) > 4*nginxIncMaxFiles {
				return nil, errors.New("include graph too large, not verified")
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

// nginxIncludesTrusted verifies, with the same tree trust check, every location outside the
// verified roots that the config includes; false (recorded in agent.skipped) means nginx -T
// must not run.
func (env *Env) nginxIncludesTrusted() bool {
	locs, err := nginxExternalLocations(env.FS)
	if err != nil {
		env.skip("nginx: " + err.Error())
		return false
	}
	for _, l := range locs {
		if !env.treeOK("nginx include", l) {
			return false
		}
	}
	return true
}

// nginxSupportsErrorLogFlag reports whether `nginx -e FILE` exists (nginx >= 1.19.5).
func nginxSupportsErrorLogFlag(version string) bool {
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 3 {
		return false
	}
	n := [3]int{}
	for i, p := range parts {
		end := 0
		for end < len(p) && p[end] >= '0' && p[end] <= '9' {
			end++
		}
		v, err := strconv.Atoi(p[:end])
		if err != nil {
			return false
		}
		n[i] = v
	}
	if n[0] != 1 {
		return n[0] > 1
	}
	if n[1] != 19 {
		return n[1] > 19
	}
	return n[2] >= 5
}

func collectNginx(ctx context.Context, env *Env) model.Facts {
	f := model.Facts{}

	v, err := env.run(ctx, "nginx", "-v")
	if isMissing(err) {
		f["nginx.installed"] = false
		return f
	}
	f["nginx.installed"] = true
	if m := reNginxVersion.FindSubmatch(v); m != nil {
		f["nginx.version"] = string(m[1])
	}

	if !env.treeOK("nginx", nginxConfigRoots...) {
		return f
	}

	if out, err := env.run(ctx, "nginx", "-V"); err == nil {
		f["nginx.modules"] = parseNginxModules(out)
	}

	if !env.nginxIncludesTrusted() {
		return f
	}

	// nginx -T parses the whole config, which may load modules and include files outside the
	// verified roots (checked above).
	//
	// NOTE (verify on a real host under panoptes-collector.service, ProtectSystem=strict):
	// nginx -t/-T opens the configured error_log and every access_log for writing and creates
	// its temp paths, so on a read-only file system it can fail with "open() ... failed (30:
	// Read-only file system)" and print no dump. `-q -e /dev/null` (nginx >= 1.19.5) only
	// replaces the compile-time default error log; logs named in the config are still opened.
	// We deliberately do NOT add `-g 'pid /dev/null; error_log /dev/null;'`: `pid` is a
	// non-repeatable directive, so it would fail with "directive is duplicate" on every config
	// that sets its own pid file, which is almost all of them. If nginx.directives is missing on
	// a real host, add the log/temp directories to ReadWritePaths= of the collector unit.
	args := []string{"-T"}
	if ver, _ := f["nginx.version"].(string); nginxSupportsErrorLogFlag(ver) {
		args = []string{"-T", "-q", "-e", "/dev/null"}
	}
	out, err := env.run(ctx, "nginx", args...)
	if err != nil && len(args) > 1 && strings.Contains(string(out), "invalid option") {
		out, err = env.run(ctx, "nginx", "-T")
	}
	if err == nil {
		dirs := parseNginxDirectives(out)
		f["nginx.directives"] = dirs
		f["nginx.http2"] = nginxHTTP2(dirs)
	}
	return f
}
