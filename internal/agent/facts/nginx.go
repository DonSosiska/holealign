package facts

import (
	"context"
	"regexp"
	"strings"

	"panoptes/internal/model"
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
			out[tokens[0]] = append(out[tokens[0]], maskDirective(tokens[0], strings.Join(tokens[1:], " ")))
		}
		tokens = tokens[:0]
	}

	// inTypes/typesDepth track a `types { ... }` block (MIME map inlined by
	// `nginx -T`); everything inside it is skipped.
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
					if len(tokens) == 1 && tokens[0] == "types" {
						inTypes = true
						typesDepth = 1
						tokens = tokens[:0]
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

	if out, err := env.run(ctx, "nginx", "-T"); err == nil {
		dirs := parseNginxDirectives(out)
		f["nginx.directives"] = dirs
		f["nginx.http2"] = nginxHTTP2(dirs)
	}
	return f
}
