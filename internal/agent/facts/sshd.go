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

var reOpenSSHVersion = regexp.MustCompile(`OpenSSH_([^,\n]+)`)

var sshdConfigRoots = []string{"/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d"}

const (
	sshdIncMaxFiles = 100
	sshdIncMaxBytes = 1 << 20
)

// sshdExternalLocations statically follows Include directives (and records PKCS11Provider /
// SecurityKeyProvider paths) from /etc/ssh/sshd_config and returns locations outside
// sshdConfigRoots that `sshd -T` would read or load as root.
func sshdExternalLocations(fsys fs.FS) ([]string, error) {
	return sshdExternalLocationsIn(fsys, sshdConfigRoots)
}

func sshdExternalLocationsIn(fsys fs.FS, roots []string) ([]string, error) {
	if fsys == nil {
		return nil, nil
	}
	queue := []string{roots[0]}
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
		if len(visited) > sshdIncMaxFiles {
			f.Close()
			return nil, fmt.Errorf("more than %d config files, includes not verified", sshdIncMaxFiles)
		}
		data, err := io.ReadAll(io.LimitReader(f, sshdIncMaxBytes+1))
		f.Close()
		if err != nil || len(data) > sshdIncMaxBytes {
			return nil, fmt.Errorf("%s exceeds %d bytes, includes not verified", file, sshdIncMaxBytes)
		}
		for _, line := range strings.Split(string(data), "\n") {
			if idx := strings.IndexByte(line, '#'); idx >= 0 {
				line = line[:idx]
			}
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			key, rest := splitSSHDirective(line)
			switch strings.ToLower(key) {
			case "include":
				for _, arg := range splitQuotedFields(rest) {
					if arg == "" || strings.ContainsRune(arg, '\x00') {
						continue
					}
					p := arg
					if !strings.HasPrefix(p, "/") {
						p = path.Join("/etc/ssh", p)
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
					if len(queue)+len(visited) > 4*sshdIncMaxFiles {
						return nil, errors.New("include graph too large, not verified")
					}
				}
			case "pkcs11provider", "securitykeyprovider":
				for _, arg := range splitQuotedFields(rest) {
					if arg == "" || strings.EqualFold(arg, "none") || strings.EqualFold(arg, "internal") || strings.ContainsRune(arg, '\x00') {
						continue
					}
					if strings.HasPrefix(arg, "/") {
						if p := path.Clean(arg); !underAnyRoot(p, roots) {
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

func splitSSHDirective(line string) (key, rest string) {
	for i := 0; i < len(line); i++ {
		if line[i] == ' ' || line[i] == '\t' || line[i] == '=' {
			return line[:i], strings.TrimLeft(line[i+1:], " \t=")
		}
	}
	return line, ""
}

func splitQuotedFields(s string) []string {
	var out []string
	var cur strings.Builder
	var q byte
	inWord := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if q != 0 {
			if c == q {
				q = 0
			} else {
				cur.WriteByte(c)
			}
			continue
		}
		switch c {
		case '"', '\'':
			q = c
			inWord = true
		case ' ', '\t':
			if inWord {
				out = append(out, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	if inWord {
		out = append(out, cur.String())
	}
	return out
}

func (env *Env) sshdIncludesTrusted() bool {
	locs, err := sshdExternalLocations(env.FS)
	if err != nil {
		env.skip("sshd: " + err.Error())
		return false
	}
	for _, l := range locs {
		if !env.treeOK("sshd include", l) {
			return false
		}
	}
	return true
}

// parseSSHDConfig parses `sshd -T` output ("keyword value" per line). Keys are
// lowercased; the first occurrence of a keyword wins.
func parseSSHDConfig(out []byte) map[string]string {
	cfg := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, _ := strings.Cut(line, " ")
		key = strings.ToLower(key)
		if _, seen := cfg[key]; seen {
			continue
		}
		cfg[key] = strings.TrimSpace(value)
	}
	return cfg
}

// parseOpenSSHVersion extracts e.g. "9.6p1 Ubuntu-3ubuntu13.5" from `ssh -V` output.
func parseOpenSSHVersion(out []byte) string {
	if m := reOpenSSHVersion.FindSubmatch(out); m != nil {
		return strings.TrimSpace(string(m[1]))
	}
	return ""
}

// errSkipped keeps a "binary missing" error and turns every other outcome into
// a generic one, so a skipped command never yields facts.
func errSkipped(err error) error {
	if isMissing(err) {
		return err
	}
	return errors.New("skipped")
}

func collectSSHD(ctx context.Context, env *Env) model.Facts {
	f := model.Facts{}

	var out []byte
	var err error
	if env.treeOK("sshd", sshdConfigRoots...) && env.sshdIncludesTrusted() {
		out, err = env.run(ctx, "sshd", "-T")
	} else {
		// -V does not read the configuration; it only tells whether sshd exists
		_, err = env.run(ctx, "sshd", "-V")
		out, err = nil, errSkipped(err)
	}
	if isMissing(err) {
		f["sshd.installed"] = false
		return f
	}
	f["sshd.installed"] = true
	if err == nil {
		f["sshd.config"] = parseSSHDConfig(out)
	}

	if v, err := env.run(ctx, "sshd", "-V"); err == nil || len(v) > 0 {
		if ver := parseOpenSSHVersion(v); ver != "" {
			f["sshd.version"] = ver
			return f
		}
	}
	if v, err := env.run(ctx, "ssh", "-V"); err == nil || len(v) > 0 {
		if ver := parseOpenSSHVersion(v); ver != "" {
			f["sshd.version"] = ver
		}
	}
	return f
}
