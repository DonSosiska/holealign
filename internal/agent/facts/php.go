package facts

import (
	"context"
	"io/fs"
	"regexp"
	"sort"
	"strings"

	"github.com/DonSosiska/panoptes/internal/model"
)

// phpIniKeys are the php.ini directives exposed as php.ini.
var phpIniKeys = map[string]bool{
	"allow_url_include": true,
	"allow_url_fopen":   true,
	"disable_functions": true,
	"expose_php":        true,
	"open_basedir":      true,
	"cgi.fix_pathinfo":  true,
}

var rePHPVersion = regexp.MustCompile(`(?m)^PHP (\d\S*)`)

// parsePHPVersion extracts the version from `php -v` output.
func parsePHPVersion(out []byte) string {
	if m := rePHPVersion.FindSubmatch(out); m != nil {
		return string(m[1])
	}
	return ""
}

// parsePHPIni reads the local values from `php -i` ("key => local => master").
// "no value" is reported as the empty string.
func parsePHPIni(out []byte) map[string]string {
	ini := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		parts := strings.Split(line, " => ")
		if len(parts) < 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		if !phpIniKeys[key] {
			continue
		}
		if _, seen := ini[key]; seen {
			continue
		}
		val := strings.TrimSpace(parts[1])
		if val == "no value" {
			val = ""
		}
		ini[key] = val
	}
	return ini
}

// phpSAPIs lists the non-CLI SAPIs whose presence can be seen on disk.
func phpSAPIs(fsys fs.FS) []string {
	var found []string
	if fsys == nil {
		return found
	}
	checks := map[string][]string{
		"php-fpm": {"usr/sbin/php-fpm*", "usr/local/sbin/php-fpm*"},
		"apache2handler": {
			"usr/lib/apache2/modules/libphp*.so",
			"usr/lib64/httpd/modules/libphp*.so",
			"usr/lib/httpd/modules/libphp*.so",
		},
	}
	for sapi, patterns := range checks {
		for _, pat := range patterns {
			if m, err := fs.Glob(fsys, pat); err == nil && len(m) > 0 {
				found = append(found, sapi)
				break
			}
		}
	}
	return found
}

// phpConfigRoots are the ini trees php reads (extension= loads shared objects).
var phpConfigRoots = []string{"/etc/php/*/cli", "/etc/php.ini", "/etc/php.d", "/usr/local/etc/php"}

func collectPHP(ctx context.Context, env *Env) model.Facts {
	f := model.Facts{}

	phpOK := env.treeOK("php", phpConfigRoots...)
	phpArgs := []string{"-v"}
	if !phpOK {
		phpArgs = []string{"-n", "-v"} // -n: no ini files, no extensions loaded
	}
	out, err := env.run(ctx, "php", phpArgs...)
	if isMissing(err) {
		f["php.installed"] = false
		return f
	}
	f["php.installed"] = true
	if err == nil {
		if v := parsePHPVersion(out); v != "" {
			f["php.version"] = v
		}
	}

	sapi := []string{}
	if err == nil {
		sapi = append(sapi, "cli")
	}
	sapi = append(sapi, phpSAPIs(env.FS)...)
	sort.Strings(sapi)
	f["php.sapi"] = sapi

	if !phpOK {
		return f
	}
	if iniOut, err := env.run(ctx, "php", "-i"); err == nil {
		f["php.ini"] = parsePHPIni(iniOut)
	}
	return f
}
