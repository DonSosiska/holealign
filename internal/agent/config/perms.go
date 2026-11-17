package config

import (
	"fmt"
	"os"
)

// PermissionWarnings reports secret-bearing files that are readable by more users than
// intended: agent.yaml and client_key (expected 0640 root:panoptes or stricter), and the
// credentials file (expected 0600). Files that do not exist are ignored.
func PermissionWarnings(c Config, credentialsPath string) []string {
	var out []string
	check := func(label, path string, allowed os.FileMode) {
		if path == "" {
			return
		}
		fi, err := os.Stat(path)
		if err != nil || !fi.Mode().IsRegular() {
			return
		}
		if extra := fi.Mode().Perm() &^ allowed; extra != 0 {
			out = append(out, fmt.Sprintf("%s %s has mode %04o; expected %04o or stricter (group/world access beyond that exposes secrets)",
				label, path, fi.Mode().Perm(), allowed))
		}
	}
	check("config file", c.Path, 0o640)
	check("client_key", c.ClientKey, 0o640)
	check("credentials file", credentialsPath, 0o600)
	return out
}
