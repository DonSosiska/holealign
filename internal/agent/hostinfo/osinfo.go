package hostinfo

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"runtime"
	"strings"

	"github.com/DonSosiska/panoptes/internal/model"
)

// parseOSRelease parses /etc/os-release style KEY=value lines.
func parseOSRelease(data []byte) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		out[strings.TrimSpace(k)] = v
	}
	return out
}

// CollectOSInfo reads /etc/os-release (falling back to /usr/lib/os-release) and the kernel release.
func CollectOSInfo() model.OSInfo {
	info := model.OSInfo{Kernel: kernelRelease(), Arch: runtime.GOARCH}
	for _, p := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		m := parseOSRelease(data)
		info.ID = m["ID"]
		info.VersionID = m["VERSION_ID"]
		info.PrettyName = m["PRETTY_NAME"]
		break
	}
	if info.ID == "" {
		info.ID = runtime.GOOS
	}
	return info
}

// hashMachineID returns the hex SHA-256 of "panoptes-machine-id:"+raw, so the
// raw (application-specific-secret-ish) machine id never leaves the host.
func hashMachineID(raw string) string {
	sum := sha256.Sum256([]byte("panoptes-machine-id:" + raw))
	return hex.EncodeToString(sum[:])
}

// MachineID returns the hashed /etc/machine-id (falling back to the dbus id,
// then the hostname).
func MachineID() string { return hashMachineID(rawMachineID()) }

func rawMachineID() string {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if data, err := os.ReadFile(p); err == nil {
			if id := strings.TrimSpace(string(data)); id != "" {
				return id
			}
		}
	}
	h, _ := os.Hostname()
	return h
}
