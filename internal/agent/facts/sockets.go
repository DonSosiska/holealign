package facts

import (
	"context"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/DonSosiska/panoptes/internal/model"
)

// socketEntry is one row of /proc/net/{tcp,tcp6,udp,udp6}.
type socketEntry struct {
	proto  string
	addr   string
	port   int
	state  string
	remote string // raw "addr:port" of the remote end
	inode  uint64
}

var procNetFiles = []string{"tcp", "tcp6", "udp", "udp6"}

// decodeProcAddr decodes the hex address of /proc/net. Each 32-bit word is
// printed in host (little-endian on the usual targets) order, so every 4-byte
// group is byte-reversed.
func decodeProcAddr(h string) (net.IP, error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, err
	}
	if len(b) != 4 && len(b) != 16 {
		return nil, fmt.Errorf("bad address length %d", len(b))
	}
	for i := 0; i < len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	return net.IP(b), nil
}

// splitProcAddr splits "HEXADDR:HEXPORT" into an IP and a port.
func splitProcAddr(s string) (net.IP, int, error) {
	host, port, ok := strings.Cut(s, ":")
	if !ok {
		return nil, 0, fmt.Errorf("bad address %q", s)
	}
	ip, err := decodeProcAddr(host)
	if err != nil {
		return nil, 0, err
	}
	p, err := strconv.ParseUint(port, 16, 16)
	if err != nil {
		return nil, 0, err
	}
	return ip, int(p), nil
}

// parseProcNet parses one /proc/net/<proto> file. For tcp only LISTEN (0A)
// sockets are kept; for udp every bound socket with an all-zero remote is kept.
func parseProcNet(data []byte, proto string) []socketEntry {
	var out []socketEntry
	lines := strings.Split(string(data), "\n")
	for _, line := range lines[min(1, len(lines)):] { // skip header
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		ip, port, err := splitProcAddr(fields[1])
		if err != nil {
			continue
		}
		state := fields[3]
		remote := fields[2]
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil || inode == 0 {
			continue
		}
		if strings.HasPrefix(proto, "tcp") {
			if state != "0A" {
				continue
			}
		} else {
			if !allZeroRemote(remote) {
				continue
			}
		}
		out = append(out, socketEntry{
			proto:  proto,
			addr:   ip.String(),
			port:   port,
			state:  state,
			remote: remote,
			inode:  inode,
		})
	}
	return out
}

func allZeroRemote(remote string) bool {
	host, port, ok := strings.Cut(remote, ":")
	if !ok {
		return false
	}
	return strings.Trim(host, "0") == "" && strings.Trim(port, "0") == ""
}

// parseSocketInode extracts N from a "socket:[N]" fd link target.
func parseSocketInode(target string) (uint64, bool) {
	if !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
		return 0, false
	}
	n, err := strconv.ParseUint(target[len("socket:["):len(target)-1], 10, 64)
	return n, err == nil
}

// mapInodesToProcesses scans /proc/<pid>/fd for the wanted socket inodes and
// returns inode -> process name (from /proc/<pid>/comm). Unreadable entries
// (no permission, process exited) are skipped silently.
func mapInodesToProcesses(fsys fs.FS, wanted map[uint64]bool) map[uint64]string {
	result := map[uint64]string{}
	if fsys == nil || len(wanted) == 0 {
		return result
	}
	procs, err := fs.ReadDir(fsys, "proc")
	if err != nil {
		return result
	}
	for _, p := range procs {
		pid := p.Name()
		if !isDigits(pid) {
			continue
		}
		fdDir := "proc/" + pid + "/fd"
		fds, err := fs.ReadDir(fsys, fdDir)
		if err != nil {
			continue
		}
		var comm string
		for _, fd := range fds {
			target, err := fs.ReadLink(fsys, fdDir+"/"+fd.Name())
			if err != nil {
				continue
			}
			inode, ok := parseSocketInode(target)
			if !ok || !wanted[inode] {
				continue
			}
			if _, done := result[inode]; done {
				continue
			}
			if comm == "" {
				if data, err := fs.ReadFile(fsys, "proc/"+pid+"/comm"); err == nil {
					comm = strings.TrimSpace(string(data))
				}
				if comm == "" {
					comm = "?"
				}
			}
			result[inode] = comm
		}
	}
	return result
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func protoOrder(p string) int {
	switch p {
	case "tcp":
		return 0
	case "tcp6":
		return 1
	case "udp":
		return 2
	default:
		return 3
	}
}

func collectSockets(ctx context.Context, env *Env) model.Facts {
	var entries []socketEntry
	readAny := false
	netDir := env.NetDir
	if netDir == "" {
		netDir = "proc/net"
	}
	for _, proto := range procNetFiles {
		data, err := env.readFile(netDir + "/" + proto)
		if err != nil {
			continue
		}
		readAny = true
		entries = append(entries, parseProcNet(data, proto)...)
	}
	if !readAny {
		return model.Facts{}
	}

	wanted := map[uint64]bool{}
	for _, e := range entries {
		wanted[e.inode] = true
	}
	procs := mapInodesToProcesses(env.FS, wanted)

	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].port != entries[j].port {
			return entries[i].port < entries[j].port
		}
		if entries[i].proto != entries[j].proto {
			return protoOrder(entries[i].proto) < protoOrder(entries[j].proto)
		}
		return entries[i].addr < entries[j].addr
	})

	listening := make([]map[string]any, 0, len(entries))
	seenPorts := map[int]bool{}
	ports := []int{}
	for _, e := range entries {
		listening = append(listening, map[string]any{
			"proto":   e.proto,
			"addr":    e.addr,
			"port":    e.port,
			"process": procs[e.inode], // "" when the owner is unknown
		})
		if !seenPorts[e.port] {
			seenPorts[e.port] = true
			ports = append(ports, e.port)
		}
	}
	sort.Ints(ports)

	return model.Facts{
		"sockets.listening": listening,
		"sockets.ports":     ports,
	}
}
