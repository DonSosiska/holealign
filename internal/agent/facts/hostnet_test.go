package facts

import (
	"testing"
	"testing/fstest"
)

// In a private network namespace /proc/net is empty; the collector reads the host's
// namespace through /proc/1/net.
func TestCollectSocketsHostNetNS(t *testing.T) {
	hdr := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	fsys := fstest.MapFS{
		"proc/net/tcp":   {Data: []byte(hdr)},
		"proc/1/net/tcp": {Data: fixture(t, "proc_net_tcp.txt")},
	}
	private := collectSockets(t.Context(), &Env{FS: fsys})
	if ports, _ := private["sockets.ports"].([]int); len(ports) != 0 {
		t.Fatalf("private /proc/net should list nothing, got %v", ports)
	}
	f := collectSockets(t.Context(), &Env{FS: fsys, NetDir: hostNetDir})
	if ports, _ := f["sockets.ports"].([]int); len(ports) == 0 {
		t.Fatalf("/proc/1/net must be used: %v", f)
	}
	// unreadable /proc/1/net => unknown (absent), never an empty list taken from /proc/net
	only := fstest.MapFS{"proc/net/tcp": {Data: []byte(hdr)}}
	if f := collectSockets(t.Context(), &Env{FS: only, NetDir: hostNetDir}); len(f) != 0 {
		t.Errorf("want no sockets facts, got %v", f)
	}
}
