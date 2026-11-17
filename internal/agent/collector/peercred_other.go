//go:build !linux

package collector

import (
	"errors"
	"net"
)

// peerUID is unavailable off Linux: connections are rejected unless Server.PeerUID is set
// (tests). The collector is only supported on Linux.
func peerUID(net.Conn) (uint32, error) {
	return 0, errors.New("peer credentials are only supported on Linux")
}
