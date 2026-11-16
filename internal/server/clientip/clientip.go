// Package clientip derives the client address of a request, honouring X-Forwarded-For only when
// the TCP peer is a configured trusted proxy (so the header cannot be spoofed by other peers).
package clientip

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Peer returns the IP of the TCP peer.
func Peer(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

// New returns a function yielding the client IP. With no trusted proxies it is Peer. When the
// peer is in trusted, the client is the right-most X-Forwarded-For entry that is not itself a
// trusted proxy; a missing or malformed header falls back to the peer address.
func New(trusted []*net.IPNet) func(*http.Request) string {
	if len(trusted) == 0 {
		return Peer
	}
	isTrusted := func(a netip.Addr) bool {
		ip := net.IP(a.AsSlice())
		for _, n := range trusted {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}
	return func(r *http.Request) string {
		peer := Peer(r)
		pa, err := netip.ParseAddr(peer)
		if err != nil || !isTrusted(pa.Unmap()) {
			return peer
		}
		var entries []string
		for _, v := range r.Header.Values("X-Forwarded-For") {
			for _, e := range strings.Split(v, ",") {
				entries = append(entries, strings.TrimSpace(e))
			}
		}
		for i := len(entries) - 1; i >= 0; i-- {
			a, err := netip.ParseAddr(entries[i])
			if err != nil {
				return peer // malformed entry: do not guess
			}
			a = a.Unmap()
			if !isTrusted(a) {
				return a.String()
			}
		}
		return peer
	}
}
