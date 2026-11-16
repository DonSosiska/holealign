package clientip

import (
	"net"
	"net/http/httptest"
	"testing"
)

func TestClientIP(t *testing.T) {
	_, proxy, _ := net.ParseCIDR("10.0.0.0/8")
	_, proxy2, _ := net.ParseCIDR("192.168.1.5/32")
	f := New([]*net.IPNet{proxy, proxy2})
	cases := []struct {
		name, remote string
		xff          []string
		want         string
	}{
		{"untrusted peer: XFF ignored (spoofing)", "203.0.113.9:1234", []string{"1.2.3.4"}, "203.0.113.9"},
		{"trusted peer, single entry", "10.1.1.1:80", []string{"198.51.100.7"}, "198.51.100.7"},
		{"client-supplied prefix is ignored: right-most untrusted wins", "10.1.1.1:80", []string{"6.6.6.6, 198.51.100.7"}, "198.51.100.7"},
		{"chain of trusted proxies skipped", "10.1.1.1:80", []string{"198.51.100.7, 192.168.1.5, 10.2.2.2"}, "198.51.100.7"},
		{"multiple header lines", "10.1.1.1:80", []string{"6.6.6.6", "198.51.100.7"}, "198.51.100.7"},
		{"no header", "10.1.1.1:80", nil, "10.1.1.1"},
		{"malformed right-most entry", "10.1.1.1:80", []string{"198.51.100.7, garbage"}, "10.1.1.1"},
		{"all trusted", "10.1.1.1:80", []string{"10.3.3.3"}, "10.1.1.1"},
		{"ipv6 client", "10.1.1.1:80", []string{"2001:db8::1"}, "2001:db8::1"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.remote
		for _, v := range c.xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		if got := f(r); got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
	// no trusted proxies configured: always the peer
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.1.1.1:80"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := New(nil)(r); got != "10.1.1.1" {
		t.Errorf("got %s", got)
	}
}
