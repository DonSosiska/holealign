package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DonSosiska/panoptes/internal/server/api"
	"github.com/DonSosiska/panoptes/internal/server/config"
	"github.com/DonSosiska/panoptes/internal/server/store"
	"github.com/DonSosiska/panoptes/internal/server/web"
)

func testLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// testServers builds the servers of cfg with the real API and web UI mounted.
func testServers(t *testing.T, cfg *config.Config) map[string]http.Handler {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ui, err := web.New(web.Deps{Store: st, Config: cfg, Logger: testLog()})
	if err != nil {
		t.Fatal(err)
	}
	apiMux := api.NewMux(api.Deps{Store: st, Logger: testLog()})
	servers, err := buildServers(cfg, testLog(), apiMux, []func(*http.ServeMux){ui.Mount})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]http.Handler{}
	for _, s := range servers {
		out[s.name] = s.srv.Handler
	}
	return out
}

func status(h http.Handler, method, path string) int {
	r := httptest.NewRequest(method, path, strings.NewReader("{}"))
	r.RemoteAddr = "192.0.2.7:5555"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}

func TestSeparateListeners(t *testing.T) {
	cfg := config.Default()
	cfg.Listen, cfg.AdminListen = ":18080", "127.0.0.1:18081"
	hs := testServers(t, &cfg)
	agent, admin := hs["agent"], hs["admin"]
	if agent == nil || admin == nil || hs["shared"] != nil {
		t.Fatalf("servers: %v", hs)
	}
	for _, p := range []string{"/login", "/", "/static/x", "/static/app.css", "/settings", "/hosts", "/findings"} {
		if c := status(agent, "GET", p); c != http.StatusNotFound {
			t.Errorf("agent listener GET %s = %d, want 404", p, c)
		}
	}
	if c := status(agent, "GET", "/healthz"); c != 200 {
		t.Errorf("agent /healthz = %d", c)
	}
	if c := status(agent, "POST", "/api/v1/enroll"); c == http.StatusNotFound {
		t.Errorf("agent listener lacks /api/v1/enroll")
	}
	for _, p := range []string{"/api/v1/enroll", "/api/v1/checkin", "/api/v1/inventory"} {
		if c := status(admin, "POST", p); c != http.StatusNotFound && c != http.StatusMethodNotAllowed {
			t.Errorf("admin listener POST %s = %d, want 404/405", p, c)
		}
	}
	// the API route must not be reachable at all (a 405 would still reveal the path); the web
	// fallback answers unknown paths
	if c := status(admin, "POST", "/api/v1/enroll"); c != http.StatusNotFound {
		t.Errorf("admin POST /api/v1/enroll = %d, want 404", c)
	}
	if c := status(admin, "GET", "/healthz"); c != 200 {
		t.Errorf("admin /healthz = %d", c)
	}
	if c := status(admin, "GET", "/login"); c != 200 {
		t.Errorf("admin /login = %d", c)
	}
}

func TestLegacySinglePort(t *testing.T) {
	for _, admin := range []string{"", ":18080"} {
		cfg := config.Default()
		cfg.Listen, cfg.AdminListen = ":18080", admin
		hs := testServers(t, &cfg)
		if len(hs) != 1 || hs["shared"] == nil {
			t.Fatalf("admin_listen=%q: servers %v", admin, hs)
		}
		h := hs["shared"]
		if c := status(h, "GET", "/login"); c != 200 {
			t.Errorf("shared /login = %d", c)
		}
		if c := status(h, "POST", "/api/v1/enroll"); c == http.StatusNotFound {
			t.Errorf("shared lacks the agent API")
		}
		if c := status(h, "GET", "/healthz"); c != 200 {
			t.Errorf("shared /healthz = %d", c)
		}
	}
}

func selfSigned(t *testing.T, dir string) (certFile, keyFile string, pool *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "panoptes.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	certFile, keyFile = filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		t.Fatal(err)
	}
	pool = x509.NewCertPool()
	c, _ := x509.ParseCertificate(der)
	pool.AddCert(c)
	return
}

func TestTLSConfigLoads(t *testing.T) {
	dir := t.TempDir()
	cert, key, pool := selfSigned(t, dir)

	if tc, err := tlsConfig("", ""); err != nil || tc != nil {
		t.Fatalf("empty: %v %v", tc, err)
	}
	tc, err := tlsConfig(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	if tc.MinVersion != tls.VersionTLS12 || len(tc.Certificates) != 1 {
		t.Fatalf("config: %+v", tc)
	}
	if _, err := tlsConfig(cert, filepath.Join(dir, "missing.pem")); err == nil {
		t.Fatal("missing key accepted")
	}

	// A server built from the config serves HTTPS and refuses TLS 1.1.
	cfg := config.Default()
	cfg.Listen, cfg.AdminListen = "127.0.0.1:0", "127.0.0.1:0"
	cfg.TLSCert, cfg.TLSKey = cert, key
	cfg.AdminTLSCert, cfg.AdminTLSKey = cert, key
	st, _ := store.OpenSQLite(filepath.Join(dir, "s.db"))
	defer st.Close()
	servers, err := buildServers(&cfg, testLog(), api.NewMux(api.Deps{Store: st, Logger: testLog()}), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range servers {
		if !s.tls {
			t.Fatalf("%s: tls not enabled", s.name)
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := servers[0].srv
	go srv.ServeTLS(ln, "", "")
	defer srv.Close()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	resp, err := client.Get("https://" + ln.Addr().String() + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.TLS == nil || resp.TLS.Version < tls.VersionTLS12 {
		t.Fatalf("status %d tls %+v", resp.StatusCode, resp.TLS)
	}
	old := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MaxVersion: tls.VersionTLS11}}}
	if r, err := old.Get("https://" + ln.Addr().String() + "/healthz"); err == nil {
		r.Body.Close()
		t.Fatal("TLS 1.1 accepted")
	}
}

func TestConfigRejectsHalfTLS(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "s.yaml")
	if err := os.WriteFile(p, []byte("tls_cert: /x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(p); err == nil {
		t.Fatal("tls_cert without tls_key accepted")
	}
}
