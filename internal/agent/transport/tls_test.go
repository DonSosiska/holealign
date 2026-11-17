package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DonSosiska/panoptes/internal/model"
)

type testPKI struct {
	caPEM      []byte
	caCert     *x509.Certificate
	caKey      *ecdsa.PrivateKey
	serverCert tls.Certificate
	serverLeaf *x509.Certificate
}

func issue(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, tmpl *x509.Certificate) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl.SerialNumber, _ = rand.Int(rand.Reader, big.NewInt(1<<60))
	tmpl.NotBefore = time.Now().Add(-time.Hour)
	tmpl.NotAfter = time.Now().Add(time.Hour)
	parent, signer := tmpl, key
	if ca != nil {
		parent, signer = ca, caKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func newPKI(t *testing.T) *testPKI {
	t.Helper()
	ca, caKey, caPEM := issue(t, nil, nil, &x509.Certificate{
		Subject: pkix.Name{CommonName: "test ca"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	})
	leaf, leafKey, leafPEM := issue(t, ca, caKey, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "server"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	keyDER, _ := x509.MarshalECPrivateKey(leafKey)
	pair, err := tls.X509KeyPair(leafPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	return &testPKI{caPEM: caPEM, caCert: ca, caKey: caKey, serverCert: pair, serverLeaf: leaf}
}

func (p *testPKI) server(t *testing.T, cfg *tls.Config) *httptest.Server {
	t.Helper()
	if cfg == nil {
		cfg = &tls.Config{}
	}
	cfg.Certificates = []tls.Certificate{p.serverCert}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`))
	}))
	srv.TLS = cfg
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func writeFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func try(t *testing.T, url string, o TLSOptions) error {
	t.Helper()
	c, err := NewWithTLS(url, "k", o)
	if err != nil {
		t.Fatal(err)
	}
	c.MaxAttempts = 1
	return c.UploadInventory(context.Background(), model.InventoryPayload{Hash: "h"})
}

func TestPinMatchAndMismatch(t *testing.T) {
	pki := newPKI(t)
	srv := pki.server(t, nil)
	ca := writeFile(t, "ca.pem", pki.caPEM)
	good := SPKIHash(pki.serverLeaf)

	if err := try(t, srv.URL, TLSOptions{CAFile: ca, PinsSHA256: []string{good}}); err != nil {
		t.Fatalf("correct pin must pass: %v", err)
	}
	// upper case and colon-separated forms are accepted
	if err := try(t, srv.URL, TLSOptions{CAFile: ca, PinsSHA256: []string{strings.ToUpper(good)}}); err != nil {
		t.Fatalf("upper-case pin: %v", err)
	}
	wrong := strings.Repeat("ab", 32)
	err := try(t, srv.URL, TLSOptions{CAFile: ca, PinsSHA256: []string{wrong}})
	if err == nil {
		t.Fatal("wrong pin must fail")
	}
	if !strings.Contains(err.Error(), "pin mismatch") || !strings.Contains(err.Error(), good) {
		t.Errorf("error should name the presented hash: %v", err)
	}
	// any one of several pins is enough
	if err := try(t, srv.URL, TLSOptions{CAFile: ca, PinsSHA256: []string{wrong, good}}); err != nil {
		t.Fatalf("pin list: %v", err)
	}
}

func TestPinDoesNotReplaceChainValidation(t *testing.T) {
	pki := newPKI(t)
	srv := pki.server(t, nil)
	// correct pin, but no ca_file: system roots do not know the test CA
	err := try(t, srv.URL, TLSOptions{PinsSHA256: []string{SPKIHash(pki.serverLeaf)}})
	if err == nil {
		t.Fatal("chain validation must still run when only pins are set")
	}
	if !strings.Contains(err.Error(), "certificate") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCAFileTrustedSystemRootsNot(t *testing.T) {
	pki := newPKI(t)
	srv := pki.server(t, nil)
	if err := try(t, srv.URL, TLSOptions{}); err == nil {
		t.Fatal("system roots must not trust the test CA")
	}
	ca := writeFile(t, "ca.pem", pki.caPEM)
	if err := try(t, srv.URL, TLSOptions{CAFile: ca}); err != nil {
		t.Fatalf("ca_file with the test CA must pass: %v", err)
	}
	// a ca_file with an unrelated CA replaces (not extends) the trust store
	other := newPKI(t)
	if err := try(t, srv.URL, TLSOptions{CAFile: writeFile(t, "o.pem", other.caPEM)}); err == nil {
		t.Fatal("other CA must not validate the server")
	}
}

func TestMutualTLS(t *testing.T) {
	pki := newPKI(t)
	clientCert, clientKey, clientPEM := issue(t, pki.caCert, pki.caKey, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "agent-1"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	_ = clientCert
	keyDER, _ := x509.MarshalECPrivateKey(clientKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pki.caPEM)
	var gotCN string
	srv := pki.server(t, &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) > 0 {
				gotCN = cs.PeerCertificates[0].Subject.CommonName
			}
			return nil
		}})
	ca := writeFile(t, "ca.pem", pki.caPEM)

	if err := try(t, srv.URL, TLSOptions{CAFile: ca}); err == nil {
		t.Fatal("server requires a client certificate")
	}
	err := try(t, srv.URL, TLSOptions{CAFile: ca, ClientCert: writeFile(t, "c.pem", clientPEM), ClientKey: writeFile(t, "k.pem", keyPEM)})
	if err != nil {
		t.Fatalf("mTLS: %v", err)
	}
	if gotCN != "agent-1" {
		t.Errorf("server saw client CN %q", gotCN)
	}
}

func TestBuildTLSConfigErrors(t *testing.T) {
	if _, err := BuildTLSConfig(TLSOptions{CAFile: "/nonexistent/ca.pem"}); err == nil {
		t.Error("unreadable ca_file")
	}
	if _, err := BuildTLSConfig(TLSOptions{CAFile: writeFile(t, "x.pem", []byte("not pem"))}); err == nil {
		t.Error("ca_file without certificates")
	}
	if _, err := BuildTLSConfig(TLSOptions{ClientCert: "/x"}); err == nil {
		t.Error("client_cert without client_key")
	}
	if _, err := BuildTLSConfig(TLSOptions{PinsSHA256: []string{"zz"}}); err == nil {
		t.Error("bad pin")
	}
	cfg, err := BuildTLSConfig(TLSOptions{})
	if err != nil || cfg.InsecureSkipVerify || cfg.MinVersion < tls.VersionTLS12 {
		t.Errorf("default config: %+v %v", cfg, err)
	}
}

func TestFetchServerPin(t *testing.T) {
	pki := newPKI(t)
	srv := pki.server(t, nil)
	ca := writeFile(t, "ca.pem", pki.caPEM)
	got, err := FetchServerPin(context.Background(), srv.URL, TLSOptions{CAFile: ca})
	if err != nil || got != SPKIHash(pki.serverLeaf) {
		t.Fatalf("pin = %q err = %v", got, err)
	}
	// the chain is validated: an untrusted server yields an error, not a pin
	if got, err := FetchServerPin(context.Background(), srv.URL, TLSOptions{}); err == nil {
		t.Fatalf("untrusted chain must not yield a pin (got %q)", got)
	}
	if _, err := FetchServerPin(context.Background(), "http://x", TLSOptions{}); err == nil {
		t.Error("http has no certificate")
	}
}
