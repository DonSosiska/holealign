package transport

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// TLSOptions configure server identity checks and the optional client certificate.
type TLSOptions struct {
	// CAFile is a PEM bundle. When set, ONLY these roots are trusted (system roots are not used).
	CAFile string
	// PinsSHA256 are hex SHA-256 fingerprints of the server leaf certificate's
	// SubjectPublicKeyInfo. When non-empty the presented leaf must match one of
	// them in addition to normal chain validation.
	PinsSHA256 []string
	// ClientCert/ClientKey (PEM file paths) enable mTLS when both are set.
	ClientCert, ClientKey string
}

// SPKIHash returns the hex SHA-256 of the certificate's SubjectPublicKeyInfo.
func SPKIHash(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// BuildTLSConfig turns the options into a tls.Config. InsecureSkipVerify is never set:
// normal chain and host name validation always run; pins are checked on top.
func BuildTLSConfig(o TLSOptions) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if o.CAFile != "" {
		data, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, fmt.Errorf("transport: ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("transport: ca_file %s contains no PEM certificate", o.CAFile)
		}
		cfg.RootCAs = pool
	}
	if (o.ClientCert == "") != (o.ClientKey == "") {
		return nil, errors.New("transport: client_cert and client_key must be set together")
	}
	if o.ClientCert != "" {
		pair, err := tls.LoadX509KeyPair(o.ClientCert, o.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("transport: client certificate: %w", err)
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	if len(o.PinsSHA256) > 0 {
		pins := make(map[string]bool, len(o.PinsSHA256))
		for _, p := range o.PinsSHA256 {
			n := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(p), ":", ""))
			if b, err := hex.DecodeString(n); err != nil || len(b) != sha256.Size {
				return nil, fmt.Errorf("transport: invalid pin %q (want 64 hex characters)", p)
			}
			pins[n] = true
		}
		// VerifyConnection runs after the normal chain verification succeeded.
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("server presented no certificate")
			}
			got := SPKIHash(cs.PeerCertificates[0])
			if !pins[got] {
				slog.Error("server certificate does not match any configured pin; refusing the connection "+
					"(if the certificate was legitimately replaced, add the new SPKI hash to server_cert_sha256)",
					"presented_spki_sha256", got, "configured_pins", len(pins))
				return fmt.Errorf("server certificate pin mismatch: presented SPKI sha256 %s matches none of the %d configured server_cert_sha256 pins", got, len(pins))
			}
			return nil
		}
	}
	return cfg, nil
}

// NewWithTLS is New with TLS identity options applied.
func NewWithTLS(baseURL, key string, o TLSOptions) (*Client, error) {
	tcfg, err := BuildTLSConfig(o)
	if err != nil {
		return nil, err
	}
	c := New(baseURL, key)
	if tr, ok := c.HTTP.Transport.(*http.Transport); ok {
		tr.TLSClientConfig = tcfg
	}
	return c, nil
}

// FetchServerPin connects to the https server URL, validates the chain normally (with
// ca_file when set) and returns the leaf SPKI SHA-256. It is a convenience for
// operators, not trust-on-first-use: the chain must already be valid, and the
// operator is expected to compare the value out of band before pinning it.
func FetchServerPin(ctx context.Context, serverURL string, o TLSOptions) (string, error) {
	u, err := url.Parse(serverURL)
	if err != nil || u.Host == "" {
		return "", errors.New("invalid server_url")
	}
	if u.Scheme != "https" {
		return "", errors.New("server_url must be https:// to have a certificate")
	}
	o.PinsSHA256 = nil
	tcfg, err := BuildTLSConfig(o)
	if err != nil {
		return "", err
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	tcfg.ServerName = host
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 15 * time.Second}, Config: tcfg}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return "", fmt.Errorf("connect %s: %w", net.JoinHostPort(host, port), err)
	}
	defer conn.Close()
	cs := conn.(*tls.Conn).ConnectionState()
	if len(cs.PeerCertificates) == 0 {
		return "", errors.New("server presented no certificate")
	}
	return SPKIHash(cs.PeerCertificates[0]), nil
}
