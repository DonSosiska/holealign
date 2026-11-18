package notify

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DonSosiska/holealign/internal/model"
)

const testSMTPPassword = "smtp-p4ssw0rd-secret"

// testCert returns a server certificate for 127.0.0.1 and a pool that trusts it.
func testCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "smtp.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

// fakeSMTP is an in-process SMTP server.
type fakeSMTP struct {
	t        *testing.T
	ln       net.Listener
	cert     tls.Certificate
	pool     *x509.CertPool
	implicit bool // TLS from the first byte
	noTLS    bool // does not advertise STARTTLS
	user     string
	pass     string
	rcptCode string // reply to RCPT TO, default "250 ok"
	mailCode string
	dataCode string // reply after the message, default "250 queued"
	greet    string

	mu       sync.Mutex
	sessions int
	authed   []string // decoded AUTH PLAIN payloads
	sawAuth  bool
	plainPW  bool // true if the password was ever seen on a non-TLS connection
	froms    []string
	rcpts    []string
	data     [][]byte
	tlsConns int
}

func newFakeSMTP(t *testing.T, configure func(*fakeSMTP)) *fakeSMTP {
	t.Helper()
	cert, pool := testCert(t)
	s := &fakeSMTP{t: t, cert: cert, pool: pool, greet: "220 smtp.test ESMTP ready"}
	if configure != nil {
		configure(s)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if s.implicit {
		ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	}
	s.ln = ln
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	return s
}

type smtpSnap struct {
	sessions, tlsConns int
	sawAuth, plainPW   bool
	authed, froms      []string
	rcpts              []string
	data               [][]byte
}

// snap returns a consistent copy of what the server has seen so far.
func (s *fakeSMTP) snap() smtpSnap {
	s.mu.Lock()
	defer s.mu.Unlock()
	return smtpSnap{sessions: s.sessions, tlsConns: s.tlsConns, sawAuth: s.sawAuth, plainPW: s.plainPW,
		authed: append([]string(nil), s.authed...), froms: append([]string(nil), s.froms...),
		rcpts: append([]string(nil), s.rcpts...), data: append([][]byte(nil), s.data...)}
}

func (s *fakeSMTP) port() int { return s.ln.Addr().(*net.TCPAddr).Port }

func (s *fakeSMTP) serve(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	s.mu.Lock()
	s.sessions++
	s.mu.Unlock()
	isTLS := s.implicit
	if s.implicit {
		s.mu.Lock()
		s.tlsConns++
		s.mu.Unlock()
	}
	br := bufio.NewReader(c)
	tp := textproto.NewReader(br)
	send := func(l string) { _, _ = io.WriteString(c, l+"\r\n") }
	send(s.greet)
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		up := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(up, "EHLO"), strings.HasPrefix(up, "HELO"):
			send("250-smtp.test")
			if !s.noTLS && !isTLS {
				send("250-STARTTLS")
			}
			if s.user != "" {
				send("250-AUTH PLAIN")
			}
			send("250 8BITMIME")
		case up == "STARTTLS":
			send("220 go ahead")
			tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{s.cert}, MinVersion: tls.VersionTLS12})
			if err := tc.Handshake(); err != nil {
				return
			}
			c = tc
			br = bufio.NewReader(c)
			tp = textproto.NewReader(br)
			send = func(l string) { _, _ = io.WriteString(c, l+"\r\n") }
			isTLS = true
			s.mu.Lock()
			s.tlsConns++
			s.mu.Unlock()
		case strings.HasPrefix(up, "AUTH PLAIN"):
			payload, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(line[len("AUTH PLAIN"):]))
			s.mu.Lock()
			s.sawAuth = true
			s.authed = append(s.authed, string(payload))
			if !isTLS && strings.Contains(string(payload), s.pass) {
				s.plainPW = true
			}
			s.mu.Unlock()
			if string(payload) == "\x00"+s.user+"\x00"+s.pass {
				send("235 2.7.0 authenticated")
			} else {
				send("535 5.7.8 authentication failed for " + string(payload[strings.LastIndexByte(string(payload), 0)+1:]))
			}
		case strings.HasPrefix(up, "MAIL FROM:"):
			if s.mailCode != "" {
				send(s.mailCode)
				continue
			}
			s.mu.Lock()
			s.froms = append(s.froms, line[len("MAIL FROM:"):])
			s.mu.Unlock()
			send("250 ok")
		case strings.HasPrefix(up, "RCPT TO:"):
			if s.rcptCode != "" {
				send(s.rcptCode)
				continue
			}
			s.mu.Lock()
			s.rcpts = append(s.rcpts, line[len("RCPT TO:"):])
			s.mu.Unlock()
			send("250 ok")
		case up == "DATA":
			send("354 end with <CRLF>.<CRLF>")
			b, err := tp.ReadDotBytes()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.data = append(s.data, b)
			s.mu.Unlock()
			if s.dataCode != "" {
				send(s.dataCode)
			} else {
				send("250 queued")
			}
		case up == "QUIT":
			send("221 bye")
			return
		default:
			send("502 not implemented")
		}
	}
}

func (s *fakeSMTP) channel(t *testing.T, mut func(*SMTPConfig)) *Email {
	t.Helper()
	cfg := SMTPConfig{Host: "127.0.0.1", Port: s.port(), TLS: TLSStartTLS, From: "Holealign <alerts@example.com>"}
	if s.implicit {
		cfg.TLS = TLSImplicit
	}
	if s.user != "" {
		cfg.Username, cfg.Password = s.user, s.pass
	}
	if mut != nil {
		mut(&cfg)
	}
	e, err := NewEmailChannel(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.rootCAs = s.pool
	return e
}

func exploitableMsg() Message {
	m := buildGroup([]model.Event{testEvent(model.EventExploitable, "CVE-2024-1", "web01")})
	m.ID = "holealign-123-1-abcdef"
	return m
}

func TestEmailDestinations(t *testing.T) {
	for _, in := range []string{"email:ops@example.com", "email:a.b+tag@sub.example.co.uk", "email:o_p-s%1@ex-ample.org"} {
		if err := ValidateDestination(in); err != nil {
			t.Errorf("%q: %v", in, err)
		}
	}
	for _, in := range []string{
		"email:", "email:ops", "email:ops@", "email:@example.com", "email:ops@example", "email:ops@@example.com", "email:a@b@example.com",
		"email:Ops Team <ops@example.com>", "email:<ops@example.com>", "email:\"ops\"@example.com", "email:ops@example.com,evil@example.net",
		"email:ops@example.com;evil@example.net", "email:ops@example.com evil@example.net", "email:ops@[127.0.0.1]", "email:ops@127.0.0.1",
		"email:.ops@example.com", "email:ops.@example.com", "email:o..ps@example.com", "email:ops@-example.com", "email:ops@example..com",
		"email:ops@example.com\r\nBcc: evil@example.net", "email:ops@exämple.com", "email:öps@example.com", "email:ops@example.123",
		"email:" + strings.Repeat("a", 65) + "@example.com", "email:ops@" + strings.Repeat("a", 64) + ".com", "email:ops@example.com\x00",
		"email:ops(comment)@example.com", "email:ops@example.com>", "email:a\tb@example.com",
	} {
		if err := ValidateDestination(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestNewEmailChannelValidation(t *testing.T) {
	ok := SMTPConfig{Host: "smtp.example.com", From: "alerts@example.com"}
	e, err := NewEmailChannel(ok)
	if err != nil || e.cfg.Port != 587 || e.cfg.TLS != TLSStartTLS {
		t.Fatalf("defaults: %v %+v", err, e)
	}
	for name, mut := range map[string]func(*SMTPConfig){
		"no host":          func(c *SMTPConfig) { c.Host = "" },
		"host with space":  func(c *SMTPConfig) { c.Host = "smtp example.com" },
		"host with url":    func(c *SMTPConfig) { c.Host = "smtp://x" },
		"port 0 negative":  func(c *SMTPConfig) { c.Port = -1 },
		"port too big":     func(c *SMTPConfig) { c.Port = 70000 },
		"plain tls":        func(c *SMTPConfig) { c.TLS = "none" },
		"empty from":       func(c *SMTPConfig) { c.From = "" },
		"bad from":         func(c *SMTPConfig) { c.From = "not an address" },
		"from injection":   func(c *SMTPConfig) { c.From = "a@example.com\r\nBcc: x@example.net" },
		"user without pwd": func(c *SMTPConfig) { c.Username = "u" },
		"bad domain":       func(c *SMTPConfig) { c.AllowedDomains = []string{"Example.com"} },
		"domain no dot":    func(c *SMTPConfig) { c.AllowedDomains = []string{"localhost"} },
	} {
		c := ok
		mut(&c)
		if _, err := NewEmailChannel(c); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestEmailSTARTTLSDeliveryAndMessageShape(t *testing.T) {
	s := newFakeSMTP(t, func(s *fakeSMTP) { s.user, s.pass = "alerts", testSMTPPassword })
	e := s.channel(t, nil)
	n := newNotifier(t, Config{Default: []string{"email:ops@example.com"}}, nil, e)
	if err := n.Notify(context.Background(), []model.Event{testEvent(model.EventExploitable, "CVE-2024-1", "web01")}); err != nil {
		t.Fatal(err)
	}
	if len(s.snap().data) != 1 || s.snap().tlsConns != 1 {
		t.Fatalf("messages = %d, tls connections = %d", len(s.snap().data), s.snap().tlsConns)
	}
	if s.snap().plainPW || !s.snap().sawAuth || len(s.snap().authed) != 1 {
		t.Errorf("auth: plain password seen = %v, auth seen = %v", s.snap().plainPW, s.snap().sawAuth)
	}
	if got := strings.TrimSpace(s.snap().froms[0]); !strings.HasPrefix(got, "<alerts@example.com>") {
		t.Errorf("MAIL FROM %q", got)
	}
	if got := strings.TrimSpace(s.snap().rcpts[0]); got != "<ops@example.com>" {
		t.Errorf("RCPT TO %q", got)
	}
	m, err := mail.ReadMessage(strings.NewReader(string(s.snap().data[0])))
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Header.Get("From"); got != `"Holealign" <alerts@example.com>` && got != "Holealign <alerts@example.com>" {
		t.Errorf("From = %q", got)
	}
	if m.Header.Get("To") != "<ops@example.com>" && m.Header.Get("To") != "ops@example.com" {
		t.Errorf("To = %q", m.Header.Get("To"))
	}
	dec := new(mime.WordDecoder)
	subj, _ := dec.DecodeHeader(m.Header.Get("Subject"))
	if !strings.Contains(subj, "EXPLOITABLE: CVE-2024-1 on web01") {
		t.Errorf("Subject = %q", subj)
	}
	if !strings.HasPrefix(m.Header.Get("Message-ID"), "<holealign-") || !strings.HasSuffix(m.Header.Get("Message-ID"), "@example.com>") {
		t.Errorf("Message-ID = %q", m.Header.Get("Message-ID"))
	}
	if _, err := m.Header.Date(); err != nil {
		t.Errorf("Date: %v", err)
	}
	mt, params, err := mime.ParseMediaType(m.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/alternative" {
		t.Fatalf("content type %q %v", m.Header.Get("Content-Type"), err)
	}
	mr := multipart.NewReader(m.Body, params["boundary"])
	var types []string
	for {
		p, err := mr.NextPart()
		if err != nil {
			break
		}
		types = append(types, strings.SplitN(p.Header.Get("Content-Type"), ";", 2)[0])
		body, _ := io.ReadAll(quotedprintable.NewReader(p))
		if strings.Contains(p.Header.Get("Content-Type"), "text/plain") && !strings.Contains(string(body), "Package: openssl 3.0.1") {
			t.Errorf("plain part = %q", body)
		}
		if strings.Contains(p.Header.Get("Content-Type"), "text/html") && !strings.Contains(string(body), "<b>EXPLOITABLE: CVE-2024-1 on web01</b>") {
			t.Errorf("html part = %q", body)
		}
	}
	if len(types) != 2 || types[0] != "text/plain" || types[1] != "text/html" {
		t.Errorf("parts = %v", types)
	}
}

func TestEmailImplicitTLS(t *testing.T) {
	s := newFakeSMTP(t, func(s *fakeSMTP) { s.implicit = true; s.user, s.pass = "alerts", testSMTPPassword })
	if err := s.channel(t, nil).Send(context.Background(), "ops@example.com", exploitableMsg()); err != nil {
		t.Fatal(err)
	}
	if len(s.snap().data) != 1 || s.snap().tlsConns != 1 || s.snap().plainPW {
		t.Errorf("messages = %d, tls = %d, plain password = %v", len(s.snap().data), s.snap().tlsConns, s.snap().plainPW)
	}
}

func TestEmailRefusesWithoutTLS(t *testing.T) {
	s := newFakeSMTP(t, func(s *fakeSMTP) { s.noTLS = true; s.user, s.pass = "alerts", testSMTPPassword })
	err := s.channel(t, nil).Send(context.Background(), "ops@example.com", exploitableMsg())
	var se *SendError
	if !errors.As(err, &se) || !se.Permanent || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("err = %v", err)
	}
	if s.snap().sawAuth || len(s.snap().data) != 0 || len(s.snap().rcpts) != 0 || len(s.snap().froms) != 0 {
		t.Errorf("session continued without TLS: auth=%v data=%d rcpt=%v", s.snap().sawAuth, len(s.snap().data), s.snap().rcpts)
	}
	// the same without credentials
	s2 := newFakeSMTP(t, func(s *fakeSMTP) { s.noTLS = true })
	if err := s2.channel(t, nil).Send(context.Background(), "ops@example.com", exploitableMsg()); err == nil || len(s2.snap().data) != 0 {
		t.Errorf("no-auth session sent without TLS: %v", err)
	}
	// implicit TLS against a plain-text server fails instead of falling back
	s3 := newFakeSMTP(t, nil)
	e := s3.channel(t, func(c *SMTPConfig) { c.TLS = TLSImplicit })
	if err := e.Send(context.Background(), "ops@example.com", exploitableMsg()); err == nil || len(s3.snap().data) != 0 {
		t.Errorf("implicit TLS against a plain server: %v", err)
	}
}

func TestEmailVerifiesServerCertificate(t *testing.T) {
	s := newFakeSMTP(t, func(s *fakeSMTP) { s.user, s.pass = "alerts", testSMTPPassword })
	e := s.channel(t, nil)
	e.rootCAs = nil // the self-signed test certificate is not trusted
	err := e.Send(context.Background(), "ops@example.com", exploitableMsg())
	var se *SendError
	if !errors.As(err, &se) || !se.Permanent {
		t.Fatalf("err = %v", err)
	}
	if s.snap().sawAuth || len(s.snap().data) != 0 {
		t.Errorf("credentials or data sent to an unverified server: auth=%v data=%d", s.snap().sawAuth, len(s.snap().data))
	}
	// wrong host name
	s2 := newFakeSMTP(t, nil)
	e2 := s2.channel(t, func(c *SMTPConfig) { c.Host = "localhost" })
	if err := e2.Send(context.Background(), "ops@example.com", exploitableMsg()); err == nil || len(s2.snap().data) != 0 {
		t.Errorf("certificate for 127.0.0.1 accepted for localhost: %v", err)
	}
}

func TestEmailAllowedDomains(t *testing.T) {
	s := newFakeSMTP(t, nil)
	e := s.channel(t, func(c *SMTPConfig) { c.AllowedDomains = []string{"example.com"} })
	if err := e.ValidTarget("ops@example.com"); err != nil {
		t.Error(err)
	}
	for _, bad := range []string{"ops@evil.example", "ops@sub.example.com", "ops@example.com.evil.example", "ops@notexample.com"} {
		if err := e.ValidTarget(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
		err := e.Send(context.Background(), bad, exploitableMsg())
		var se *SendError
		if !errors.As(err, &se) || !se.Permanent {
			t.Errorf("%q: Send err = %v", bad, err)
		}
	}
	if s.snap().sessions != 0 {
		t.Errorf("a disallowed recipient reached the SMTP server (%d sessions)", s.snap().sessions)
	}
	if err := e.Send(context.Background(), "OPS@EXAMPLE.COM", exploitableMsg()); err != nil {
		t.Errorf("case-insensitive domain: %v", err)
	}
}

func TestEmailHeaderInjectionInSubject(t *testing.T) {
	s := newFakeSMTP(t, nil)
	e := s.channel(t, nil)
	msg := Message{ID: "id\r\nBcc: evil@example.net", Lines: []Line{
		{txt("Alert\r\nBcc: evil@example.net\r\nX-Evil: 1 Subject: x\x00\x07 on "), bold("web‮01")},
		{txt("body")},
	}}
	if err := e.Send(context.Background(), "ops@example.com", msg); err != nil {
		t.Fatal(err)
	}
	m, err := mail.ReadMessage(strings.NewReader(string(s.snap().data[0])))
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"Bcc", "X-Evil"} {
		if m.Header.Get(h) != "" {
			t.Errorf("injected header %s present", h)
		}
	}
	if got := m.Header["Subject"]; len(got) != 1 {
		t.Errorf("subjects = %v", got)
	}
	subj, _ := new(mime.WordDecoder).DecodeHeader(m.Header.Get("Subject"))
	if strings.ContainsAny(subj, "\r\n\x00\x07 ‮") || !strings.Contains(subj, "Alert Bcc: evil@example.net") {
		t.Errorf("subject = %q", subj)
	}
	if strings.ContainsAny(m.Header.Get("Message-ID"), "\r\n ") || len(m.Header["Message-Id"]) != 1 {
		t.Errorf("Message-ID = %q", m.Header.Get("Message-ID"))
	}
	if len(s.snap().rcpts) != 1 {
		t.Errorf("recipients = %v", s.snap().rcpts)
	}
	// every header line of the raw message is one of ours
	head, _, _ := strings.Cut(string(s.snap().data[0]), "\r\n\r\n")
	for _, l := range strings.Split(head, "\r\n") {
		if strings.HasPrefix(l, " ") {
			continue
		}
		k, _, _ := strings.Cut(l, ":")
		switch k {
		case "From", "To", "Subject", "Date", "Message-ID", "MIME-Version", "Auto-Submitted", "Content-Type":
		default:
			t.Errorf("unexpected header line %q", l)
		}
	}
}

func TestEmailHostileBodyIsInert(t *testing.T) {
	s := newFakeSMTP(t, nil)
	e := s.channel(t, nil)
	ev := hostile()
	ev.Host.Hostname = "<script>alert(1)</script>" + strings.Repeat("h<&>", 2500)
	m := buildGroup([]model.Event{ev})
	m.ID = "x"
	if err := e.Send(context.Background(), "ops@example.com", m); err != nil {
		t.Fatal(err)
	}
	if len(s.snap().data[0]) > 40<<10 {
		t.Errorf("message is %d bytes", len(s.snap().data[0]))
	}
	msg, _ := mail.ReadMessage(strings.NewReader(string(s.snap().data[0])))
	_, params, _ := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	mr := multipart.NewReader(msg.Body, params["boundary"])
	for {
		p, err := mr.NextPart()
		if err != nil {
			break
		}
		body, _ := io.ReadAll(quotedprintable.NewReader(p))
		if strings.Contains(p.Header.Get("Content-Type"), "text/html") {
			for _, bad := range []string{"<script>", "<a href=\"https://evil.example\">x", "<b>b</b>", "<i>"} {
				if strings.Contains(string(body), bad) {
					t.Errorf("html part contains %q", bad)
				}
			}
			if !strings.Contains(string(body), "&lt;script&gt;") {
				t.Error("script tag not escaped")
			}
		}
	}
}

func TestEmailSMTPErrorMapping(t *testing.T) {
	cases := []struct {
		name      string
		set       func(*fakeSMTP)
		permanent bool
		attempts  int // SMTP sessions
	}{
		{"rcpt 550", func(s *fakeSMTP) { s.rcptCode = "550 5.1.1 no such user" }, true, 1},
		{"rcpt 452", func(s *fakeSMTP) { s.rcptCode = "452 4.2.2 mailbox full" }, false, maxAttempts},
		{"mail 421", func(s *fakeSMTP) { s.mailCode = "421 4.3.2 shutting down" }, false, maxAttempts},
		{"data 554", func(s *fakeSMTP) { s.dataCode = "554 5.7.1 rejected as spam" }, true, 1},
		{"data 451", func(s *fakeSMTP) { s.dataCode = "451 4.3.0 try later" }, false, maxAttempts},
		{"greeting 554", func(s *fakeSMTP) { s.greet = "554 no service" }, true, 1},
		{"greeting 421", func(s *fakeSMTP) { s.greet = "421 busy" }, false, maxAttempts},
	}
	for _, c := range cases {
		s := newFakeSMTP(t, c.set)
		pl := &problemLog{}
		n := newNotifier(t, Config{Default: []string{"email:ops@example.com"}, OnDeliveryProblem: pl.add}, nil, s.channel(t, nil))
		_ = n.Notify(context.Background(), []model.Event{testEvent(model.EventExploitable, "CVE-1", "h")})
		got := s.snap().sessions
		if got != c.attempts {
			t.Errorf("%s: sessions = %d, want %d", c.name, got, c.attempts)
		}
		ps := pl.all()
		if len(ps) != 1 || ps[0].permanent != c.permanent || ps[0].room != "email:ops@example.com" {
			t.Errorf("%s: problems = %+v", c.name, ps)
		}
	}
	// connection refused is transient
	s := newFakeSMTP(t, nil)
	e := s.channel(t, nil)
	s.ln.Close()
	err := e.Send(context.Background(), "ops@example.com", exploitableMsg())
	var se *SendError
	if !errors.As(err, &se) || se.Permanent {
		t.Errorf("refused: %v", err)
	}
}

func TestEmailPasswordNeverInErrors(t *testing.T) {
	// the server echoes the password in its rejection
	s := newFakeSMTP(t, func(s *fakeSMTP) { s.user, s.pass = "alerts", testSMTPPassword })
	e := s.channel(t, func(c *SMTPConfig) { c.Password = testSMTPPassword + "x" }) // wrong password
	err := e.Send(context.Background(), "ops@example.com", exploitableMsg())
	var se *SendError
	if !errors.As(err, &se) || !se.Permanent || se.Status != 535 {
		t.Fatalf("auth failure: %#v", err)
	}
	if strings.Contains(err.Error(), testSMTPPassword) {
		t.Errorf("error contains the password: %v", err)
	}
	s2 := newFakeSMTP(t, func(s *fakeSMTP) {
		s.rcptCode = "550 rejected " + testSMTPPassword
		s.user, s.pass = "u", testSMTPPassword
	})
	e2 := s2.channel(t, nil)
	err = e2.Send(context.Background(), "ops@example.com", exploitableMsg())
	if err == nil || strings.Contains(err.Error(), testSMTPPassword) {
		t.Errorf("error = %v", err)
	}
}

func TestEmailContextDeadline(t *testing.T) {
	// a server that accepts and never answers
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	e, _ := NewEmailChannel(SMTPConfig{Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, From: "a@example.com"})
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = e.Send(ctx, "ops@example.com", exploitableMsg())
	if err == nil || time.Since(start) > 5*time.Second {
		t.Errorf("err = %v after %v", err, time.Since(start))
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want the context error", err)
	}
}

func TestFormatEmailSubject(t *testing.T) {
	subj, plain, html := formatEmail(Message{Lines: []Line{{txt("🔴 "), bold("EXPLOITABLE: CVE-1 on " + strings.Repeat("h", 500))}}})
	if len([]rune(subj)) > emailMaxSubject || !strings.HasPrefix(subj, "🔴 EXPLOITABLE") {
		t.Errorf("subject = %q", subj)
	}
	if plain == "" || !strings.Contains(html, "<body") {
		t.Error("bodies missing")
	}
	if s, _, _ := formatEmail(Message{}); s != "Holealign notification" {
		t.Errorf("empty subject = %q", s)
	}
}
