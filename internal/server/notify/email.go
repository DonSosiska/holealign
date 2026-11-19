package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	emailScheme = "email"

	// SMTP TLS modes.
	TLSStartTLS = "starttls"
	TLSImplicit = "implicit"

	emailDialTimeout = 10 * time.Second
	emailTotalLimit  = 60 * time.Second // whole SMTP transaction when the context has no deadline
	emailMaxSubject  = 150
)

func init() { registerChannel(emailScheme, ValidMailbox) }

var (
	mailLocalRe = regexp.MustCompile(`^[A-Za-z0-9_+-]+(\.[A-Za-z0-9_+-]+)*$`)
	mailLabelRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	hostNameRe  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
)

// ValidMailbox checks a single RFC 5321 mailbox "local@domain" strictly: no display name, no angle
// brackets, no quoted local part, no comments, no address literal, ASCII only. The local part is
// dot-separated atoms of letters, digits and "_+-" (at most 64 bytes); "%" is excluded to prevent
// SMTP percent-hack relays from rerouting allowed_domains addresses. The domain has at least two
// LDH labels, the last not numeric (at most 253 bytes).
func ValidMailbox(addr string) error {
	local, domain, ok := strings.Cut(addr, "@")
	switch {
	case !ok || strings.Contains(domain, "@"):
		return errors.New("not an email address (expected local@domain.tld)")
	case len(addr) > 254 || len(local) == 0 || len(local) > 64 || !mailLocalRe.MatchString(local):
		return errors.New("not a plain email address (no display name, quotes or special characters; local part up to 64 characters of a-z 0-9 . _ + -)")
	case len(domain) > 253:
		return errors.New("email domain is too long")
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return errors.New("email domain needs at least two labels (example.com)")
	}
	for _, l := range labels {
		if !mailLabelRe.MatchString(l) {
			return errors.New("invalid email domain")
		}
	}
	if _, err := strconv.Atoi(labels[len(labels)-1]); err == nil {
		return errors.New("invalid email domain")
	}
	return nil
}

// MailboxDomain returns the lower-case domain of a valid mailbox.
func MailboxDomain(addr string) string {
	_, d, _ := strings.Cut(addr, "@")
	return strings.ToLower(d)
}

// ValidMailDomain checks an allowed_domains entry (a domain such as example.com).
func ValidMailDomain(d string) error {
	if d != strings.ToLower(d) {
		return errors.New("domain must be lower case")
	}
	return ValidMailbox("x@" + d)
}

// ValidSMTPHost checks the SMTP server host (a name or an IP address).
func ValidSMTPHost(h string) error {
	if net.ParseIP(h) != nil || hostNameRe.MatchString(h) {
		return nil
	}
	return errors.New("not a host name or IP address")
}

// SMTPConfig configures the email channel.
type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string // only used with Username
	TLS      string // TLSStartTLS (default) or TLSImplicit
	From     string // "alerts@example.com" or "Holealign <alerts@example.com>"
	// AllowedDomains, when not empty, limits the recipients to these (lower case) domains.
	AllowedDomains []string
}

// Email sends messages through an SMTP server. TLS is mandatory: the connection is encrypted with
// STARTTLS (and refused when the server does not offer it) or from the start (implicit TLS), the
// server certificate is verified against the system roots, and the password is only sent after
// that. There is no fallback to plain text.
type Email struct {
	cfg  SMTPConfig
	from mail.Address
	// test hooks
	rootCAs *x509.CertPool
	now     func() time.Time
}

var _ Channel = (*Email)(nil)

// NewEmailChannel validates the configuration.
func NewEmailChannel(cfg SMTPConfig) (*Email, error) {
	if err := ValidSMTPHost(cfg.Host); err != nil {
		return nil, fmt.Errorf("notify: email smtp host: %w", err)
	}
	if cfg.Port == 0 {
		cfg.Port = 587
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return nil, errors.New("notify: email smtp port must be 1-65535")
	}
	if cfg.TLS == "" {
		cfg.TLS = TLSStartTLS
	}
	if cfg.TLS != TLSStartTLS && cfg.TLS != TLSImplicit {
		return nil, fmt.Errorf("notify: email smtp tls must be %q or %q (plain text is not supported)", TLSStartTLS, TLSImplicit)
	}
	if cfg.Username != "" && cfg.Password == "" {
		return nil, errors.New("notify: email smtp username is set but the password is empty")
	}
	if strings.ContainsAny(cfg.Username, "\r\n\x00") || strings.ContainsAny(cfg.Password, "\r\n\x00") {
		return nil, errors.New("notify: email smtp credentials contain control characters")
	}
	from, err := ParseSender(cfg.From)
	if err != nil {
		return nil, fmt.Errorf("notify: email smtp from: %w", err)
	}
	for _, d := range cfg.AllowedDomains {
		if err := ValidMailDomain(d); err != nil {
			return nil, fmt.Errorf("notify: email allowed_domains %q: %w", clip(d, 60), err)
		}
	}
	return &Email{cfg: cfg, from: from, now: time.Now}, nil
}

// ParseSender parses the From setting: a plain address or "Name <address>".
func ParseSender(s string) (mail.Address, error) {
	if strings.TrimSpace(s) == "" {
		return mail.Address{}, errors.New("is empty")
	}
	if strings.ContainsAny(s, "\r\n\x00") {
		return mail.Address{}, errors.New("contains control characters")
	}
	a, err := mail.ParseAddress(s)
	if err != nil {
		return mail.Address{}, errors.New("not a valid address (expected alerts@example.com or Holealign <alerts@example.com>)")
	}
	if err := ValidMailbox(a.Address); err != nil {
		return mail.Address{}, err
	}
	a.Name = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, a.Name)
	return *a, nil
}

func (e *Email) Scheme() string { return emailScheme }

func (e *Email) ValidTarget(target string) error { return e.checkRecipient(target) }

func (e *Email) checkRecipient(t string) error {
	if err := ValidMailbox(t); err != nil {
		return err
	}
	if len(e.cfg.AllowedDomains) > 0 && !containsFold(e.cfg.AllowedDomains, MailboxDomain(t)) {
		return fmt.Errorf("domain %q is not in email.allowed_domains", MailboxDomain(t))
	}
	return nil
}

func containsFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// emailError builds a SendError from a failed SMTP step. 4xx replies are transient, 5xx permanent.
// Anything that is not an SMTP reply (network, timeout) is transient, except certificate errors,
// which retrying cannot fix. The password is removed from the text.
func (e *Email) emailError(step string, err error) error {
	text := clBase(stripSecret(err.Error(), e.cfg.Password))
	if len(text) > 160 {
		text = strings.ToValidUTF8(text[:160], "") + "..."
	}
	var te *textproto.Error
	var ce x509.CertificateInvalidError
	var ua x509.UnknownAuthorityError
	var hn x509.HostnameError
	switch {
	case errors.As(err, &te):
		return &SendError{Status: te.Code, Permanent: te.Code >= 500, Err: fmt.Errorf("smtp %s: %s", step, text)}
	case errors.As(err, &ce), errors.As(err, &ua), errors.As(err, &hn):
		return &SendError{Permanent: true, Err: fmt.Errorf("smtp %s: server certificate rejected: %s", step, text)}
	}
	return &SendError{Err: fmt.Errorf("smtp %s: %s", step, text)}
}

func (e *Email) Send(ctx context.Context, to string, msg Message) (err error) {
	if err := e.checkRecipient(to); err != nil {
		return &SendError{Permanent: true, Err: fmt.Errorf("email destination: %w", err)}
	}
	data, err := e.buildMessage(to, msg)
	if err != nil {
		return &SendError{Permanent: true, Err: err}
	}

	addr := net.JoinHostPort(e.cfg.Host, strconv.Itoa(e.cfg.Port))
	deadline := e.now().Add(emailTotalLimit)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	dialer := net.Dialer{Timeout: emailDialTimeout}
	conn, derr := dialer.DialContext(ctx, "tcp", addr)
	if derr != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return e.emailError("connect", derr)
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)
	// closing the connection interrupts a blocked read or write when the context ends
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	defer func() {
		if err == nil {
			return
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		} else if d, ok := ctx.Deadline(); ok && !time.Now().Before(d) {
			// the connection deadline (the context deadline) fired a moment before the context did
			err = context.DeadlineExceeded
		}
	}()

	tlsConf := &tls.Config{ServerName: e.cfg.Host, MinVersion: tls.VersionTLS12, RootCAs: e.rootCAs}
	var c *smtp.Client
	switch e.cfg.TLS {
	case TLSImplicit:
		tc := tls.Client(conn, tlsConf)
		if herr := tc.HandshakeContext(ctx); herr != nil {
			return e.emailError("tls handshake", herr)
		}
		if c, err = smtp.NewClient(tc, e.cfg.Host); err != nil {
			return e.emailError("greeting", err)
		}
	default:
		if c, err = smtp.NewClient(conn, e.cfg.Host); err != nil {
			return e.emailError("greeting", err)
		}
		if ok, _ := c.Extension("STARTTLS"); !ok {
			_ = c.Close()
			return &SendError{Permanent: true, Err: errors.New("smtp: the server does not offer STARTTLS; refusing to send without TLS (use tls: implicit or fix the server)")}
		}
		if err = c.StartTLS(tlsConf); err != nil {
			return e.emailError("starttls", err)
		}
	}
	defer c.Close()

	if e.cfg.Username != "" {
		// PlainAuth refuses to send the password over an unencrypted connection; it is always TLS here.
		if err = c.Auth(smtp.PlainAuth("", e.cfg.Username, e.cfg.Password, e.cfg.Host)); err != nil {
			var te *textproto.Error
			if !errors.As(err, &te) { // e.g. the server does not offer AUTH
				return &SendError{Permanent: true, Err: errors.New("smtp auth: " + clBase(stripSecret(err.Error(), e.cfg.Password)))}
			}
			return e.emailError("auth", err)
		}
	}
	if err = c.Mail(e.from.Address); err != nil {
		return e.emailError("MAIL FROM", err)
	}
	if err = c.Rcpt(to); err != nil {
		return e.emailError("RCPT TO", err)
	}
	w, err := c.Data()
	if err != nil {
		return e.emailError("DATA", err)
	}
	if _, err = w.Write(data); err != nil {
		return e.emailError("DATA", err)
	}
	if err = w.Close(); err != nil {
		return e.emailError("DATA", err)
	}
	_ = c.Quit()
	return nil
}

// --- message -----------------------------------------------------------------------------------

// cleanHeader strips everything from a header value that is not printable: CR, LF and all other
// control and non-printable characters (this is what prevents header injection), and cuts it.
func cleanHeader(s string, limit int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		switch {
		case r == '\t' || r == '\n' || r == '\r':
			r = ' '
		case !unicode.IsPrint(r) && r != ' ', unicode.Is(unicode.Cf, r), r == 0x2028, r == 0x2029:
			continue
		}
		if n++; n > limit {
			break
		}
		b.WriteRune(r)
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

var msgIDRe = regexp.MustCompile(`[^A-Za-z0-9._-]`)

// formatEmail returns the subject, the plain text and the HTML body.
func formatEmail(m Message) (subject, plain, htmlBody string) {
	if len(m.Lines) > 0 {
		subject = cleanHeader(m.Lines[0].plain(), emailMaxSubject)
	}
	if subject == "" {
		subject = "Holealign notification"
	}
	plain, h := formatMatrix(m)
	htmlBody = `<!doctype html><html><head><meta charset="utf-8"></head><body style="font-family:sans-serif">` + h + `</body></html>`
	return subject, plain, htmlBody
}

func qpPart(contentType, body string) string {
	var buf bytes.Buffer
	w := quotedprintable.NewWriter(&buf)
	_, _ = w.Write([]byte(strings.ReplaceAll(body, "\r\n", "\n")))
	_ = w.Close()
	return "Content-Type: " + contentType + "; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n" + buf.String() + "\r\n"
}

// buildMessage renders the RFC 5322 message. No untrusted text reaches a header except the subject,
// which is cleaned and encoded; the message ID is reduced to safe characters.
func (e *Email) buildMessage(to string, msg Message) ([]byte, error) {
	subject, plain, htmlBody := formatEmail(msg)
	var rnd [12]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, errors.New("random source failed")
	}
	boundary := "holealign-" + hex.EncodeToString(rnd[:])
	id := msgIDRe.ReplaceAllString(msg.ID, "")
	if id == "" {
		id = hex.EncodeToString(rnd[:])
	}
	var b bytes.Buffer
	hdr := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	hdr("From", e.from.String())
	hdr("To", (&mail.Address{Address: to}).String())
	hdr("Subject", mime.QEncoding.Encode("utf-8", subject))
	hdr("Date", e.now().Format(time.RFC1123Z))
	hdr("Message-ID", "<"+id+"@"+MailboxDomain(e.from.Address)+">")
	hdr("MIME-Version", "1.0")
	hdr("Auto-Submitted", "auto-generated")
	hdr("Content-Type", `multipart/alternative; boundary="`+boundary+`"`)
	b.WriteString("\r\n")
	b.WriteString("--" + boundary + "\r\n" + qpPart("text/plain", plain))
	b.WriteString("--" + boundary + "\r\n" + qpPart("text/html", htmlBody))
	b.WriteString("--" + boundary + "--\r\n")
	return b.Bytes(), nil
}
