package notify

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Channels that talk to several configured endpoints (Discord, Teams, generic webhooks) address them
// by NAME ("discord:ops"). The URL behind a name lives only in the config file or the environment, so
// nobody who can edit routes in the web UI can make the server request an arbitrary URL.

// nameRe is the syntax of a webhook or endpoint name.
var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// ValidName reports whether name is a valid webhook/endpoint name (lower case letters, digits, "_",
// "-"; at most 32 characters, starting with a letter or digit).
func ValidName(name string) error {
	if !nameRe.MatchString(name) {
		return errors.New("not a valid name (expected 1-32 characters of a-z, 0-9, _ and -, starting with a letter or digit; the name of a webhook in the config file, never a URL)")
	}
	return nil
}

// noRedirect returns a copy of c that never follows redirects: a redirect answer is returned as it
// is and treated as a failure, so a hook cannot bounce the request (and its body) to another host.
func noRedirect(c *http.Client) *http.Client {
	if c == nil {
		c = newHTTPClient()
	}
	cp := *c
	cp.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &cp
}

// retryAfterValue parses a Retry-After header value: delta-seconds (an integer, or a decimal number
// for services that send fractions). HTTP dates are not used by the services here.
func retryAfterValue(v string) time.Duration {
	f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil || f <= 0 || f > 24*3600 {
		return 0
	}
	return time.Duration(f * float64(time.Second))
}

// stripAll removes every secret from s.
func stripAll(s string, secrets []string) string {
	for _, x := range secrets {
		s = stripSecret(s, x)
	}
	return s
}

// redactNet drops the request URL from a transport error and removes the secrets from what is left.
func redactNet(err error, secrets []string) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	return errors.New("network: " + stripAll(err.Error(), secrets))
}

// httpFailure maps a non-success HTTP answer to a SendError. 429, 408 and 5xx are transient, every
// other status (including 3xx, as redirects are not followed) is permanent. secrets are removed from
// the response excerpt.
func httpFailure(service string, code int, hdr http.Header, body []byte, retryAfter time.Duration, secrets []string) *SendError {
	if retryAfter <= 0 {
		retryAfter = retryAfterValue(hdr.Get("Retry-After"))
	}
	switch {
	case code == http.StatusTooManyRequests:
		return &SendError{Status: code, RetryAfter: retryAfter, Err: errors.New("rate limited (429)")}
	case code >= 500 || code == http.StatusRequestTimeout:
		return &SendError{Status: code, Err: fmt.Errorf("server error %d", code)}
	}
	if code >= 300 && code < 400 {
		return &SendError{Status: code, Permanent: true, Err: fmt.Errorf("%s answered with redirect %d (redirects are not followed)", service, code)}
	}
	ex := stripAll(clBase(snippet(body)), secrets)
	if len(ex) > 160 {
		ex = strings.ToValidUTF8(ex[:160], "") + "..."
	}
	if ex == "" {
		return &SendError{Status: code, Permanent: true, Err: fmt.Errorf("%s responded %d", service, code)}
	}
	return &SendError{Status: code, Permanent: true, Err: fmt.Errorf("%s responded %d: %s", service, code, ex)}
}

// parseHookURL parses a webhook URL and requires one of the schemes, a host, and no user info or
// fragment. Errors never contain the URL.
func parseHookURL(raw string, schemes ...string) (*url.URL, error) {
	if raw == "" {
		return nil, errors.New("URL is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("URL is not parseable")
	}
	ok := false
	for _, s := range schemes {
		ok = ok || u.Scheme == s
	}
	if !ok {
		return nil, fmt.Errorf("URL scheme must be %s", strings.Join(schemes, " or "))
	}
	if u.Hostname() == "" {
		return nil, errors.New("URL has no host")
	}
	if u.User != nil {
		return nil, errors.New("URL must not contain user info")
	}
	if u.Fragment != "" {
		return nil, errors.New("URL must not contain a fragment")
	}
	return u, nil
}

// cutRunes cuts s to at most n runes.
func cutRunes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	i := 0
	for j := range s {
		if i == n {
			return s[:j]
		}
		i++
	}
	return s
}

// lastPathElem is the last element of a URL path (the token of most webhook URLs).
func lastPathElem(u *url.URL) string {
	p := strings.TrimRight(u.Path, "/")
	return p[strings.LastIndexByte(p, '/')+1:]
}

// hookSecrets lists the strings to remove from errors about a webhook URL: the whole URL, its path
// and query (as they appear in transport errors) and its last path element.
func hookSecrets(raw string) []string {
	out := []string{raw}
	if u, err := url.Parse(raw); err == nil {
		if u.Path != "" && u.Path != "/" {
			out = append(out, u.Path)
		}
		if u.RawQuery != "" {
			out = append(out, u.RawQuery)
		}
		if t := lastPathElem(u); len(t) >= 8 {
			out = append(out, t)
		}
	}
	return out
}
