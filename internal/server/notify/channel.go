package notify

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

// Channel delivers a rendered message to one kind of destination (Matrix, Slack, Telegram, ...).
//
// A new channel is one file in this package: implement Channel, call registerChannel from an init
// function in the same file, add a config section (internal/server/config) and wire the constructor
// in cmd/holealign-server. Grouping, routing, retry with backoff, burst summaries, partial-delivery
// memory and delivery-problem reporting are done by the Notifier and need no channel code.
type Channel interface {
	// Scheme is the destination prefix ("matrix", "slack", "telegram", ...).
	Scheme() string
	// ValidTarget strictly checks the part of a destination after "scheme:". It is called when the
	// config is loaded and when routes are saved in the web UI, so it must be a pure syntax check.
	ValidTarget(target string) error
	// Send performs ONE delivery attempt of msg to target (the channel formats the neutral
	// Message itself). Failures that carry an HTTP status must be returned as *SendError so the
	// Notifier can decide between retry and giving up; context errors are returned as they are.
	// msg.ID is a unique idempotency key that stays the same across the retries of one message.
	Send(ctx context.Context, target string, msg Message) error
}

// SendError is a failed delivery attempt. Status is the HTTP status (0: network error).
// Permanent marks a failure that retrying the same request cannot fix (e.g. 4xx other than 429,
// or an "ok":false API answer such as channel_not_found). RetryAfter is the delay the service asked
// for (0: none). The error text must never contain secrets (tokens, URLs with tokens).
type SendError struct {
	Status     int
	Permanent  bool
	RetryAfter time.Duration
	Err        error
}

func (e *SendError) Error() string { return e.Err.Error() }
func (e *SendError) Unwrap() error { return e.Err }

// schemeValidators holds the schemes known to the package, independent of what is configured. It
// is used to parse and validate destinations without constructing any channel.
var schemeValidators = map[string]func(target string) error{}

// registerChannel makes a scheme known. Call it from an init function of the channel's file.
func registerChannel(scheme string, valid func(target string) error) {
	schemeValidators[scheme] = valid
}

// Schemes lists the known destination schemes, sorted.
func Schemes() []string {
	out := make([]string, 0, len(schemeValidators))
	for s := range schemeValidators {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

const matrixScheme = "matrix"

var schemeLike = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*$`)

// ParseDestination splits a destination "scheme:target". A destination whose prefix is not a known
// scheme is a Matrix room ID or alias ("!id:server", "#alias:server"), so existing configs and stored
// routes keep working. It does not validate the target.
func ParseDestination(dest string) (scheme, target string) {
	dest = strings.TrimSpace(dest)
	if i := strings.IndexByte(dest, ':'); i > 0 {
		if _, ok := schemeValidators[dest[:i]]; ok {
			return dest[:i], dest[i+1:]
		}
	}
	return matrixScheme, dest
}

// ValidateDestination checks a destination's syntax strictly (known scheme, valid target).
// It does not check that the channel is configured; the config package does that.
func ValidateDestination(dest string) error {
	if strings.TrimSpace(dest) == "" {
		return errors.New("empty destination")
	}
	scheme, target := ParseDestination(dest)
	if err := schemeValidators[scheme](target); err != nil {
		if scheme == matrixScheme {
			if i := strings.IndexByte(dest, ':'); i > 0 && schemeLike.MatchString(dest[:i]) {
				return fmt.Errorf("%q: unknown scheme %q (known: %s) or not a Matrix room ID: %w", clip(dest, 80), dest[:i], strings.Join(Schemes(), ", "), err)
			}
		}
		return fmt.Errorf("%q: %w", clip(dest, 80), err)
	}
	return nil
}

// CanonicalDestination returns the normalised form: Matrix IDs bare, everything else
// "scheme:target". It returns an error for an invalid destination.
func CanonicalDestination(dest string) (string, error) {
	if err := ValidateDestination(dest); err != nil {
		return "", err
	}
	scheme, target := ParseDestination(dest)
	if scheme == matrixScheme {
		return target, nil
	}
	return scheme + ":" + target, nil
}

func clip(s string, n int) string {
	if len(s) > n {
		return strings.ToValidUTF8(s[:n], "") + "..."
	}
	return s
}

// appendUnique appends the non-empty values of src that are not yet in dst.
func appendUnique(dst []string, src ...string) []string {
	for _, s := range src {
		if s == "" || slices.Contains(dst, s) {
			continue
		}
		dst = append(dst, s)
	}
	return dst
}
