// Package store persists Holealign server state. Store is an interface so a Postgres
// implementation can be added later; SQLite (pure Go) is the default.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/DonSosiska/holealign/internal/model"
)

var (
	// ErrNotFound is returned when a row does not exist.
	ErrNotFound = errors.New("store: not found")
	// ErrExists is returned when a unique constraint would be violated (user, token name).
	ErrExists = errors.New("store: already exists")
	// ErrReenrollDenied is returned by EnrollHost when the machine is already enrolled and the caller
	// presented neither the host's current agent key nor an admin re-enroll permission.
	ErrReenrollDenied = errors.New("store: host exists; previous key required")
	// ErrTokenExhausted is returned by EnrollHost when the token's max_hosts is reached.
	ErrTokenExhausted = errors.New("store: enrollment token exhausted")
)

// Facts limits enforced after merging a check-in.
const (
	MaxFactKeys      = 1000
	MaxFactsBytes    = 1 << 20
	MaxFactValueByte = 64 << 10
)

// LimitError reports a request that exceeds a size limit (HTTP 413).
type LimitError struct{ Msg string }

func (e *LimitError) Error() string { return e.Msg }

// EnrollParams describes a host enrolling (or re-enrolling) with a new agent key.
type EnrollParams struct {
	MachineID    string
	Hostname     string
	Labels       []string
	AgentVersion string
	KeyHash      string // SHA-256 hex of the new agent key

	// PreviousKeyHash is the hash of the Bearer key presented with the request. A host that already
	// exists is re-enrolled only if this is one of its current keys or reenroll_allowed is set.
	PreviousKeyHash string
	// LocalRecovery permits key-less re-enrollment for the server's own in-process local agent
	// without opening a remote re-enrollment window in the database. Never set from HTTP handlers.
	LocalRecovery bool
	// TokenName is the enrollment token used; recorded on the host. MaxHosts (0 = unlimited) is
	// enforced when the host is new. TokenLabels, if non-empty, replace Labels and lock them.
	TokenName   string
	MaxHosts    int
	TokenLabels []string
}

// HostAdmin is the admin view of a host.
type HostAdmin struct {
	model.Host
	TokenName       string
	ReenrollAllowed bool      // a key-less re-enrollment is currently permitted (not expired)
	ReenrollUntil   time.Time // expiry of that permission (zero = none)
}

// SkippedTarget is an inventory target the server refused (oversized, malformed, not CycloneDX).
type SkippedTarget struct {
	Kind   model.TargetKind `json:"kind"`
	Name   string           `json:"name"`
	Reason string           `json:"reason"`
}

// EnrollTokenOpts are the creation options of an enrollment token.
type EnrollTokenOpts struct {
	Name      string
	Hash      string
	MaxHosts  int       // 0 = unlimited
	ExpiresAt time.Time // zero = never
	Labels    []string  // authoritative labels for hosts enrolled with this token
}

// CheckinResult is what ApplyCheckin learned while merging a check-in.
type CheckinResult struct {
	Host         model.Host
	FactsChanged bool
	FirstCheckin bool // the server had no facts/check-in for this host before
}

// FindingFilter narrows ListFindings. Zero values mean "no filter".
type FindingFilter struct {
	Verdict         model.Verdict // exact verdict; if empty, resolved findings are excluded unless IncludeResolved
	IncludeResolved bool
	Label           string // host carries this label
	KEV             *bool
	VulnID          string // matches vuln_id or any alias
	HostID          string
	// Tier is "", "attention" or "background" (see TierAttention). EPSSThreshold (0..1) is the
	// triage.epss_threshold used to decide it; callers must pass the configured value.
	Tier          string
	EPSSThreshold float64
	Limit         int // default 100, max 1000
	Offset        int
}

// Priority tiers of open findings (computed from stored columns, never stored).
const (
	TierAttention  = "attention"
	TierBackground = "background"
)

// TierCounts counts distinct (host, vuln_id) pairs of open findings. Each pair is counted once, in
// the first matching bucket: Exploitable (any package exploitable), Attention (conditions_unknown
// and in the attention tier), Background (other conditions_unknown), NotExploitable
// (affected_not_exploitable), NotAffected.
type TierCounts struct {
	Exploitable, Attention, Background, NotExploitable, NotAffected int
}

// FindingGroup is one (host, vuln_id) with the packages it affects.
type FindingGroup struct {
	HostID, VulnID string
	Verdict        model.Verdict // worst verdict of the packages
	Severity       string        // highest severity
	CVSS, EPSS     float64       // maxima
	KEV            bool
	Attention      bool            // group is in the attention tier
	Findings       []model.Finding // the packages (those matching the non-tier filters)
}

// EnrollTokenInfo is the listing view of an enrollment token (never the secret).
type EnrollTokenInfo struct {
	Name      string
	CreatedAt time.Time
	Revoked   bool
	LastUsed  time.Time
	MaxHosts  int
	ExpiresAt time.Time
	Labels    []string
	Hosts     int // hosts enrolled with this token
}

// ApplyResult is returned by ApplyHostFindings.
type ApplyResult struct {
	Current  []model.Finding // stored rows for the supplied findings (IDs and first_seen filled)
	Resolved []model.Finding // rows that were active before and are now marked resolved
}

// User is a web UI account.
type User struct {
	Username     string
	PasswordHash string // bcrypt
	CreatedAt    time.Time
}

// Session is a web UI login session; only the token hash is stored.
type Session struct {
	TokenHash string
	Username  string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Store is the persistence contract used by api, pipeline, feeds and the web UI.
type Store interface {
	Close() error

	// Hosts and agents.
	EnrollHost(ctx context.Context, p EnrollParams) (model.Host, error)
	HostByAgentKey(ctx context.Context, keyHash string) (model.Host, error)
	ApplyCheckin(ctx context.Context, hostID string, req model.CheckinRequest, now time.Time) (CheckinResult, error)
	GetHost(ctx context.Context, id string) (model.Host, error)
	ListHosts(ctx context.Context) ([]model.Host, error)
	DeleteHost(ctx context.Context, id string) error
	ListHostsAdmin(ctx context.Context) ([]HostAdmin, error)
	// SetReenrollAllowed permits (DefaultReenrollTTL) or forbids a key-less re-enrollment.
	SetReenrollAllowed(ctx context.Context, id string, allowed bool) error
	SetReenrollAllowedUntil(ctx context.Context, id string, until time.Time) error

	// Inventory.
	ReplaceInventory(ctx context.Context, hostID string, p model.InventoryPayload) error
	// ReplaceInventorySkipped is ReplaceInventory plus the refused targets (kept with their reason).
	ReplaceInventorySkipped(ctx context.Context, hostID string, p model.InventoryPayload, skipped []SkippedTarget) error
	ListTargets(ctx context.Context, hostID string) ([]model.InventoryTarget, error)
	ListSkippedTargets(ctx context.Context, hostID string) ([]SkippedTarget, error)

	// Enrollment tokens (hash only).
	CreateEnrollToken(ctx context.Context, name, tokenHash string) error
	CreateEnrollTokenOpts(ctx context.Context, o EnrollTokenOpts) error
	UseEnrollToken(ctx context.Context, tokenHash string) (bool, error)
	// UseEnrollTokenInfo validates the token (exists, not revoked, not expired) without writing,
	// then records last_used. ErrNotFound when invalid.
	UseEnrollTokenInfo(ctx context.Context, tokenHash string, now time.Time) (EnrollTokenInfo, error)
	ListEnrollTokens(ctx context.Context) ([]EnrollTokenInfo, error)
	RevokeEnrollToken(ctx context.Context, name string) error

	// Findings.
	ApplyHostFindings(ctx context.Context, hostID string, found []model.Finding, now time.Time) (ApplyResult, error)
	HostFindings(ctx context.Context, hostID string) ([]model.Finding, error) // all rows including resolved
	GetFinding(ctx context.Context, id int64) (model.Finding, error)
	ListFindings(ctx context.Context, f FindingFilter) ([]model.Finding, int, error)
	// ListFindingGroups is ListFindings grouped by (host, vuln_id); total counts groups. A group is in
	// the attention tier when any of its matching packages is.
	ListFindingGroups(ctx context.Context, f FindingFilter) ([]FindingGroup, int, error)
	// CountByTier counts open findings per distinct (host, vuln_id): global and per host.
	CountByTier(ctx context.Context, epssThreshold float64) (TierCounts, map[string]TierCounts, error)
	// Retention: delete resolved findings / notification dedup rows older than cutoff.
	PruneResolvedFindings(ctx context.Context, cutoff time.Time) (int64, error)
	PruneNotifications(ctx context.Context, cutoff time.Time) (int64, error)

	// Notification dedup. A finding key identifies host+target+package+vuln; a dedup key adds the event kind.
	NotificationSent(ctx context.Context, dedupKey string) (bool, error)
	FindingNotified(ctx context.Context, findingKey string) (bool, error) // any exploitable/unknown_critical recorded
	RecordNotification(ctx context.Context, findingKey, dedupKey string, kind model.EventKind, at time.Time) error

	// Rules (DB rules override files).
	GetRule(ctx context.Context, id string) (model.Rule, error)
	ListRules(ctx context.Context) ([]model.Rule, error)
	UpsertRule(ctx context.Context, r model.Rule, now time.Time) error

	// Users and sessions for the web UI.
	CreateUser(ctx context.Context, username, passwordHash string) error
	GetUser(ctx context.Context, username string) (User, error)
	ListUsers(ctx context.Context) ([]User, error)
	SetUserPassword(ctx context.Context, username, passwordHash string) error
	DeleteUser(ctx context.Context, username string) error
	CountUsers(ctx context.Context) (int, error)
	CreateSession(ctx context.Context, s Session) error
	GetSession(ctx context.Context, tokenHash string, now time.Time) (Session, error)
	DeleteSession(ctx context.Context, tokenHash string) error
	// ExtendSession moves a live session's expiry to expiresAt (idle-timeout refresh).
	ExtendSession(ctx context.Context, tokenHash string, expiresAt, now time.Time) error
	DeleteExpiredSessions(ctx context.Context, now time.Time) error

	// Settings (JSON values edited in the web UI, e.g. "matrix.routes") and kv (feed timestamps).
	GetSetting(ctx context.Context, key string) (json.RawMessage, error)
	SetSetting(ctx context.Context, key string, value json.RawMessage, now time.Time) error
	KVGet(ctx context.Context, key string) (string, error)
	KVSet(ctx context.Context, key, value string, now time.Time) error
}

// FindingKey builds the finding identity used for notification dedup.
func FindingKey(f model.Finding) string {
	return f.HostID + "|" + f.Target + "|" + f.PackageName + "|" + f.VulnID
}

// DedupKey is FindingKey plus the event kind (contracts §5).
func DedupKey(f model.Finding, kind model.EventKind) string {
	return FindingKey(f) + "|" + string(kind)
}

// NewSecret generates a random secret with the given prefix ("pa_" agent keys, "pt_" enroll tokens,
// "ps_" sessions) and returns it together with its SHA-256 hex hash. Only the hash is stored.
func NewSecret(prefix string) (secret, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	secret = prefix + hex.EncodeToString(b)
	return secret, HashSecret(secret), nil
}

// HashSecret returns the hex SHA-256 of a secret.
func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// HashPassword returns a bcrypt hash.
func HashPassword(pw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(h), err
}

// CheckPassword reports whether pw matches a bcrypt hash.
func CheckPassword(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

func newID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}
