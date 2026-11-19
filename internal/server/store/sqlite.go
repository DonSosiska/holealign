package store

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	// Pure-Go SQLite driver. This is the modernc-based fork that Grype already links; importing
	// modernc.org/sqlite as well would panic ("Register called twice for driver sqlite").
	_ "github.com/glebarez/go-sqlite"

	"github.com/DonSosiska/holealign/internal/model"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// SQLite implements Store on top of a SQLite file (WAL mode).
type SQLite struct {
	db *sql.DB
}

var _ Store = (*SQLite)(nil)

// OpenSQLite opens (creating if needed) the database at path and runs migrations.
func OpenSQLite(path string) (*SQLite, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	esc := strings.NewReplacer("?", "%3f", "#", "%23").Replace(path)
	dsn := "file:" + esc + "?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)" +
		"&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	s := &SQLite{db: db}
	if err := s.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	_ = os.Chmod(path, 0o600)
	return s, nil
}

// Close closes the database.
func (s *SQLite) Close() error { return s.db.Close() }

func (s *SQLite) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL)`); err != nil {
		return err
	}
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		numStr, _, _ := strings.Cut(name, "_")
		ver, err := strconv.Atoi(numStr)
		if err != nil {
			return fmt.Errorf("bad migration name %q", name)
		}
		var n int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version=?`, ver).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			continue
		}
		body, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return err
		}
		err = s.tx(ctx, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, string(body)); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			_, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,name,applied_at) VALUES(?,?,?)`,
				ver, name, ts(time.Now()))
			return err
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// SchemaVersion returns the highest applied migration (useful in tests).
func (s *SQLite) SchemaVersion(ctx context.Context) (int, error) {
	var v sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&v)
	return int(v.Int64), err
}

func (s *SQLite) tx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// --- helpers ---------------------------------------------------------------

func ts(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func fromTS(ms int64) time.Time {
	if ms == 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms).UTC()
}

func jsonStr(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "null"
	}
	return string(b)
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func isUnique(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

func notFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

type scanner interface{ Scan(dest ...any) error }

// --- hosts -----------------------------------------------------------------

const hostCols = `id, machine_id, hostname, labels, os, facts, agent_version, inventory_hash, last_checkin`

func scanHost(sc scanner) (model.Host, error) {
	var h model.Host
	var labels, osj, facts string
	var last int64
	if err := sc.Scan(&h.ID, &h.MachineID, &h.Hostname, &labels, &osj, &facts, &h.AgentVersion, &h.InventoryHash, &last); err != nil {
		return h, err
	}
	_ = json.Unmarshal([]byte(labels), &h.Labels)
	_ = json.Unmarshal([]byte(osj), &h.OS)
	_ = json.Unmarshal([]byte(facts), &h.Facts)
	if h.Labels == nil {
		h.Labels = []string{}
	}
	if h.Facts == nil {
		h.Facts = model.Facts{}
	}
	h.LastCheckin = fromTS(last)
	return h, nil
}

func (s *SQLite) EnrollHost(ctx context.Context, p EnrollParams) (model.Host, error) {
	var out model.Host
	err := s.tx(ctx, func(tx *sql.Tx) error {
		now := ts(time.Now())
		labels, locked := p.Labels, 0
		if len(p.TokenLabels) > 0 {
			labels, locked = p.TokenLabels, 1
		}
		if labels == nil {
			labels = []string{}
		}
		var id string
		var allowedUntil int64
		err := tx.QueryRowContext(ctx, `SELECT id, reenroll_allowed_until FROM hosts WHERE machine_id=?`, p.MachineID).Scan(&id, &allowedUntil)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			if p.MaxHosts > 0 && p.TokenName != "" {
				var n int
				if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM hosts WHERE token_name=?`, p.TokenName).Scan(&n); err != nil {
					return err
				}
				if n >= p.MaxHosts {
					return ErrTokenExhausted
				}
			}
			id = newID("h_")
			if _, err := tx.ExecContext(ctx, `INSERT INTO hosts(id,machine_id,hostname,labels,agent_version,created_at,token_name,labels_locked) VALUES(?,?,?,?,?,?,?,?)`,
				id, p.MachineID, p.Hostname, jsonStr(labels), p.AgentVersion, now, p.TokenName, locked); err != nil {
				return err
			}
		case err != nil:
			return err
		default:
			ok := allowedUntil > now || p.LocalRecovery
			if !ok && p.PreviousKeyHash != "" {
				var n int
				if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM agent_keys WHERE host_id=? AND key_hash=?`, id, p.PreviousKeyHash).Scan(&n); err != nil {
					return err
				}
				ok = n > 0
			}
			if !ok {
				return ErrReenrollDenied
			}
			if len(p.TokenLabels) > 0 {
				// The new token carries authoritative labels: adopt them and its quota.
				if p.MaxHosts > 0 && p.TokenName != "" {
					var n int
					if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM hosts WHERE token_name=? AND id<>?`, p.TokenName, id).Scan(&n); err != nil {
						return err
					}
					if n >= p.MaxHosts {
						return ErrTokenExhausted
					}
				}
				if _, err := tx.ExecContext(ctx, `UPDATE hosts SET hostname=?, labels=?, agent_version=?, reenroll_allowed_until=0, reenroll_allowed=0, token_name=?, labels_locked=1 WHERE id=?`,
					p.Hostname, jsonStr(labels), p.AgentVersion, p.TokenName, id); err != nil {
					return err
				}
			} else {
				// Keep the existing token binding and authoritative labels (a different token
				// without labels must not unlock them or move the host). Unlocked hosts take
				// the labels of the request.
				if _, err := tx.ExecContext(ctx, `UPDATE hosts SET hostname=?, labels=CASE WHEN labels_locked<>0 THEN labels ELSE ? END,
					agent_version=?, reenroll_allowed_until=0, reenroll_allowed=0 WHERE id=?`,
					p.Hostname, jsonStr(labels), p.AgentVersion, id); err != nil {
					return err
				}
			}
			// rotate: old keys stop working
			if _, err := tx.ExecContext(ctx, `DELETE FROM agent_keys WHERE host_id=?`, id); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO agent_keys(key_hash,host_id,created_at) VALUES(?,?,?)`, p.KeyHash, id, now); err != nil {
			return err
		}
		h, err := scanHost(tx.QueryRowContext(ctx, `SELECT `+hostCols+` FROM hosts WHERE id=?`, id))
		out = h
		return err
	})
	return out, err
}

func (s *SQLite) ListHostsAdmin(ctx context.Context) ([]HostAdmin, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+hostCols+`, token_name, reenroll_allowed_until FROM hosts ORDER BY hostname, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HostAdmin
	for rows.Next() {
		var h model.Host
		var labels, osj, facts, tn string
		var last int64
		var ra int64
		if err := rows.Scan(&h.ID, &h.MachineID, &h.Hostname, &labels, &osj, &facts, &h.AgentVersion, &h.InventoryHash, &last, &tn, &ra); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(labels), &h.Labels)
		h.LastCheckin = fromTS(last)
		out = append(out, HostAdmin{Host: h, TokenName: tn, ReenrollAllowed: ra > ts(time.Now()), ReenrollUntil: fromTS(ra)})
	}
	return out, rows.Err()
}

// DefaultReenrollTTL is how long SetReenrollAllowed(true) permits a key-less re-enrollment.
const DefaultReenrollTTL = time.Hour

func (s *SQLite) SetReenrollAllowed(ctx context.Context, id string, allowed bool) error {
	until := time.Time{}
	if allowed {
		until = time.Now().Add(DefaultReenrollTTL)
	}
	return s.SetReenrollAllowedUntil(ctx, id, until)
}

// SetReenrollAllowedUntil permits a re-enrollment without the old key until the given time
// (zero clears the permission).
func (s *SQLite) SetReenrollAllowedUntil(ctx context.Context, id string, until time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE hosts SET reenroll_allowed_until=?, reenroll_allowed=0 WHERE id=?`, ts(until), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) HostByAgentKey(ctx context.Context, keyHash string) (model.Host, error) {
	h, err := scanHost(s.db.QueryRowContext(ctx, `SELECT `+prefixCols("h", hostCols)+` FROM hosts h
		JOIN agent_keys k ON k.host_id=h.id WHERE k.key_hash=?`, keyHash))
	return h, notFound(err)
}

func prefixCols(alias, cols string) string {
	parts := strings.Split(cols, ",")
	for i, p := range parts {
		parts[i] = alias + "." + strings.TrimSpace(p)
	}
	return strings.Join(parts, ", ")
}

func (s *SQLite) ApplyCheckin(ctx context.Context, hostID string, req model.CheckinRequest, now time.Time) (CheckinResult, error) {
	var res CheckinResult
	err := s.tx(ctx, func(tx *sql.Tx) error {
		h, err := scanHost(tx.QueryRowContext(ctx, `SELECT `+hostCols+` FROM hosts WHERE id=?`, hostID))
		if err != nil {
			return notFound(err)
		}
		res.FirstCheckin = h.LastCheckin.IsZero()
		oldFacts, _ := json.Marshal(h.Facts)

		var facts model.Facts
		if req.FactsComplete {
			facts = model.Facts{}
			for k, v := range req.Facts {
				if v != nil {
					facts[k] = v
				}
			}
		} else {
			facts = h.Facts
			if facts == nil {
				facts = model.Facts{}
			}
			for k, v := range req.Facts {
				if v == nil {
					delete(facts, k)
				} else {
					facts[k] = v
				}
			}
		}
		newFacts, err := json.Marshal(facts)
		if err != nil {
			return err
		}
		if err := checkFactLimits(facts, len(newFacts)); err != nil {
			return err
		}
		res.FactsChanged = string(oldFacts) != string(newFacts)

		var locked int
		if err := tx.QueryRowContext(ctx, `SELECT labels_locked FROM hosts WHERE id=?`, hostID).Scan(&locked); err != nil {
			return err
		}
		labels := req.Labels
		if labels == nil || locked != 0 { // token labels are authoritative
			labels = h.Labels
		}
		hostname := req.Hostname
		if hostname == "" {
			hostname = h.Hostname
		}
		ver := req.AgentVersion
		if ver == "" {
			ver = h.AgentVersion
		}
		osInfo := req.OS
		if osInfo == (model.OSInfo{}) {
			osInfo = h.OS // an empty OS block means "unchanged"
		}
		if _, err := tx.ExecContext(ctx, `UPDATE hosts SET hostname=?, labels=?, os=?, facts=?, agent_version=?, last_checkin=? WHERE id=?`,
			hostname, jsonStr(labels), jsonStr(osInfo), string(newFacts), ver, ts(now), hostID); err != nil {
			return err
		}
		h, err = scanHost(tx.QueryRowContext(ctx, `SELECT `+hostCols+` FROM hosts WHERE id=?`, hostID))
		res.Host = h
		return err
	})
	return res, err
}

func checkFactLimits(facts model.Facts, total int) error {
	if len(facts) > MaxFactKeys {
		return &LimitError{fmt.Sprintf("too many facts (max %d keys)", MaxFactKeys)}
	}
	if total > MaxFactsBytes {
		return &LimitError{fmt.Sprintf("facts too large (max %d bytes)", MaxFactsBytes)}
	}
	for k, v := range facts {
		if b, err := json.Marshal(v); err == nil && len(b) > MaxFactValueByte {
			return &LimitError{fmt.Sprintf("fact %q too large (max %d bytes)", k, MaxFactValueByte)}
		}
	}
	return nil
}

func (s *SQLite) GetHost(ctx context.Context, id string) (model.Host, error) {
	h, err := scanHost(s.db.QueryRowContext(ctx, `SELECT `+hostCols+` FROM hosts WHERE id=?`, id))
	return h, notFound(err)
}

func (s *SQLite) ListHosts(ctx context.Context) ([]model.Host, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+hostCols+` FROM hosts ORDER BY hostname, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Host
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *SQLite) DeleteHost(ctx context.Context, id string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM hosts WHERE id=?`, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		// findings, targets and keys cascade; remove the per-host kv state and dedup rows too.
		esc := likeEscape(id)
		for _, q := range []struct{ sql, arg string }{
			{`DELETE FROM kv WHERE key LIKE ? ESCAPE '\'`, "poison." + esc + ".%"},
			{`DELETE FROM kv WHERE key LIKE ? ESCAPE '\'`, "health.%." + esc},
			{`DELETE FROM notifications_sent WHERE dedup_key LIKE ? ESCAPE '\'`, "host|" + esc + "|%"},
			{`DELETE FROM notifications_sent WHERE finding_key LIKE ? ESCAPE '\'`, esc + "|%"},
		} {
			if _, err := tx.ExecContext(ctx, q.sql, q.arg); err != nil {
				return err
			}
		}
		return nil
	})
}

func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// --- inventory -------------------------------------------------------------

func (s *SQLite) ReplaceInventory(ctx context.Context, hostID string, p model.InventoryPayload) error {
	return s.ReplaceInventorySkipped(ctx, hostID, p, nil)
}

// ReplaceInventorySkipped stores the valid targets of p and, next to them, the targets that were
// refused (name, kind and reason only; no SBOM). The pipeline carries over the findings of those.
func (s *SQLite) ReplaceInventorySkipped(ctx context.Context, hostID string, p model.InventoryPayload, skipped []SkippedTarget) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE hosts SET inventory_hash=? WHERE id=?`, p.Hash, hostID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM targets WHERE host_id=?`, hostID); err != nil {
			return err
		}
		// a new inventory lifts the poison flags of matcher panics (pipeline)
		if _, err := tx.ExecContext(ctx, `DELETE FROM kv WHERE key LIKE ? ESCAPE '\'`, "poison."+likeEscape(hostID)+".%"); err != nil {
			return err
		}
		for _, t := range p.Targets {
			containers := t.Containers
			if containers == nil {
				containers = []string{}
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO targets(host_id,kind,name,image_id,containers,sbom,skipped) VALUES(?,?,?,?,?,?,'')
				ON CONFLICT(host_id,kind,name) DO UPDATE SET image_id=excluded.image_id, containers=excluded.containers, sbom=excluded.sbom, skipped=''`,
				hostID, string(t.Kind), t.Name, t.ImageID, jsonStr(containers), []byte(t.SBOM)); err != nil {
				return err
			}
		}
		for _, k := range skipped {
			// never overwrite a valid target of the same identity
			if _, err := tx.ExecContext(ctx, `INSERT INTO targets(host_id,kind,name,image_id,containers,sbom,skipped) VALUES(?,?,?,'','[]',x'',?)
				ON CONFLICT(host_id,kind,name) DO NOTHING`, hostID, string(k.Kind), k.Name, k.Reason); err != nil {
				return err
			}
		}
		return nil
	})
}

// ListTargets returns the targets that have an SBOM (skipped ones are listed by ListSkippedTargets).
func (s *SQLite) ListTargets(ctx context.Context, hostID string) ([]model.InventoryTarget, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT kind,name,image_id,containers,sbom FROM targets WHERE host_id=? AND skipped='' ORDER BY kind, name`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.InventoryTarget
	for rows.Next() {
		var t model.InventoryTarget
		var kind, containers string
		var sbom []byte
		if err := rows.Scan(&kind, &t.Name, &t.ImageID, &containers, &sbom); err != nil {
			return nil, err
		}
		t.Kind = model.TargetKind(kind)
		_ = json.Unmarshal([]byte(containers), &t.Containers)
		t.SBOM = json.RawMessage(sbom)
		out = append(out, t)
	}
	return out, rows.Err()
}

// ListSkippedTargets returns the targets of the last inventory that were refused, with the reason.
func (s *SQLite) ListSkippedTargets(ctx context.Context, hostID string) ([]SkippedTarget, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT kind,name,skipped FROM targets WHERE host_id=? AND skipped<>'' ORDER BY kind, name`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SkippedTarget
	for rows.Next() {
		var k SkippedTarget
		var kind string
		if err := rows.Scan(&kind, &k.Name, &k.Reason); err != nil {
			return nil, err
		}
		k.Kind = model.TargetKind(kind)
		out = append(out, k)
	}
	return out, rows.Err()
}

// --- retention ---------------------------------------------------------------

// PruneResolvedFindings deletes findings resolved before cutoff and returns how many.
func (s *SQLite) PruneResolvedFindings(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM findings WHERE verdict=? AND last_seen<?`, string(model.VerdictResolved), ts(cutoff))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// PruneNotifications deletes dedup rows sent before cutoff, except those of findings that are
// still open (deleting them would re-send the alert).
func (s *SQLite) PruneNotifications(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM notifications_sent WHERE sent_at<? AND NOT EXISTS (
		SELECT 1 FROM findings f WHERE f.verdict<>? AND f.host_id||'|'||f.target||'|'||f.package_name||'|'||f.vuln_id = notifications_sent.finding_key)`,
		ts(cutoff), string(model.VerdictResolved))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// --- enrollment tokens -----------------------------------------------------

func (s *SQLite) CreateEnrollToken(ctx context.Context, name, tokenHash string) error {
	return s.CreateEnrollTokenOpts(ctx, EnrollTokenOpts{Name: name, Hash: tokenHash})
}

func (s *SQLite) CreateEnrollTokenOpts(ctx context.Context, o EnrollTokenOpts) error {
	labels := o.Labels
	if labels == nil {
		labels = []string{}
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO enroll_tokens(token_hash,name,created_at,max_hosts,expires_at,labels) VALUES(?,?,?,?,?,?)`,
		o.Hash, o.Name, ts(time.Now()), o.MaxHosts, ts(o.ExpiresAt), jsonStr(labels))
	if isUnique(err) {
		return ErrExists
	}
	return err
}

// UseEnrollToken reports whether the token is valid (known, not revoked, not expired, not
// exhausted) and records last_used for valid tokens only.
func (s *SQLite) UseEnrollToken(ctx context.Context, tokenHash string) (bool, error) {
	info, err := s.UseEnrollTokenInfo(ctx, tokenHash, time.Now())
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return info.MaxHosts <= 0 || info.Hosts < info.MaxHosts, nil
}

func (s *SQLite) UseEnrollTokenInfo(ctx context.Context, tokenHash string, now time.Time) (EnrollTokenInfo, error) {
	var i EnrollTokenInfo
	var c, lu, exp int64
	var rev int
	var labels string
	err := s.db.QueryRowContext(ctx, `SELECT name,created_at,revoked,last_used,max_hosts,expires_at,labels,
		(SELECT COUNT(*) FROM hosts WHERE token_name=enroll_tokens.name) FROM enroll_tokens WHERE token_hash=?`, tokenHash).
		Scan(&i.Name, &c, &rev, &lu, &i.MaxHosts, &exp, &labels, &i.Hosts)
	if err != nil {
		return i, notFound(err)
	}
	i.CreatedAt, i.Revoked, i.LastUsed, i.ExpiresAt = fromTS(c), rev != 0, fromTS(lu), fromTS(exp)
	_ = json.Unmarshal([]byte(labels), &i.Labels)
	if i.Revoked || (!i.ExpiresAt.IsZero() && !now.Before(i.ExpiresAt)) {
		return EnrollTokenInfo{}, ErrNotFound
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE enroll_tokens SET last_used=? WHERE token_hash=?`, ts(now), tokenHash); err != nil {
		return i, err
	}
	return i, nil
}

func (s *SQLite) ListEnrollTokens(ctx context.Context) ([]EnrollTokenInfo, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name,created_at,revoked,last_used,max_hosts,expires_at,labels,
		(SELECT COUNT(*) FROM hosts WHERE token_name=enroll_tokens.name) FROM enroll_tokens ORDER BY created_at, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EnrollTokenInfo
	for rows.Next() {
		var i EnrollTokenInfo
		var c, lu, exp int64
		var rev int
		var labels string
		if err := rows.Scan(&i.Name, &c, &rev, &lu, &i.MaxHosts, &exp, &labels, &i.Hosts); err != nil {
			return nil, err
		}
		i.CreatedAt, i.Revoked, i.LastUsed, i.ExpiresAt = fromTS(c), rev != 0, fromTS(lu), fromTS(exp)
		_ = json.Unmarshal([]byte(labels), &i.Labels)
		out = append(out, i)
	}
	return out, rows.Err()
}

func (s *SQLite) RevokeEnrollToken(ctx context.Context, name string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE enroll_tokens SET revoked=1 WHERE name=?`, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// --- findings --------------------------------------------------------------

const findingCols = `id, host_id, target, target_kind, package_name, package_version, package_type, purl, vuln_id,
	aliases, severity, cvss, epss, kev, fixed_versions, fix_state, verdict, verdict_reason, rule_id, rule_status,
	first_seen, last_seen`

func scanFinding(sc scanner) (model.Finding, error) {
	var f model.Finding
	var tk, aliases, fixed, verdict, rstatus string
	var kev int
	var first, last int64
	err := sc.Scan(&f.ID, &f.HostID, &f.Target, &tk, &f.PackageName, &f.PackageVer, &f.PackageType, &f.PURL, &f.VulnID,
		&aliases, &f.Severity, &f.CVSS, &f.EPSS, &kev, &fixed, &f.FixState, &verdict, &f.VerdictReason, &f.RuleID, &rstatus,
		&first, &last)
	if err != nil {
		return f, err
	}
	f.TargetKind = model.TargetKind(tk)
	f.Verdict = model.Verdict(verdict)
	f.RuleStatus = model.RuleStatus(rstatus)
	f.KEV = kev != 0
	_ = json.Unmarshal([]byte(aliases), &f.Aliases)
	_ = json.Unmarshal([]byte(fixed), &f.FixedVersions)
	if f.Aliases == nil {
		f.Aliases = []string{}
	}
	if f.FixedVersions == nil {
		f.FixedVersions = []string{}
	}
	f.FirstSeen, f.LastSeen = fromTS(first), fromTS(last)
	return f, nil
}

func (s *SQLite) ApplyHostFindings(ctx context.Context, hostID string, found []model.Finding, now time.Time) (ApplyResult, error) {
	var res ApplyResult
	err := s.tx(ctx, func(tx *sql.Tx) error {
		seen := map[int64]bool{}
		for _, f := range found {
			aliases, fixed := f.Aliases, f.FixedVersions
			if aliases == nil {
				aliases = []string{}
			}
			if fixed == nil {
				fixed = []string{}
			}
			tk := f.TargetKind
			if tk == "" {
				tk = model.TargetHost
			}
			var id int64
			err := tx.QueryRowContext(ctx, `INSERT INTO findings(host_id,target,target_kind,package_name,package_version,package_type,purl,vuln_id,
					aliases,severity,cvss,epss,kev,fixed_versions,fix_state,verdict,verdict_reason,rule_id,rule_status,first_seen,last_seen)
				VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
				ON CONFLICT(host_id,target,package_name,package_version,vuln_id) DO UPDATE SET
					target_kind=excluded.target_kind, package_type=excluded.package_type, purl=excluded.purl,
					aliases=excluded.aliases, severity=excluded.severity, cvss=excluded.cvss, epss=excluded.epss, kev=excluded.kev,
					fixed_versions=excluded.fixed_versions, fix_state=excluded.fix_state, verdict=excluded.verdict,
					verdict_reason=excluded.verdict_reason, rule_id=excluded.rule_id, rule_status=excluded.rule_status,
					last_seen=excluded.last_seen
				RETURNING id`,
				hostID, f.Target, string(tk), f.PackageName, f.PackageVer, f.PackageType, f.PURL, f.VulnID,
				jsonStr(aliases), f.Severity, f.CVSS, f.EPSS, b2i(f.KEV), jsonStr(fixed), f.FixState, string(f.Verdict),
				f.VerdictReason, f.RuleID, string(f.RuleStatus), ts(now), ts(now)).Scan(&id)
			if err != nil {
				return err
			}
			seen[id] = true
		}
		// read back stored rows; anything active and unseen becomes resolved
		rows, err := tx.QueryContext(ctx, `SELECT `+findingCols+` FROM findings WHERE host_id=? ORDER BY id`, hostID)
		if err != nil {
			return err
		}
		var all []model.Finding
		for rows.Next() {
			f, err := scanFinding(rows)
			if err != nil {
				rows.Close()
				return err
			}
			all = append(all, f)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, f := range all {
			switch {
			case seen[f.ID]:
				res.Current = append(res.Current, f)
			case f.Verdict != model.VerdictResolved:
				if _, err := tx.ExecContext(ctx, `UPDATE findings SET verdict=?, verdict_reason='no longer detected', last_seen=? WHERE id=?`,
					string(model.VerdictResolved), ts(now), f.ID); err != nil {
					return err
				}
				f.Verdict, f.VerdictReason, f.LastSeen = model.VerdictResolved, "no longer detected", now.UTC()
				res.Resolved = append(res.Resolved, f)
			}
		}
		return nil
	})
	return res, err
}

func (s *SQLite) HostFindings(ctx context.Context, hostID string) ([]model.Finding, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+findingCols+` FROM findings WHERE host_id=? ORDER BY id`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Finding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *SQLite) GetFinding(ctx context.Context, id int64) (model.Finding, error) {
	f, err := scanFinding(s.db.QueryRowContext(ctx, `SELECT `+findingCols+` FROM findings WHERE id=?`, id))
	return f, notFound(err)
}

// --- notifications ---------------------------------------------------------

func (s *SQLite) NotificationSent(ctx context.Context, dedupKey string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM notifications_sent WHERE dedup_key=?`, dedupKey).Scan(&n)
	return n > 0, err
}

func (s *SQLite) FindingNotified(ctx context.Context, findingKey string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM notifications_sent WHERE finding_key=? AND kind IN (?,?)`,
		findingKey, string(model.EventExploitable), string(model.EventUnknownCritical)).Scan(&n)
	return n > 0, err
}

// RecordNotification stores the dedup key and forgets other kinds sent for the same finding, so
// "the same key twice in a row" is suppressed while a later transition back is delivered again.
func (s *SQLite) RecordNotification(ctx context.Context, findingKey, dedupKey string, kind model.EventKind, at time.Time) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM notifications_sent WHERE finding_key=? AND dedup_key<>?`, findingKey, dedupKey); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO notifications_sent(dedup_key,finding_key,kind,sent_at) VALUES(?,?,?,?)
			ON CONFLICT(dedup_key) DO UPDATE SET sent_at=excluded.sent_at`, dedupKey, findingKey, string(kind), ts(at))
		return err
	})
}

// --- rules -----------------------------------------------------------------

func (s *SQLite) GetRule(ctx context.Context, id string) (model.Rule, error) {
	var js string
	if err := s.db.QueryRowContext(ctx, `SELECT json FROM rules WHERE id=?`, id).Scan(&js); err != nil {
		return model.Rule{}, notFound(err)
	}
	var r model.Rule
	return r, json.Unmarshal([]byte(js), &r)
}

func (s *SQLite) ListRules(ctx context.Context) ([]model.Rule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT json FROM rules ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Rule
	for rows.Next() {
		var js string
		if err := rows.Scan(&js); err != nil {
			return nil, err
		}
		var r model.Rule
		if err := json.Unmarshal([]byte(js), &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *SQLite) UpsertRule(ctx context.Context, r model.Rule, now time.Time) error {
	if r.ID == "" {
		return errors.New("rule id is empty")
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO rules(id,json,status,updated_at) VALUES(?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET json=excluded.json, status=excluded.status, updated_at=excluded.updated_at`,
		r.ID, jsonStr(r), string(r.Status), ts(now))
	return err
}

// --- users and sessions ----------------------------------------------------

func (s *SQLite) CreateUser(ctx context.Context, username, passwordHash string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO users(username,password_hash,created_at) VALUES(?,?,?)`, username, passwordHash, ts(time.Now()))
	if isUnique(err) {
		return ErrExists
	}
	return err
}

func (s *SQLite) GetUser(ctx context.Context, username string) (User, error) {
	var u User
	var c int64
	err := s.db.QueryRowContext(ctx, `SELECT username,password_hash,created_at FROM users WHERE username=?`, username).Scan(&u.Username, &u.PasswordHash, &c)
	u.CreatedAt = fromTS(c)
	return u, notFound(err)
}

func (s *SQLite) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT username,password_hash,created_at FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		var c int64
		if err := rows.Scan(&u.Username, &u.PasswordHash, &c); err != nil {
			return nil, err
		}
		u.CreatedAt = fromTS(c)
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *SQLite) SetUserPassword(ctx context.Context, username, passwordHash string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET password_hash=? WHERE username=?`, passwordHash, username)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	// a password change invalidates existing sessions
	_, err = s.db.ExecContext(ctx, `DELETE FROM sessions WHERE username=?`, username)
	return err
}

func (s *SQLite) DeleteUser(ctx context.Context, username string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE username=?`, username)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

func (s *SQLite) CreateSession(ctx context.Context, se Session) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions(token_hash,username,created_at,expires_at) VALUES(?,?,?,?)`,
		se.TokenHash, se.Username, ts(se.CreatedAt), ts(se.ExpiresAt))
	return err
}

func (s *SQLite) GetSession(ctx context.Context, tokenHash string, now time.Time) (Session, error) {
	var se Session
	var c, e int64
	err := s.db.QueryRowContext(ctx, `SELECT token_hash,username,created_at,expires_at FROM sessions WHERE token_hash=? AND expires_at>?`,
		tokenHash, ts(now)).Scan(&se.TokenHash, &se.Username, &c, &e)
	se.CreatedAt, se.ExpiresAt = fromTS(c), fromTS(e)
	return se, notFound(err)
}

func (s *SQLite) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash=?`, tokenHash)
	return err
}

// ExtendSession sets a still-valid session's expiry; ErrNotFound if it is gone or already expired.
func (s *SQLite) ExtendSession(ctx context.Context, tokenHash string, expiresAt, now time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE sessions SET expires_at=? WHERE token_hash=? AND expires_at>?`,
		ts(expiresAt), tokenHash, ts(now))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) DeleteExpiredSessions(ctx context.Context, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at<=?`, ts(now))
	return err
}

// --- settings and kv -------------------------------------------------------

func (s *SQLite) GetSetting(ctx context.Context, key string) (json.RawMessage, error) {
	var v string
	if err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, key).Scan(&v); err != nil {
		return nil, notFound(err)
	}
	return json.RawMessage(v), nil
}

func (s *SQLite) SetSetting(ctx context.Context, key string, value json.RawMessage, now time.Time) error {
	if !json.Valid(value) {
		return errors.New("setting value is not valid JSON")
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO settings(key,value,updated_at) VALUES(?,?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`, key, string(value), ts(now))
	return err
}

func (s *SQLite) KVGet(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM kv WHERE key=?`, key).Scan(&v)
	return v, notFound(err)
}

func (s *SQLite) KVSet(ctx context.Context, key, value string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO kv(key,value,updated_at) VALUES(?,?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`, key, value, ts(now))
	return err
}
