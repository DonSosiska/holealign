package store

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"panoptes/internal/model"
)

func open(t *testing.T) *SQLite {
	t.Helper()
	s, err := OpenSQLite(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func enroll(t *testing.T, s *SQLite, machine string, labels ...string) model.Host {
	t.Helper()
	_, hash, _ := NewSecret("pa_")
	h, err := s.EnrollHost(context.Background(), EnrollParams{MachineID: machine, Hostname: machine, Labels: labels, KeyHash: hash})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestMigrationsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.db")
	s, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := s.SchemaVersion(context.Background())
	if v < 1 {
		t.Fatalf("schema version %d", v)
	}
	s.Close()
	s, err = OpenSQLite(path) // second open must not re-run migrations
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
}

func TestPragmas(t *testing.T) {
	s := open(t)
	var mode string
	var busy, fk int
	_ = s.db.QueryRow(`PRAGMA journal_mode`).Scan(&mode)
	_ = s.db.QueryRow(`PRAGMA busy_timeout`).Scan(&busy)
	_ = s.db.QueryRow(`PRAGMA foreign_keys`).Scan(&fk)
	if mode != "wal" || busy < 1000 || fk != 1 {
		t.Fatalf("pragmas: mode=%s busy=%d fk=%d", mode, busy, fk)
	}
}

func TestSecrets(t *testing.T) {
	sec, hash, err := NewSecret("pt_")
	if err != nil || sec[:3] != "pt_" || HashSecret(sec) != hash || len(hash) != 64 {
		t.Fatalf("bad secret %q %q %v", sec, hash, err)
	}
}

func TestEnrollRotatesKeyAndReusesHost(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	k1, h1, _ := NewSecret("pa_")
	k2, h2, _ := NewSecret("pa_")
	_ = k1
	_ = k2
	a, err := s.EnrollHost(ctx, EnrollParams{MachineID: "m1", Hostname: "web1", KeyHash: h1})
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.EnrollHost(ctx, EnrollParams{MachineID: "m1", Hostname: "web1-renamed", KeyHash: h2})
	if err != nil {
		t.Fatal(err)
	}
	if a.ID != b.ID || b.Hostname != "web1-renamed" {
		t.Fatalf("host not reused: %+v %+v", a, b)
	}
	if _, err := s.HostByAgentKey(ctx, h1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old key should be rotated out, got %v", err)
	}
	if h, err := s.HostByAgentKey(ctx, h2); err != nil || h.ID != a.ID {
		t.Fatalf("new key: %v %v", h, err)
	}
}

func TestEnrollTokens(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	_, hash, _ := NewSecret("pt_")
	if err := s.CreateEnrollToken(ctx, "lab", hash); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateEnrollToken(ctx, "lab", "other"); !errors.Is(err, ErrExists) {
		t.Fatalf("dup name: %v", err)
	}
	if ok, _ := s.UseEnrollToken(ctx, hash); !ok {
		t.Fatal("token should be valid")
	}
	if ok, _ := s.UseEnrollToken(ctx, "nope"); ok {
		t.Fatal("unknown token valid")
	}
	if err := s.RevokeEnrollToken(ctx, "lab"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.UseEnrollToken(ctx, hash); ok {
		t.Fatal("revoked token valid")
	}
	l, _ := s.ListEnrollTokens(ctx)
	if len(l) != 1 || !l[0].Revoked {
		t.Fatalf("list: %+v", l)
	}
	if err := s.RevokeEnrollToken(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}

func TestCheckinFactsMerge(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	h := enroll(t, s, "m1")
	now := time.Now()
	r, err := s.ApplyCheckin(ctx, h.ID, model.CheckinRequest{
		Labels: []string{"prod"}, OS: model.OSInfo{ID: "debian", VersionID: "12"}, FactsComplete: true,
		Facts: model.Facts{"os.id": "debian", "a": "1", "b": "2"},
	}, now)
	if err != nil || !r.FactsChanged || !r.FirstCheckin {
		t.Fatalf("%+v %v", r, err)
	}
	// diff: change a, delete b, add c
	r, err = s.ApplyCheckin(ctx, h.ID, model.CheckinRequest{Facts: model.Facts{"a": "9", "b": nil, "c": []any{"x"}}}, now)
	if err != nil || !r.FactsChanged || r.FirstCheckin {
		t.Fatalf("%+v %v", r, err)
	}
	f := r.Host.Facts
	if f["a"] != "9" || f["os.id"] != "debian" || f["c"] == nil {
		t.Fatalf("facts: %v", f)
	}
	if _, ok := f["b"]; ok {
		t.Fatal("b should be deleted")
	}
	if len(r.Host.Labels) != 1 || r.Host.Labels[0] != "prod" || r.Host.OS.ID != "debian" {
		t.Fatalf("labels kept: %+v", r.Host.Labels)
	}
	// same diff again: no change
	r, _ = s.ApplyCheckin(ctx, h.ID, model.CheckinRequest{Facts: model.Facts{"a": "9"}}, now)
	if r.FactsChanged {
		t.Fatal("no-op diff reported as change")
	}
	// complete snapshot replaces
	r, _ = s.ApplyCheckin(ctx, h.ID, model.CheckinRequest{FactsComplete: true, Facts: model.Facts{"z": true}}, now)
	if len(r.Host.Facts) != 1 || r.Host.Facts["z"] != true || !r.FactsChanged {
		t.Fatalf("replace: %v", r.Host.Facts)
	}
}

func TestInventoryReplace(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	h := enroll(t, s, "m1")
	p := model.InventoryPayload{Hash: "h1", Targets: []model.InventoryTarget{
		{Kind: model.TargetHost, Name: "host", SBOM: json.RawMessage(`{"a":1}`)},
		{Kind: model.TargetContainerImage, Name: "nginx:1", ImageID: "sha256:x", Containers: []string{"web"}, SBOM: json.RawMessage(`{"b":2}`)},
	}}
	if err := s.ReplaceInventory(ctx, h.ID, p); err != nil {
		t.Fatal(err)
	}
	p.Hash, p.Targets = "h2", p.Targets[:1]
	if err := s.ReplaceInventory(ctx, h.ID, p); err != nil {
		t.Fatal(err)
	}
	ts, _ := s.ListTargets(ctx, h.ID)
	if len(ts) != 1 || string(ts[0].SBOM) != `{"a":1}` {
		t.Fatalf("targets: %+v", ts)
	}
	got, _ := s.GetHost(ctx, h.ID)
	if got.InventoryHash != "h2" {
		t.Fatal(got.InventoryHash)
	}
	if err := s.ReplaceInventory(ctx, "nohost", p); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown host: %v", err)
	}
}

func finding(host, pkg, ver, vuln string, v model.Verdict) model.Finding {
	return model.Finding{HostID: host, Target: "host", TargetKind: model.TargetHost, PackageName: pkg, PackageVer: ver,
		PackageType: "deb", VulnID: vuln, Severity: "High", CVSS: 7.5, Verdict: v, Aliases: []string{"GHSA-" + vuln}}
}

func TestFindingsUpsertResolveAndFilter(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	h1 := enroll(t, s, "m1", "prod", "web")
	h2 := enroll(t, s, "m2", "dev")
	t0 := time.Now().Add(-time.Hour)
	t1 := time.Now()

	a := finding(h1.ID, "openssl", "1.0", "CVE-1", model.VerdictExploitable)
	a.KEV = true
	b := finding(h1.ID, "bash", "5.0", "CVE-2", model.VerdictConditionsUnknown)
	c := finding(h2.ID, "curl", "7", "CVE-3", model.VerdictNotExploitable)
	r, err := s.ApplyHostFindings(ctx, h1.ID, []model.Finding{a, b}, t0)
	if err != nil || len(r.Current) != 2 || len(r.Resolved) != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := s.ApplyHostFindings(ctx, h2.ID, []model.Finding{c}, t0); err != nil {
		t.Fatal(err)
	}
	firstID := r.Current[0].ID

	// upsert same key: same id, first_seen kept, verdict updated; b disappears -> resolved
	a2 := a
	a2.Verdict = model.VerdictNotExploitable
	r, err = s.ApplyHostFindings(ctx, h1.ID, []model.Finding{a2}, t1)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Current) != 1 || r.Current[0].ID != firstID || r.Current[0].Verdict != model.VerdictNotExploitable {
		t.Fatalf("upsert: %+v", r.Current)
	}
	if !r.Current[0].FirstSeen.Before(r.Current[0].LastSeen) {
		t.Fatal("first_seen should be preserved")
	}
	if len(r.Resolved) != 1 || r.Resolved[0].VulnID != "CVE-2" || r.Resolved[0].Verdict != model.VerdictResolved {
		t.Fatalf("resolved: %+v", r.Resolved)
	}
	// resolving twice does not re-report
	r, _ = s.ApplyHostFindings(ctx, h1.ID, []model.Finding{a2}, t1)
	if len(r.Resolved) != 0 {
		t.Fatal("already resolved reported again")
	}

	all, total, err := s.ListFindings(ctx, FindingFilter{})
	if err != nil || total != 2 || len(all) != 2 {
		t.Fatalf("default list excludes resolved: %d %v", total, err)
	}
	_, total, _ = s.ListFindings(ctx, FindingFilter{IncludeResolved: true})
	if total != 3 {
		t.Fatalf("include resolved: %d", total)
	}
	res, _, _ := s.ListFindings(ctx, FindingFilter{Verdict: model.VerdictResolved})
	if len(res) != 1 || res[0].VulnID != "CVE-2" {
		t.Fatalf("resolved filter: %+v", res)
	}
	yes := true
	kev, _, _ := s.ListFindings(ctx, FindingFilter{KEV: &yes})
	if len(kev) != 1 || kev[0].VulnID != "CVE-1" {
		t.Fatalf("kev: %+v", kev)
	}
	lab, _, _ := s.ListFindings(ctx, FindingFilter{Label: "prod"})
	if len(lab) != 1 || lab[0].HostID != h1.ID {
		t.Fatalf("label: %+v", lab)
	}
	if lab, _, _ = s.ListFindings(ctx, FindingFilter{Label: "web"}); len(lab) != 1 {
		t.Fatal("second label")
	}
	if lab, _, _ = s.ListFindings(ctx, FindingFilter{Label: "nolabel"}); len(lab) != 0 {
		t.Fatal("unknown label matched")
	}
	byAlias, _, _ := s.ListFindings(ctx, FindingFilter{VulnID: "GHSA-CVE-3"})
	if len(byAlias) != 1 || byAlias[0].VulnID != "CVE-3" {
		t.Fatalf("alias filter: %+v", byAlias)
	}
	byHost, _, _ := s.ListFindings(ctx, FindingFilter{HostID: h2.ID})
	if len(byHost) != 1 {
		t.Fatal("host filter")
	}
	page, total, _ := s.ListFindings(ctx, FindingFilter{Limit: 1, Offset: 1})
	if len(page) != 1 || total != 2 {
		t.Fatalf("paging: %d/%d", len(page), total)
	}
	g, err := s.GetFinding(ctx, firstID)
	if err != nil || g.PackageName != "openssl" || len(g.Aliases) != 1 {
		t.Fatalf("get: %+v %v", g, err)
	}
	if _, err := s.GetFinding(ctx, 9999); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	// a resolved finding that reappears is revived under the same id
	b2 := b
	b2.Verdict = model.VerdictExploitable
	r, _ = s.ApplyHostFindings(ctx, h1.ID, []model.Finding{a2, b2}, t1)
	if len(r.Current) != 2 || r.Current[1].Verdict != model.VerdictExploitable {
		t.Fatalf("revive: %+v", r.Current)
	}
}

func TestSQLInjectionSafeFilter(t *testing.T) {
	s := open(t)
	_, _, err := s.ListFindings(context.Background(), FindingFilter{VulnID: "x'; DROP TABLE findings;--", Label: "' OR 1=1 --"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ListFindings(context.Background(), FindingFilter{}); err != nil {
		t.Fatal(err)
	}
}

func TestNotificationDedup(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	f := finding("h1", "openssl", "1", "CVE-1", model.VerdictExploitable)
	fk := FindingKey(f)
	ek, rk := DedupKey(f, model.EventExploitable), DedupKey(f, model.EventResolved)
	if ok, _ := s.NotificationSent(ctx, ek); ok {
		t.Fatal("nothing sent yet")
	}
	if ok, _ := s.FindingNotified(ctx, fk); ok {
		t.Fatal("not notified")
	}
	_ = s.RecordNotification(ctx, fk, ek, model.EventExploitable, time.Now())
	if ok, _ := s.NotificationSent(ctx, ek); !ok {
		t.Fatal("should be recorded")
	}
	if ok, _ := s.FindingNotified(ctx, fk); !ok {
		t.Fatal("should be notified")
	}
	_ = s.RecordNotification(ctx, fk, rk, model.EventResolved, time.Now())
	if ok, _ := s.NotificationSent(ctx, ek); ok {
		t.Fatal("exploitable key should be cleared by resolved")
	}
	if ok, _ := s.FindingNotified(ctx, fk); ok {
		t.Fatal("resolved is not an alert")
	}
}

func TestRulesUsersSessionsSettingsKV(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	now := time.Now()

	r := model.Rule{ID: "CVE-1", Vulns: []string{"CVE-1"}, Status: model.RuleDraft, ExploitableIf: "true"}
	if err := s.UpsertRule(ctx, r, now); err != nil {
		t.Fatal(err)
	}
	r.Status = model.RuleReviewed
	_ = s.UpsertRule(ctx, r, now)
	got, err := s.GetRule(ctx, "CVE-1")
	if err != nil || got.Status != model.RuleReviewed || got.ExploitableIf != "true" {
		t.Fatalf("%+v %v", got, err)
	}
	if l, _ := s.ListRules(ctx); len(l) != 1 {
		t.Fatal("rules list")
	}
	if _, err := s.GetRule(ctx, "x"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}

	hash, _ := HashPassword("secret")
	if err := s.CreateUser(ctx, "admin", hash); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(ctx, "admin", hash); !errors.Is(err, ErrExists) {
		t.Fatal(err)
	}
	u, _ := s.GetUser(ctx, "admin")
	if !CheckPassword(u.PasswordHash, "secret") || CheckPassword(u.PasswordHash, "wrong") {
		t.Fatal("password check")
	}
	if n, _ := s.CountUsers(ctx); n != 1 {
		t.Fatal(n)
	}
	_ = s.CreateSession(ctx, Session{TokenHash: "th", Username: "admin", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if _, err := s.GetSession(ctx, "th", now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(ctx, "th", now.Add(2*time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatal("expired session valid")
	}
	h2, _ := HashPassword("new")
	_ = s.SetUserPassword(ctx, "admin", h2)
	if _, err := s.GetSession(ctx, "th", now); !errors.Is(err, ErrNotFound) {
		t.Fatal("password change should drop sessions")
	}
	if err := s.SetUserPassword(ctx, "ghost", h2); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if err := s.DeleteUser(ctx, "admin"); err != nil {
		t.Fatal(err)
	}

	if _, err := s.GetSetting(ctx, "matrix.routes"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	_ = s.SetSetting(ctx, "matrix.routes", json.RawMessage(`[{"label":"prod"}]`), now)
	v, _ := s.GetSetting(ctx, "matrix.routes")
	if string(v) != `[{"label":"prod"}]` {
		t.Fatal(string(v))
	}
	if err := s.SetSetting(ctx, "bad", json.RawMessage(`{`), now); err == nil {
		t.Fatal("invalid json accepted")
	}

	_ = s.KVSet(ctx, "feeds.grype.checked", "x", now)
	_ = s.KVSet(ctx, "feeds.grype.checked", "y", now)
	if v, _ := s.KVGet(ctx, "feeds.grype.checked"); v != "y" {
		t.Fatal(v)
	}
}
