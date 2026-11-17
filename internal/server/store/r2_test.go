package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"panoptes/internal/model"
)

func hostLabels(t *testing.T, s *SQLite, id string) (labels []string, token string, locked bool) {
	t.Helper()
	h, err := s.GetHost(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	var tn string
	var l int
	if err := s.db.QueryRow(`SELECT token_name, labels_locked FROM hosts WHERE id=?`, id).Scan(&tn, &l); err != nil {
		t.Fatal(err)
	}
	return h.Labels, tn, l != 0
}

func TestReenrollWithOtherTokenKeepsLockedLabelsAndToken(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	_, k1, _ := NewSecret("pa_")
	_, k2, _ := NewSecret("pa_")
	h, err := s.EnrollHost(ctx, EnrollParams{MachineID: "m1", KeyHash: k1, TokenName: "prod", TokenLabels: []string{"prod", "db"}})
	if err != nil {
		t.Fatal(err)
	}
	// old key + a different token WITHOUT labels, self-asserted labels in the request
	if _, err := s.EnrollHost(ctx, EnrollParams{MachineID: "m1", KeyHash: k2, PreviousKeyHash: k1, TokenName: "open", Labels: []string{"dev"}}); err != nil {
		t.Fatal(err)
	}
	ls, tn, locked := hostLabels(t, s, h.ID)
	if tn != "prod" || !locked || len(ls) != 2 || ls[0] != "prod" || ls[1] != "db" {
		t.Fatalf("labels=%v token=%q locked=%v", ls, tn, locked)
	}
	// a new token that carries labels takes over (and its quota is checked)
	_, k3, _ := NewSecret("pa_")
	if _, err := s.EnrollHost(ctx, EnrollParams{MachineID: "m1", KeyHash: k3, PreviousKeyHash: k2, TokenName: "stage", TokenLabels: []string{"stage"}, MaxHosts: 1}); err != nil {
		t.Fatal(err)
	}
	ls, tn, locked = hostLabels(t, s, h.ID)
	if tn != "stage" || !locked || len(ls) != 1 || ls[0] != "stage" {
		t.Fatalf("labels=%v token=%q locked=%v", ls, tn, locked)
	}
	// another host fills token "stage" (max 1) -> a third host cannot move onto it
	_, ko, _ := NewSecret("pa_")
	_, ko2, _ := NewSecret("pa_")
	if _, err := s.EnrollHost(ctx, EnrollParams{MachineID: "m2", KeyHash: ko, TokenName: "other", TokenLabels: []string{"x"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnrollHost(ctx, EnrollParams{MachineID: "m2", KeyHash: ko2, PreviousKeyHash: ko, TokenName: "stage", TokenLabels: []string{"stage"}, MaxHosts: 1}); !errors.Is(err, ErrTokenExhausted) {
		t.Fatalf("max_hosts on re-enroll: %v", err)
	}
	// an unlocked host keeps taking the labels of the request
	_, ku, _ := NewSecret("pa_")
	_, ku2, _ := NewSecret("pa_")
	u, _ := s.EnrollHost(ctx, EnrollParams{MachineID: "m3", KeyHash: ku, TokenName: "open", Labels: []string{"a"}})
	if _, err := s.EnrollHost(ctx, EnrollParams{MachineID: "m3", KeyHash: ku2, PreviousKeyHash: ku, TokenName: "open", Labels: []string{"b"}}); err != nil {
		t.Fatal(err)
	}
	if ls, _, locked := hostLabels(t, s, u.ID); locked || len(ls) != 1 || ls[0] != "b" {
		t.Fatalf("unlocked host: %v %v", ls, locked)
	}
}

func TestReenrollAllowedExpires(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	_, k1, _ := NewSecret("pa_")
	_, k2, _ := NewSecret("pa_")
	a, _ := s.EnrollHost(ctx, EnrollParams{MachineID: "m1", KeyHash: k1})
	if err := s.SetReenrollAllowedUntil(ctx, a.ID, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnrollHost(ctx, EnrollParams{MachineID: "m1", KeyHash: k2}); !errors.Is(err, ErrReenrollDenied) {
		t.Fatalf("expired permission honoured: %v", err)
	}
	hs, _ := s.ListHostsAdmin(ctx)
	if hs[0].ReenrollAllowed {
		t.Fatal("expired flag shown as allowed")
	}
	if err := s.SetReenrollAllowedUntil(ctx, a.ID, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	hs, _ = s.ListHostsAdmin(ctx)
	if !hs[0].ReenrollAllowed || time.Until(hs[0].ReenrollUntil) < 50*time.Minute {
		t.Fatalf("%+v", hs[0])
	}
	if err := s.SetReenrollAllowed(ctx, a.ID, true); err != nil { // default TTL
		t.Fatal(err)
	}
	if _, err := s.EnrollHost(ctx, EnrollParams{MachineID: "m1", KeyHash: k2}); err != nil {
		t.Fatal(err)
	}
}

func TestSkippedTargetsRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	h := enroll(t, s, "m1")
	p := model.InventoryPayload{Hash: "a", Targets: []model.InventoryTarget{{Kind: model.TargetHost, Name: "host", SBOM: []byte(`{"bomFormat":"CycloneDX"}`)}}}
	skipped := []SkippedTarget{{Kind: model.TargetContainerImage, Name: "huge", Reason: "too big"}, {Kind: model.TargetHost, Name: "host", Reason: "duplicate"}}
	if err := s.ReplaceInventorySkipped(ctx, h.ID, p, skipped); err != nil {
		t.Fatal(err)
	}
	ts, _ := s.ListTargets(ctx, h.ID)
	if len(ts) != 1 || ts[0].Name != "host" || len(ts[0].SBOM) == 0 {
		t.Fatalf("targets: %+v", ts)
	}
	sk, _ := s.ListSkippedTargets(ctx, h.ID)
	if len(sk) != 1 || sk[0].Name != "huge" || sk[0].Reason != "too big" {
		t.Fatalf("skipped: %+v", sk)
	}
	// a plain ReplaceInventory clears them
	if err := s.ReplaceInventory(ctx, h.ID, p); err != nil {
		t.Fatal(err)
	}
	if sk, _ := s.ListSkippedTargets(ctx, h.ID); len(sk) != 0 {
		t.Fatalf("stale skipped rows: %+v", sk)
	}
}

func TestDeleteHostRemovesPerHostState(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	h := enroll(t, s, "m1")
	o := enroll(t, s, "m2")
	for _, k := range []string{"poison." + h.ID + ".abcd", "health.pipeline_alert." + h.ID, "poison." + o.ID + ".abcd", "health.pipeline_alert." + o.ID, "feeds.grype.updated_at"} {
		_ = s.KVSet(ctx, k, "x", time.Now())
	}
	_ = s.RecordNotification(ctx, "host|"+h.ID+"|silent", "host|"+h.ID+"|agent_silent", model.EventAgentSilent, time.Now())
	_ = s.RecordNotification(ctx, o.ID+"|t|p|CVE", o.ID+"|t|p|CVE|exploitable", model.EventExploitable, time.Now())
	_ = s.RecordNotification(ctx, h.ID+"|t|p|CVE", h.ID+"|t|p|CVE|exploitable", model.EventExploitable, time.Now())
	if err := s.DeleteHost(ctx, h.ID); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]bool{"poison." + h.ID + ".abcd": false, "health.pipeline_alert." + h.ID: false,
		"poison." + o.ID + ".abcd": true, "health.pipeline_alert." + o.ID: true, "feeds.grype.updated_at": true} {
		if _, err := s.KVGet(ctx, k); (err == nil) != want {
			t.Errorf("kv %s present=%v want %v", k, err == nil, want)
		}
	}
	for k, want := range map[string]bool{"host|" + h.ID + "|agent_silent": false, h.ID + "|t|p|CVE|exploitable": false, o.ID + "|t|p|CVE|exploitable": true} {
		if ok, _ := s.NotificationSent(ctx, k); ok != want {
			t.Errorf("notification %s present=%v want %v", k, ok, want)
		}
	}
	if err := s.DeleteHost(ctx, h.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
}

func TestRetentionPrune(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	h := enroll(t, s, "m1")
	old := time.Now().Add(-100 * 24 * time.Hour)
	mk := func(id string) model.Finding {
		return model.Finding{HostID: h.ID, Target: "host", TargetKind: model.TargetHost, PackageName: "p", PackageVer: "1", VulnID: id, Severity: "High", Verdict: model.VerdictExploitable}
	}
	// both findings first seen long ago; B vanishes (resolved at `old`), A stays open
	if _, err := s.ApplyHostFindings(ctx, h.ID, []model.Finding{mk("CVE-A"), mk("CVE-B")}, old); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyHostFindings(ctx, h.ID, []model.Finding{mk("CVE-A")}, old.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// a recently resolved one must survive
	if _, err := s.ApplyHostFindings(ctx, h.ID, []model.Finding{mk("CVE-A"), mk("CVE-C")}, time.Now().Add(-48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyHostFindings(ctx, h.ID, []model.Finding{mk("CVE-A")}, time.Now().Add(-24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	n, err := s.PruneResolvedFindings(ctx, time.Now().Add(-30*24*time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("pruned %d (%v), want only CVE-B", n, err)
	}
	all, _ := s.HostFindings(ctx, h.ID)
	if len(all) != 2 {
		t.Fatalf("left: %+v", all)
	}

	// notifications: old rows go, except that of the still-open finding
	fa, fb := mk("CVE-A"), mk("CVE-B")
	_ = s.RecordNotification(ctx, FindingKey(fa), DedupKey(fa, model.EventExploitable), model.EventExploitable, old)
	_ = s.RecordNotification(ctx, FindingKey(fb), DedupKey(fb, model.EventExploitable), model.EventExploitable, old)
	fresh := mk("CVE-N")
	_ = s.RecordNotification(ctx, FindingKey(fresh), DedupKey(fresh, model.EventExploitable), model.EventExploitable, time.Now())
	n, err = s.PruneNotifications(ctx, time.Now().Add(-90*24*time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("pruned %d notifications (%v), want 1", n, err)
	}
	if ok, _ := s.NotificationSent(ctx, DedupKey(fa, model.EventExploitable)); !ok {
		t.Fatal("dedup row of an open finding pruned (would re-alert)")
	}
	if ok, _ := s.NotificationSent(ctx, DedupKey(fb, model.EventExploitable)); ok {
		t.Fatal("old row of a resolved finding kept")
	}
}
