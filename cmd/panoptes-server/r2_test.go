package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DonSosiska/panoptes/internal/model"
	"github.com/DonSosiska/panoptes/internal/server/store"
)

func TestTokenNameValidation(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PANOPTES_CONFIG", "")
	t.Setenv("PANOPTES_DATA_DIR", dir)
	for _, bad := range []string{"-lead", ".dot", "has space", "semi;colon", "new\nline", strings.Repeat("a", 65), "ü"} {
		if code, _, _ := runCLI(t, "", "token", "create", bad); code == 0 {
			t.Errorf("accepted token name %q", bad)
		}
	}
	for _, ok := range []string{"a", "Prod-1", "web.eu_1", strings.Repeat("a", 64)} {
		if code, _, errs := runCLI(t, "", "token", "create", ok); code != 0 {
			t.Errorf("rejected %q: %s", ok, errs)
		}
	}
}

func TestAllowReenrollTTL(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PANOPTES_CONFIG", "")
	t.Setenv("PANOPTES_DATA_DIR", dir)
	st, err := store.OpenSQLite(filepath.Join(dir, "panoptes.db"))
	if err != nil {
		t.Fatal(err)
	}
	_, hash, _ := store.NewSecret("pa_")
	h, err := st.EnrollHost(context.Background(), store.EnrollParams{MachineID: "m1", Hostname: "web1", KeyHash: hash})
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	until := func() time.Time {
		st, _ := store.OpenSQLite(filepath.Join(dir, "panoptes.db"))
		defer st.Close()
		hs, _ := st.ListHostsAdmin(context.Background())
		return hs[0].ReenrollUntil
	}
	if code, _, errs := runCLI(t, "", "host", "allow-reenroll", "web1"); code != 0 {
		t.Fatal(errs)
	}
	if d := time.Until(until()); d < 55*time.Minute || d > 61*time.Minute {
		t.Fatalf("default ttl: %v", d)
	}
	if code, _, errs := runCLI(t, "", "host", "allow-reenroll", h.ID, "-ttl", "10m"); code != 0 {
		t.Fatal(errs)
	}
	if d := time.Until(until()); d < 9*time.Minute || d > 11*time.Minute {
		t.Fatalf("ttl 10m: %v", d)
	}
	if code, _, errs := runCLI(t, "", "host", "allow-reenroll", "-ttl", "5m", "web1"); code != 0 {
		t.Fatal(errs)
	}
	for _, bad := range []string{"0s", "-1h", "9999h"} {
		if code, _, _ := runCLI(t, "", "host", "allow-reenroll", "web1", "-ttl", bad); code == 0 {
			t.Errorf("ttl %s accepted", bad)
		}
	}
	_, out, _ := runCLI(t, "", "host", "list")
	if !strings.Contains(out, "allowed until ") {
		t.Fatalf("list: %q", out)
	}
}

func TestPruneOnce(t *testing.T) {
	cfg := mustLoad(t)
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	_, hash, _ := store.NewSecret("pa_")
	h, _ := st.EnrollHost(ctx, store.EnrollParams{MachineID: "m1", KeyHash: hash})
	f := model.Finding{HostID: h.ID, Target: "host", TargetKind: model.TargetHost, PackageName: "p", PackageVer: "1", VulnID: "CVE-1", Verdict: model.VerdictExploitable}
	old := time.Now().Add(-60 * 24 * time.Hour)
	_, _ = st.ApplyHostFindings(ctx, h.ID, []model.Finding{f}, old)
	_, _ = st.ApplyHostFindings(ctx, h.ID, nil, old) // resolved 60 days ago
	_ = st.RecordNotification(ctx, "k", "k|x", model.EventExploitable, time.Now().Add(-100*24*time.Hour))
	pruneOnce(ctx, st, cfg, time.Now(), nopLogger())
	if all, _ := st.HostFindings(ctx, h.ID); len(all) != 0 {
		t.Fatalf("resolved finding older than 30d kept: %+v", all)
	}
	if ok, _ := st.NotificationSent(ctx, "k|x"); ok {
		t.Fatal("notification older than 90d kept")
	}
	// 0 = keep
	cfg.Retention.ResolvedFindings, cfg.Retention.Notifications = 0, 0
	_, _ = st.ApplyHostFindings(ctx, h.ID, []model.Finding{f}, old)
	_, _ = st.ApplyHostFindings(ctx, h.ID, nil, old)
	_ = st.RecordNotification(ctx, "k", "k|x", model.EventExploitable, old)
	pruneOnce(ctx, st, cfg, time.Now(), nopLogger())
	if all, _ := st.HostFindings(ctx, h.ID); len(all) != 1 {
		t.Fatal("retention 0 must keep everything")
	}
	if ok, _ := st.NotificationSent(ctx, "k|x"); !ok {
		t.Fatal("retention 0 must keep notifications")
	}
}

func TestCLIOwnerResolution(t *testing.T) {
	dir := t.TempDir()
	uid := os.Getuid()
	if uid == 0 {
		t.Skip("owner resolution differs when the test itself runs as root")
	}
	db := filepath.Join(dir, "panoptes.db")
	got, _, err := cliOwner(dir, db)
	if err != nil || got != uid {
		t.Fatalf("existing dir: uid=%d err=%v", got, err)
	}
	// a data dir that does not exist yet resolves to the nearest existing parent
	got, _, err = cliOwner(filepath.Join(dir, "a", "b"), filepath.Join(dir, "a", "b", "panoptes.db"))
	if err != nil || got != uid {
		t.Fatalf("missing dir: uid=%d err=%v", got, err)
	}
}

func TestPrepareCLICreatesDataDirAsCurrentUser(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "new", "data")
	t.Setenv("PANOPTES_CONFIG", "")
	t.Setenv("PANOPTES_DATA_DIR", dir)
	if code, _, errs := runCLI(t, "", "token", "list"); code != 0 {
		t.Fatal(errs)
	}
	if _, err := os.Stat(filepath.Join(dir, "panoptes.db")); err != nil {
		t.Fatal(err)
	}
}
