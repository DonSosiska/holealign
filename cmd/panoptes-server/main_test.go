package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"panoptes/internal/server/store"
)

func runCLI(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

func TestVersion(t *testing.T) {
	code, out, _ := runCLI(t, "", "-version")
	if code != 0 || !strings.Contains(out, "panoptes-server") {
		t.Fatalf("%d %q", code, out)
	}
}

func TestTokenLifecycle(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PANOPTES_CONFIG", filepath.Join(dir, "none.yaml")) // missing explicit file must fail
	if code, _, _ := runCLI(t, "", "token", "list"); code == 0 {
		t.Fatal("missing config file should fail")
	}
	t.Setenv("PANOPTES_CONFIG", "")
	t.Setenv("PANOPTES_DATA_DIR", dir)

	code, out, _ := runCLI(t, "", "token", "create", "lab")
	tok := strings.TrimSpace(out)
	if code != 0 || !strings.HasPrefix(tok, "pt_") {
		t.Fatalf("create: %d %q", code, out)
	}
	if code, _, _ := runCLI(t, "", "token", "create", "lab"); code == 0 {
		t.Fatal("duplicate name accepted")
	}
	_, out, _ = runCLI(t, "", "token", "list")
	if !strings.Contains(out, "lab") || !strings.Contains(out, "active") || strings.Contains(out, tok) {
		t.Fatalf("list must show name, never the secret: %q", out)
	}
	st, _ := store.OpenSQLite(filepath.Join(dir, "panoptes.db"))
	if ok, _ := st.UseEnrollToken(context.Background(), store.HashSecret(tok)); !ok {
		t.Fatal("token should validate")
	}
	st.Close()

	if code, _, _ := runCLI(t, "", "token", "revoke", "lab"); code != 0 {
		t.Fatal("revoke")
	}
	_, out, _ = runCLI(t, "", "-config", "", "token", "list")
	if !strings.Contains(out, "revoked") {
		t.Fatalf("%q", out)
	}
	if code, _, _ := runCLI(t, "", "token", "revoke", "ghost"); code == 0 {
		t.Fatal("revoking unknown token should fail")
	}
}

func TestUserSetPassword(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PANOPTES_CONFIG", "")
	t.Setenv("PANOPTES_DATA_DIR", dir)
	if code, _, _ := runCLI(t, "short\n", "user", "set-password", "admin"); code == 0 {
		t.Fatal("short password accepted")
	}
	if code, _, _ := runCLI(t, "correct horse\n", "user", "set-password", "admin"); code != 0 {
		t.Fatal("create user")
	}
	if code, _, _ := runCLI(t, "battery staple\n", "user", "set-password", "admin"); code != 0 {
		t.Fatal("update user")
	}
	st, _ := store.OpenSQLite(filepath.Join(dir, "panoptes.db"))
	defer st.Close()
	u, err := st.GetUser(context.Background(), "admin")
	if err != nil || !store.CheckPassword(u.PasswordHash, "battery staple") {
		t.Fatalf("%v", err)
	}
}

func TestEnsureAdmin(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PANOPTES_CONFIG", "")
	t.Setenv("PANOPTES_DATA_DIR", dir)
	t.Setenv("PANOPTES_ADMIN_PASSWORD", "initial-secret")
	_ = os.MkdirAll(dir, 0o750)
	st, _ := store.OpenSQLite(filepath.Join(dir, "panoptes.db"))
	defer st.Close()
	cfg := mustLoad(t)
	if err := ensureAdmin(context.Background(), cfg, st, nopLogger()); err != nil {
		t.Fatal(err)
	}
	u, err := st.GetUser(context.Background(), "admin")
	if err != nil || !store.CheckPassword(u.PasswordHash, "initial-secret") {
		t.Fatalf("%v", err)
	}
}
