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

func TestEnsureAdminLengthAndFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PANOPTES_CONFIG", "")
	t.Setenv("PANOPTES_DATA_DIR", dir)
	st, _ := store.OpenSQLite(filepath.Join(dir, "panoptes.db"))
	defer st.Close()
	cfg := mustLoad(t)

	t.Setenv("PANOPTES_ADMIN_PASSWORD", "elevenchars")
	if err := ensureAdmin(context.Background(), cfg, st, nopLogger()); err == nil {
		t.Fatal("11-char password accepted")
	}
	pwFile := filepath.Join(dir, "pw")
	_ = os.WriteFile(pwFile, []byte("a-long-enough-secret\n"), 0o600)
	t.Setenv("PANOPTES_ADMIN_PASSWORD_FILE", pwFile)
	if err := ensureAdmin(context.Background(), cfg, st, nopLogger()); err != nil {
		t.Fatal(err)
	}
	u, err := st.GetUser(context.Background(), "admin")
	if err != nil || !store.CheckPassword(u.PasswordHash, "a-long-enough-secret") {
		t.Fatalf("file password not used: %v", err)
	}
}

func TestTokenOptionsAndHostCommands(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PANOPTES_CONFIG", "")
	t.Setenv("PANOPTES_DATA_DIR", dir)
	if code, _, _ := runCLI(t, "", "token", "create", "bad", "-labels", "BAD LABEL"); code == 0 {
		t.Fatal("invalid label accepted")
	}
	code, out, _ := runCLI(t, "", "token", "create", "prod", "-max-hosts", "3", "-expires", "72h", "-labels", "prod,web")
	if code != 0 || !strings.HasPrefix(strings.TrimSpace(out), "pt_") {
		t.Fatalf("%d %q", code, out)
	}
	_, out, _ = runCLI(t, "", "token", "list")
	if !strings.Contains(out, "0/3") || !strings.Contains(out, "prod,web") {
		t.Fatalf("list: %q", out)
	}

	st, _ := store.OpenSQLite(filepath.Join(dir, "panoptes.db"))
	_, hash, _ := store.NewSecret("pa_")
	h, err := st.EnrollHost(context.Background(), store.EnrollParams{MachineID: "m1", Hostname: "web1", KeyHash: hash})
	if err != nil {
		t.Fatal(err)
	}
	st.Close()

	_, out, _ = runCLI(t, "", "host", "list")
	if !strings.Contains(out, h.ID) || !strings.Contains(out, "web1") {
		t.Fatalf("host list: %q", out)
	}
	if code, _, _ := runCLI(t, "", "host", "allow-reenroll", "web1"); code != 0 {
		t.Fatal("allow-reenroll by hostname")
	}
	_, out, _ = runCLI(t, "", "host", "list")
	if !strings.Contains(out, "allowed") {
		t.Fatalf("flag not shown: %q", out)
	}
	if code, _, _ := runCLI(t, "", "host", "allow-reenroll", "nope"); code == 0 {
		t.Fatal("unknown host accepted")
	}
	if code, _, _ := runCLI(t, "", "host", "delete", h.ID); code != 0 {
		t.Fatal("delete by id")
	}
	_, out, _ = runCLI(t, "", "host", "list")
	if strings.Contains(out, "web1") {
		t.Fatalf("host still listed: %q", out)
	}
}
