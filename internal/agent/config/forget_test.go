package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tokenDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	old := enrollTokenDir
	enrollTokenDir = dir
	t.Cleanup(func() { enrollTokenDir = old })
	return dir
}

func TestForgetEnrollToken(t *testing.T) {
	dir := tokenDir(t)
	path := filepath.Join(dir, "agent.yaml")
	orig := "# Written by install.sh\nserver_url: \"https://x.example\"\nenroll_token: \"pt_secret123\"\nlabels: [\"a\"]\nnested:\n  enroll_token: keep-me\nstate_dir: /var/lib/panoptes-agent\n"
	if err := os.WriteFile(path, []byte(orig), 0o640); err != nil {
		t.Fatal(err)
	}
	os.Chmod(path, 0o640)
	before, _ := os.Stat(path)

	if err := ForgetEnrollToken(path); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	want := strings.Replace(orig, `enroll_token: "pt_secret123"`, `enroll_token: ""`, 1)
	if string(got) != want {
		t.Errorf("content:\n%s\nwant:\n%s", got, want)
	}
	if strings.Contains(string(got), "pt_secret123") {
		t.Error("token still present")
	}
	after, _ := os.Stat(path)
	if after.Mode().Perm() != 0o640 {
		t.Errorf("mode = %v, want 0640", after.Mode().Perm())
	}
	if !sameOwner(before, after) {
		t.Error("owner/group changed")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("temporary file left behind: %v", entries)
	}
	cfg, err := Parse(got)
	if err != nil || cfg.EnrollToken != "" || cfg.ServerURL != "https://x.example" {
		t.Errorf("rewritten file does not load: %+v %v", cfg, err)
	}
	// idempotent
	if err := ForgetEnrollToken(path); err != nil {
		t.Fatal(err)
	}
	again, _ := os.ReadFile(path)
	if string(again) != string(got) {
		t.Error("second call changed the file")
	}
}

func TestForgetEnrollTokenOtherForms(t *testing.T) {
	dir := tokenDir(t)
	for in, want := range map[string]string{
		"enroll_token: pt_x\n":           "enroll_token: \"\"\n",
		"enroll_token:   'pt_x'  \n":     "enroll_token: \"\"\n",
		"\"enroll_token\": \"pt_x\"\n":   "\"enroll_token\": \"\"\n",
		"a: 1\nenroll_token: pt_x":       "a: 1\nenroll_token: \"\"",
		"a: 1\r\nenroll_token: pt_x\r\n": "a: 1\r\nenroll_token: \"\"\r\n",
	} {
		path := filepath.Join(dir, "agent.yaml")
		os.WriteFile(path, []byte(in), 0o600)
		if err := ForgetEnrollToken(path); err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if got, _ := os.ReadFile(path); string(got) != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}

func TestForgetEnrollTokenRefusesOtherFiles(t *testing.T) {
	dir := tokenDir(t)
	other := t.TempDir()
	outside := filepath.Join(other, "agent.yaml")
	os.WriteFile(outside, []byte("enroll_token: x\n"), 0o600)
	if err := ForgetEnrollToken(outside); err == nil {
		t.Error("file outside the config directory rewritten")
	}
	if err := ForgetEnrollToken(filepath.Join(dir, "sub", "..", "..", filepath.Base(other), "agent.yaml")); err == nil {
		t.Error("path traversal accepted")
	}
	if err := ForgetEnrollToken("relative.yaml"); err == nil {
		t.Error("relative path accepted")
	}
	// a symlink inside the directory must not redirect the rewrite
	link := filepath.Join(dir, "agent.yaml")
	if err := os.Symlink(outside, link); err != nil {
		t.Skip(err)
	}
	if err := ForgetEnrollToken(link); err == nil {
		t.Error("symlink followed")
	}
	if b, _ := os.ReadFile(outside); !strings.Contains(string(b), "x") {
		t.Error("target of the symlink was modified")
	}
	// directory instead of file
	os.Remove(link)
	os.Mkdir(link, 0o755)
	if err := ForgetEnrollToken(link); err == nil {
		t.Error("directory accepted")
	}
	// a missing file is an error, a file without the key is left alone
	if err := ForgetEnrollToken(filepath.Join(dir, "nope.yaml")); err == nil {
		t.Error("missing file accepted")
	}
	plain := filepath.Join(dir, "plain.yaml")
	os.WriteFile(plain, []byte("server_url: x\n"), 0o640)
	if err := ForgetEnrollToken(plain); err != nil {
		t.Errorf("file without a token: %v", err)
	}
}

func TestPermissionWarnings(t *testing.T) {
	dir := t.TempDir()
	mk := func(name string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte("x"), 0o600)
		os.Chmod(p, mode)
		return p
	}
	good := Config{Path: mk("agent.yaml", 0o640), ClientKey: mk("client.key", 0o600)}
	if w := PermissionWarnings(good, mk("credentials.json", 0o600)); len(w) != 0 {
		t.Errorf("unexpected warnings: %v", w)
	}
	bad := Config{Path: mk("agent2.yaml", 0o644), ClientKey: mk("client2.key", 0o604)}
	w := PermissionWarnings(bad, mk("credentials2.json", 0o640))
	if len(w) != 3 {
		t.Fatalf("warnings = %v", w)
	}
	for i, frag := range []string{"config file", "client_key", "credentials file"} {
		if !strings.Contains(w[i], frag) {
			t.Errorf("warning %d = %q", i, w[i])
		}
	}
	if w := PermissionWarnings(Config{Path: filepath.Join(dir, "missing")}, ""); len(w) != 0 {
		t.Errorf("missing files must be ignored: %v", w)
	}
}
