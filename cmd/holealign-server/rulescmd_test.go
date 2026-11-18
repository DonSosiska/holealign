package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	repoRules = "../../rules"
	repoTests = "../../rules-tests"
)

func TestRulesCLIFlow(t *testing.T) {
	t.Setenv("HOLEALIGN_CONFIG", "")
	t.Setenv("SOURCE_DATE_EPOCH", "")
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "rules.key")

	code, out, errOut := runCLI(t, "", "rules", "keygen", "-out", keyFile)
	if code != 0 || !strings.Contains(out, "public_key: ") || !strings.Contains(out, "key_id:") {
		t.Fatalf("keygen: %d %q %q", code, out, errOut)
	}
	pub := ""
	for _, l := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(l, "public_key: "); ok {
			pub = strings.TrimSpace(v)
		}
	}
	if st, err := os.Stat(keyFile); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", st, err)
	}
	if strings.Contains(out, "PRIVATE") || strings.Contains(out, mustRead(t, keyFile)) {
		t.Fatal("private key printed")
	}
	// refuses to overwrite
	before := mustRead(t, keyFile)
	if code, _, errOut := runCLI(t, "", "rules", "keygen", "-out", keyFile); code == 0 || !strings.Contains(errOut, "refusing to overwrite") {
		t.Fatalf("overwrite: %d %q", code, errOut)
	}
	if mustRead(t, keyFile) != before {
		t.Fatal("key was overwritten")
	}

	// build is deterministic
	out1, out2 := filepath.Join(dir, "o1"), filepath.Join(dir, "o2")
	args := func(o string) []string {
		return []string{"rules", "build", "-rules", repoRules, "-tests", repoTests, "-seq", "7", "-out", o, "-created-at", "2026-03-04T05:06:07Z"}
	}
	code, sha1, errOut := runCLI(t, "", args(out1)...)
	if code != 0 || len(strings.TrimSpace(sha1)) != 64 {
		t.Fatalf("build: %d %q %q", code, sha1, errOut)
	}
	_, sha2, _ := runCLI(t, "", args(out2)...)
	if sha1 != sha2 {
		t.Fatalf("not deterministic: %s vs %s", sha1, sha2)
	}
	tarball := filepath.Join(out1, "rules-7.tar.gz")

	// sign -> .sig + latest.json, verify
	if code, _, errOut := runCLI(t, "", "rules", "sign", "-key", keyFile, tarball); code != 0 {
		t.Fatalf("sign: %d %q", code, errOut)
	}
	for _, n := range []string{"rules-7.tar.gz.sig", "latest.json"} {
		if _, err := os.Stat(filepath.Join(out1, n)); err != nil {
			t.Fatal(err)
		}
	}
	if l := mustRead(t, filepath.Join(out1, "latest.json")); !strings.Contains(l, `"seq": 7`) || !strings.Contains(l, `"url": "rules-7.tar.gz"`) {
		t.Fatalf("latest.json: %s", l)
	}
	code, out, errOut = runCLI(t, "", "rules", "verify", "-pub", pub, tarball)
	if code != 0 || !strings.Contains(out, "OK: bundle 7, 8 rules") {
		t.Fatalf("verify: %d %q %q", code, out, errOut)
	}
	_, otherOut, _ := runCLI(t, "", "rules", "keygen", "-out", filepath.Join(dir, "other.key"))
	otherPub := strings.TrimSpace(strings.SplitN(strings.TrimPrefix(otherOut, "public_key: "), "\n", 2)[0])
	if code, _, _ := runCLI(t, "", "rules", "verify", "-pub", otherPub, tarball); code == 0 {
		t.Fatal("verified with a foreign key")
	}

	// import + status through the server configuration
	data := filepath.Join(dir, "data")
	cfg := filepath.Join(dir, "server.yaml")
	if err := os.WriteFile(cfg, []byte("data_dir: "+data+"\nrules:\n  feed:\n    enabled: true\n    trusted_keys: ["+pub+"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errOut = runCLI(t, "", "-config", cfg, "rules", "import", tarball)
	if code != 0 || !strings.Contains(out, "installed rules bundle 7 (8 rules)") {
		t.Fatalf("import: %d %q %q", code, out, errOut)
	}
	if code, _, errOut := runCLI(t, "", "-config", cfg, "rules", "import", tarball); code == 0 || !strings.Contains(errOut, "already installed") {
		t.Fatalf("re-import: %d %q", code, errOut)
	}
	code, out, _ = runCLI(t, "", "-config", cfg, "rules", "status")
	if code != 0 || !strings.Contains(out, "installed:      seq 7") || !strings.Contains(out, "rules:          8") {
		t.Fatalf("status: %d %q", code, out)
	}
}

func TestRulesBuildRefusesBadInput(t *testing.T) {
	dir := t.TempDir()
	rd := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rd, 0o755); err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(filepath.Join(repoRules, "CVE-2024-4577.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	draft := strings.Replace(string(src), "status: reviewed", "status: draft", 1)
	if err := os.WriteFile(filepath.Join(rd, "CVE-2024-4577.yaml"), []byte(draft), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	code, _, errOut := runCLI(t, "", "rules", "build", "-rules", rd, "-tests", repoTests, "-seq", "1", "-out", out)
	if code == 0 || !strings.Contains(errOut, "only reviewed rules") {
		t.Fatalf("draft accepted: %d %q", code, errOut)
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("output directory created for a failed build")
	}
}

func TestRulesImportNeedsTrustedKeys(t *testing.T) {
	t.Setenv("HOLEALIGN_CONFIG", "")
	cfg := filepath.Join(t.TempDir(), "server.yaml")
	if err := os.WriteFile(cfg, []byte("data_dir: "+t.TempDir()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := runCLI(t, "", "-config", cfg, "rules", "import", "x.tar.gz"); code == 0 || !strings.Contains(errOut, "trusted_keys") {
		t.Fatalf("%d %q", code, errOut)
	}
	if code, _, _ := runCLI(t, "", "rules"); code != 2 {
		t.Fatal("usage exit code")
	}
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
