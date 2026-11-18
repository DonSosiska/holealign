package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DonSosiska/holealign/internal/server/config"
	"github.com/DonSosiska/holealign/internal/server/llm"
)

const evalRule = `id: CVE-2099-0100-ref
vulns: [CVE-2099-0100]
title: "reference"
packages:
  - {name: openssh-server, type: deb}
facts: [sshd.config]
exploitable_if: >
  facts["sshd.config"][?"permitrootlogin"].orValue("yes") != "no"
explanation: "Needs root login."
fix:
  upgrade: "Upgrade."
status: reviewed
source: builtin
`

const evalTests = `- name: on
  finding: {vuln: CVE-2099-0100, package: openssh-server, type: deb}
  facts:
    sshd.config: {permitrootlogin: "yes"}
  want: exploitable
- name: off
  finding: {vuln: CVE-2099-0100, package: openssh-server, type: deb}
  facts:
    sshd.config: {permitrootlogin: "no"}
  want: affected_not_exploitable
`

func evalDirs(t *testing.T) (rulesDir, testsDir string) {
	t.Helper()
	d := t.TempDir()
	rulesDir, testsDir = filepath.Join(d, "r"), filepath.Join(d, "t")
	for _, x := range []string{rulesDir, testsDir} {
		if err := os.MkdirAll(x, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.WriteFile(filepath.Join(rulesDir, "CVE-2099-0100-ref.yaml"), []byte(evalRule), 0o644)
	_ = os.WriteFile(filepath.Join(testsDir, "CVE-2099-0100-ref.yaml"), []byte(evalTests), 0o644)
	return
}

func TestRulesEvalCLI(t *testing.T) {
	t.Setenv("HOLEALIGN_CONFIG", "")
	for _, e := range []string{"HOLEALIGN_LLM_PROVIDER", "HOLEALIGN_LLM_MODEL", "HOLEALIGN_LLM_BASE_URL", "HOLEALIGN_LLM_API_KEY", "ANTHROPIC_API_KEY", "HOLEALIGN_LLM_EFFORT"} {
		t.Setenv(e, "")
	}
	osv := httptest.NewServer(http.NotFoundHandler())
	defer osv.Close()
	old := newBotProvider
	defer func() { newBotProvider = old }()
	var seen []config.LLM
	prov := cliProv{cliReply}
	newBotProvider = func(c config.LLM) (llm.Provider, error) { seen = append(seen, c); return prov, nil }
	rd, td := evalDirs(t)
	outF := filepath.Join(t.TempDir(), "report.json")
	code, out, errOut := runCLI(t, "", "rules", "eval", "-rules", rd, "-tests", td, "-provider", "openai-compatible", "-base-url", "http://x",
		"-variants", "m1@low,m2", "-runs", "2", "-osv-url", osv.URL, "-out", outF, "-effort", "high")
	if code != 0 {
		t.Fatalf("%d %q", code, errOut)
	}
	for _, s := range []string{"## m1@low", "## m2@high", "## Variants compared", "CVE-2099-0100-ref | 2/2 | 100%"} {
		if !strings.Contains(out, s) {
			t.Errorf("stdout lacks %q:\n%s", s, out)
		}
	}
	if b, err := os.ReadFile(outF); err != nil || !strings.Contains(string(b), `"variant": "m2@high"`) {
		t.Fatalf("report file: %v %s", err, b)
	}
	if len(seen) != 2 || seen[0].Model != "m1" || seen[0].Effort != "low" || seen[1].Model != "m2" || seen[1].Effort != "high" {
		t.Fatalf("provider configs: %+v", seen)
	}
	if ents, _ := os.ReadDir(rd); len(ents) != 1 {
		t.Fatalf("eval must not write to the rules dir: %v", ents)
	}

	// Failed drafts are measurements: exit 0.
	prov.reply = `{"rule":{"title":"t"},"tests":[]}`
	newBotProvider = func(config.LLM) (llm.Provider, error) { return prov, nil }
	if code, out, errOut = runCLI(t, "", "rules", "eval", "-rules", rd, "-tests", td, "-provider", "openai-compatible", "-base-url", "http://x",
		"-model", "m", "-runs", "1", "-osv-url", osv.URL); code != 0 || !strings.Contains(out, "0/1") {
		t.Fatalf("failed drafts: %d %q %q", code, out, errOut)
	}

	// No call possible: non-zero.
	newBotProvider = func(config.LLM) (llm.Provider, error) { return errProv{}, nil }
	if code, _, errOut = runCLI(t, "", "rules", "eval", "-rules", rd, "-tests", td, "-provider", "openai-compatible", "-base-url", "http://x",
		"-model", "m", "-runs", "1", "-osv-url", osv.URL); code != 1 || !strings.Contains(errOut, "no LLM call") {
		t.Fatalf("no calls: %d %q", code, errOut)
	}

	// Usage errors.
	for _, args := range [][]string{
		{"rules", "eval"},
		{"rules", "eval", "-rules", rd, "-tests", td, "-variants", "m@bogus", "-provider", "openai-compatible"},
		{"rules", "eval", "-rules", rd, "-tests", td, "-ids", "nope", "-model", "m", "-provider", "openai-compatible"},
		{"rules", "eval", "-rules", rd, "-tests", td, "-effort", "extreme", "-model", "m", "-provider", "openai-compatible"},
	} {
		if code, _, _ = runCLI(t, "", args...); code != 1 {
			t.Errorf("%v: exit %d", args, code)
		}
	}
}

type errProv struct{}

func (errProv) Name() string { return "fake:m" }
func (errProv) Complete(context.Context, string, string) (string, error) {
	return "", errors.New("connection refused")
}

func TestBotUsageLine(t *testing.T) {
	var u botUsage
	var b bytes.Buffer
	u.print(&b)
	if b.Len() != 0 {
		t.Fatalf("no calls, no line: %q", b.String())
	}
	u.add(llm.Usage{Model: "claude-haiku-5-5", InputTokens: 1000000, OutputTokens: 1000000, CacheReadTokens: 5, CacheWriteTokens: 6})
	u.add(llm.Usage{Model: "claude-haiku-5-5", InputTokens: 1})
	u.print(&b)
	want := "usage: model=claude-haiku-5-5 calls=2 in=1000001 out=1000000 cache_read=5 cache_write=6 est_usd=0.6000\n"
	if b.String() != want {
		t.Fatalf("got %q want %q", b.String(), want)
	}
}
