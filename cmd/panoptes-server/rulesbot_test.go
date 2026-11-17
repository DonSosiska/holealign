package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DonSosiska/panoptes/internal/server/config"
	"github.com/DonSosiska/panoptes/internal/server/llm"
)

type cliProv struct{ reply string }

func (p cliProv) Name() string                                             { return "fake:m" }
func (p cliProv) Complete(context.Context, string, string) (string, error) { return p.reply, nil }

const cliCand = `{"vuln":"CVE-2099-0100","aliases":[],"package":"openssh","binary_packages":["openssh-server"],"type":"deb","ecosystem":"Debian:12","severity":"High","cvss":8.1,"epss":0.2,"kev":false,"published":"2099-01-01T00:00:00Z"}`

const cliReply = `{"rule":{"title":"t","facts":["sshd.config"],"exploitable_if":"facts[\"sshd.config\"][?\"permitrootlogin\"].orValue(\"yes\") != \"no\"","explanation":"e","fix":{"upgrade":"u"}},
"tests":[{"name":"on","finding":{"package":"openssh-server"},"facts":{"sshd.config":{"permitrootlogin":"yes"}},"want":"exploitable"},
{"name":"off","finding":{"package":"openssh-server"},"facts":{"sshd.config":{"permitrootlogin":"no"}},"want":"affected_not_exploitable"}]}`

func TestRulesDraftCLI(t *testing.T) {
	t.Setenv("PANOPTES_CONFIG", "")
	for _, e := range []string{"PANOPTES_LLM_PROVIDER", "PANOPTES_LLM_MODEL", "PANOPTES_LLM_BASE_URL", "PANOPTES_LLM_API_KEY", "ANTHROPIC_API_KEY"} {
		t.Setenv(e, "")
	}
	osv := httptest.NewServer(http.NotFoundHandler()) // no advisory: drafting from candidate data
	defer osv.Close()
	old := newBotProvider
	defer func() { newBotProvider = old }()
	var got config.LLM
	prov := cliProv{cliReply}
	newBotProvider = func(c config.LLM) (llm.Provider, error) { got = c; return prov, nil }

	dir := t.TempDir()
	args := []string{"rules", "draft", "-candidate", cliCand, "-rules", repoRules, "-tests", repoTests,
		"-out-rules", filepath.Join(dir, "r"), "-out-tests", filepath.Join(dir, "t"), "-provider", "openai-compatible",
		"-model", "m", "-base-url", "http://x", "-osv-url", osv.URL}
	code, out, errOut := runCLI(t, "", args...)
	if code != 0 || !strings.Contains(out, "## Rule for CVE-2099-0100") || got.Model != "m" || got.Provider != "openai-compatible" {
		t.Fatalf("draft: %d %q %q %+v", code, out, errOut, got)
	}
	for _, p := range []string{"r/CVE-2099-0100-openssh.yaml", "t/CVE-2099-0100-openssh.yaml"} {
		if _, err := os.Stat(filepath.Join(dir, p)); err != nil {
			t.Fatal(err)
		}
	}
	// the same ID again: the second run writes into a directory that already has it
	if code, _, _ := runCLI(t, "", args...); code != exitIDExists {
		t.Fatalf("collision exit code %d", code)
	}
	// invalid draft: exit 2, nothing written
	prov.reply = `{"rule":{"title":"t"},"tests":[]}`
	newBotProvider = func(config.LLM) (llm.Provider, error) { return prov, nil }
	dir2 := t.TempDir()
	bad := append([]string{}, args...)
	for i, a := range bad {
		if a == filepath.Join(dir, "r") {
			bad[i] = filepath.Join(dir2, "r")
		}
		if a == filepath.Join(dir, "t") {
			bad[i] = filepath.Join(dir2, "t")
		}
	}
	code, _, errOut = runCLI(t, "", bad...)
	if code != exitDraftFailed || !strings.Contains(errOut, "no valid rule") {
		t.Fatalf("bad draft: %d %q", code, errOut)
	}
	if ents, _ := os.ReadDir(dir2); len(ents) != 0 {
		t.Fatalf("files written on failure: %v", ents)
	}
	// usage / no provider
	if code, _, _ := runCLI(t, "", "rules", "draft"); code != 1 {
		t.Fatalf("usage exit %d", code)
	}
	if code, _, errOut := runCLI(t, "", "rules", "draft", "-candidate", cliCand, "-rules", repoRules, "-tests", repoTests); code != 1 || !strings.Contains(errOut, "no LLM provider") {
		t.Fatalf("no provider: %d %q", code, errOut)
	}
}

func TestRulesCandidatesCLI(t *testing.T) {
	t.Setenv("PANOPTES_CONFIG", "")
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"CVE-2099-0200","modified":"2099-01-10T00:00:00Z"}]}]}`))
	})
	mux.HandleFunc("/v1/vulns/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"CVE-2099-0200","published":"2099-01-01T00:00:00Z","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}`))
	})
	mux.HandleFunc("/epss", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"cve":"CVE-2099-0200","epss":"0.25"}]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	dir := t.TempDir()
	kev := filepath.Join(dir, "kev.json")
	pk := filepath.Join(dir, "pkgs.txt")
	_ = os.WriteFile(kev, []byte(`{"vulnerabilities":[]}`), 0o644)
	_ = os.WriteFile(pk, []byte("# test\nopenssh\n"), 0o644)
	outF := filepath.Join(dir, "c.json")
	code, _, errOut := runCLI(t, "", "rules", "candidates", "-packages", pk, "-rules", repoRules, "-kev", kev, "-epss", srv.URL+"/epss?cve=",
		"-osv-url", srv.URL, "-ecosystems", " Debian:12, ,", "-since", "100000d", "-max", "5", "-out", outF)
	if code != 0 {
		t.Fatalf("%d %q", code, errOut)
	}
	var cs []map[string]any
	b, _ := os.ReadFile(outF)
	if err := json.Unmarshal(b, &cs); err != nil || len(cs) != 1 || cs[0]["vuln"] != "CVE-2099-0200" || cs[0]["epss"] != 0.25 || cs[0]["severity"] != "Critical" {
		t.Fatalf("%s %v", b, err)
	}
}
