package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DonSosiska/holealign/internal/server/config"
	"github.com/DonSosiska/holealign/internal/server/rules"
)

func TestBuiltinRulesEmbeddedAndOverride(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.Default()

	// no rules_dir on disk: the 8 embedded rules are still there
	cfg.RulesDir = filepath.Join(t.TempDir(), "missing")
	rs := builtinRules(&cfg, log)
	if len(rs) < 8 {
		t.Fatalf("embedded rules: %d", len(rs))
	}
	e := rules.New(rs, nil)
	if p := e.Problems(); len(p) != 0 {
		t.Fatal(p)
	}
	for _, r := range e.Rules() {
		if e.Sources()[r.ID] != "builtin" {
			t.Fatalf("%s source %q", r.ID, e.Sources()[r.ID])
		}
	}

	// rules_dir overrides by id and may add rules
	dir := t.TempDir()
	src, err := os.ReadFile(filepath.Join(repoRules, "CVE-2024-4577.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	over := strings.Replace(string(src), `title: "PHP-CGI`, `title: "OVERRIDDEN PHP-CGI`, 1)
	extra := strings.Replace(string(src), "id: CVE-2024-4577", "id: LOCAL-1", 1)
	for n, c := range map[string]string{"a.yaml": over, "b.yaml": extra} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg.RulesDir = dir
	rs2 := builtinRules(&cfg, log)
	if len(rs2) != len(rs)+1 {
		t.Fatalf("got %d rules, want %d", len(rs2), len(rs)+1)
	}
	found := false
	for _, r := range rs2 {
		if r.ID == "CVE-2024-4577" {
			found = strings.HasPrefix(r.Title, "OVERRIDDEN")
		}
	}
	if !found {
		t.Fatal("rules_dir rule did not replace the embedded one")
	}
}
