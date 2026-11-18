package web

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DonSosiska/holealign/internal/model"
	"github.com/DonSosiska/holealign/internal/server/config"
	"github.com/DonSosiska/holealign/internal/server/store"
)

// TestDevServer starts a throwaway UI with demo data when HOLEALIGN_WEB_DEV=<addr> is set,
// e.g. HOLEALIGN_WEB_DEV=127.0.0.1:8099 go test ./internal/server/web -run DevServer -timeout 1h
// Login: admin / admin-password.
func TestDevServer(t *testing.T) {
	addr := os.Getenv("HOLEALIGN_WEB_DEV")
	if addr == "" {
		t.Skip("set HOLEALIGN_WEB_DEV=<addr> to run")
	}
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "dev.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	hash, _ := store.HashPassword("admin-password")
	_ = st.CreateUser(ctx, "admin", hash)

	e := &env{t: t, st: st}
	h := e.seedHost("web-01", "prod", "web")
	e.seedFinding(h, "CVE-2024-6387", model.VerdictExploitable, true)
	e.seedFinding(h, "CVE-2024-0001", model.VerdictConditionsUnknown, false)
	e.seedFinding(h, "CVE-2024-0002", model.VerdictNotExploitable, false)
	_ = st.UpsertRule(ctx, model.Rule{ID: "CVE-2024-6387", Vulns: []string{"CVE-2024-6387"}, Title: "regreSSHion",
		Packages: []model.PackageSelector{{Name: "foo"}}, Facts: []string{"os.id"}, ExploitableIf: `facts["os.id"] == "debian"`,
		Explanation: "Demo rule.", Status: model.RuleDraft, Source: "llm:demo"}, time.Now())

	cfg := config.Default()
	cfg.Matrix.Homeserver = "https://matrix.example.org"
	cfg.PublicURL = "http://" + addr
	srv, err := New(Deps{Store: st, Config: &cfg, Logger: slog.Default()})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	srv.Mount(mux)
	t.Logf("dev server on http://%s (admin / admin-password)", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		t.Fatal(err)
	}
}
