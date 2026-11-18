package main

import (
	"database/sql"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// The server links the inventory scanner (built-in local agent) and Grype. Both of the SQLite
// drivers register the database/sql name "sqlite" and a second registration panics at start, so
// modernc.org/sqlite must only be linked by the agent binary (cmd/holealign-agent/sqlite_driver.go).

func TestSingleSQLiteDriver(t *testing.T) {
	// Reaching this point means package initialisation (all driver registrations) did not panic.
	n := 0
	for _, d := range sql.Drivers() {
		if d == "sqlite" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("sql.Drivers() has %d \"sqlite\" entries: %v", n, sql.Drivers())
	}
	// and the driver is usable
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		t.Fatal(err)
	}
}

func goDeps(t *testing.T, pkg string) []string {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go tool not available")
	}
	cmd := exec.Command(goBin, "list", "-deps", pkg)
	out, err := cmd.Output()
	if err != nil {
		t.Skipf("go list failed: %v", err)
	}
	return strings.Fields(string(out))
}

func TestModerncSQLiteOnlyInAgentBinary(t *testing.T) {
	const modernc = "modernc.org/sqlite"
	if slices.Contains(goDeps(t, "github.com/DonSosiska/holealign/cmd/holealign-server"), modernc) {
		t.Fatalf("the server binary links %s: it would panic at start (driver \"sqlite\" registered twice)", modernc)
	}
	if !slices.Contains(goDeps(t, "github.com/DonSosiska/holealign/cmd/holealign-agent"), modernc) {
		t.Fatalf("the agent binary no longer links %s: Syft cannot read newer RPM databases", modernc)
	}
}
