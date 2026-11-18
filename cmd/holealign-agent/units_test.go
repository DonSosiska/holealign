package main

import (
	"os"
	"strings"
	"testing"
)

func read(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile("../../" + rel)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// heredoc returns the body of `cat > "$VAR" <<'EOF'` in install.sh.
func heredoc(t *testing.T, script, variable string) string {
	t.Helper()
	marker := `cat > "$` + variable + `" <<'EOF'` + "\n"
	i := strings.Index(script, marker)
	if i < 0 {
		t.Fatalf("heredoc for %s not found in install.sh", variable)
	}
	rest := script[i+len(marker):]
	j := strings.Index(rest, "\nEOF\n")
	if j < 0 {
		t.Fatalf("heredoc for %s not terminated", variable)
	}
	return rest[:j+1]
}

// install.sh embeds the units; they must not drift from deploy/systemd.
func TestInstallScriptEmbedsTheUnitFiles(t *testing.T) {
	script := read(t, "deploy/install.sh")
	if got, want := heredoc(t, script, "UNIT_PATH"), read(t, "deploy/systemd/holealign-agent.service"); got != want {
		t.Error("install.sh agent unit differs from deploy/systemd/holealign-agent.service")
	}
	if got, want := heredoc(t, script, "COLLECTOR_UNIT_PATH"), read(t, "deploy/systemd/holealign-collector.service"); got != want {
		t.Error("install.sh collector unit differs from deploy/systemd/holealign-collector.service")
	}
}

func TestUnitIsolationDirectives(t *testing.T) {
	collector := read(t, "deploy/systemd/holealign-collector.service")
	for _, d := range []string{"PrivateNetwork=yes", "IPAddressDeny=any", "RestrictAddressFamilies=AF_UNIX\n",
		"RuntimeDirectory=holealign", "RuntimeDirectoryMode=0750", "Group=holealign", "UMask=0007", "-mode collector"} {
		if !strings.Contains(collector, d) {
			t.Errorf("collector unit lacks %q", d)
		}
	}
	sender := read(t, "deploy/systemd/holealign-agent.service")
	for _, d := range []string{"User=holealign", "Group=holealign", "Requires=holealign-collector.service", "CapabilityBoundingSet=\n",
		"NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes", "PrivateDevices=yes",
		"StateDirectory=holealign-agent", "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6", "SystemCallFilter=@system-service",
		"MemoryDenyWriteExecute=yes", "-mode sender"} {
		if !strings.Contains(sender, d) {
			t.Errorf("sender unit lacks %q", d)
		}
	}
	if strings.Contains(sender, "CAP_") && !strings.Contains(sender, "CapabilityBoundingSet=\n") {
		t.Error("sender must have an empty capability bounding set")
	}
}
