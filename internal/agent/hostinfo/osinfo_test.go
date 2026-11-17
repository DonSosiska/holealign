package hostinfo

import (
	"regexp"
	"testing"
)

func TestParseOSRelease(t *testing.T) {
	m := parseOSRelease([]byte("# c\nID=debian\nVERSION_ID=\"12\"\nPRETTY_NAME='Debian GNU/Linux 12 (bookworm)'\n"))
	if m["ID"] != "debian" || m["VERSION_ID"] != "12" || m["PRETTY_NAME"] != "Debian GNU/Linux 12 (bookworm)" {
		t.Fatalf("%v", m)
	}
}

func TestMachineIDHashed(t *testing.T) {
	got := hashMachineID("abc123")
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(got) {
		t.Fatalf("hash = %q", got)
	}
	if got == "abc123" || got != hashMachineID("abc123") || got == hashMachineID("abc124") {
		t.Error("hash must be deterministic and input dependent")
	}
	if id := MachineID(); !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(id) {
		t.Errorf("MachineID() = %q", id)
	}
}
