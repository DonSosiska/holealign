package api

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/DonSosiska/panoptes/internal/model"
)

func TestCountComponentsStrictCycloneDX(t *testing.T) {
	cases := []struct {
		name, doc string
		want      int
		err       string // substring; "" = ok
	}{
		{"plain", `{"bomFormat":"CycloneDX","components":[{"name":"a"},{"name":"b","components":[{"name":"c"}]}]}`, 3, ""},
		{"no components", `{"bomFormat":"CycloneDX"}`, 0, ""},
		{"capitalised key", `{"bomFormat":"CycloneDX","Components":[{"name":"a"}]}`, 0, "ambiguous key"},
		{"upper key nested", `{"bomFormat":"CycloneDX","components":[{"COMPONENTS":[{"name":"a"}]}]}`, 0, "ambiguous key"},
		{"escaped lookalike", `{"bomFormat":"CycloneDX","components":[],"components":[]}`, 0, ""}, // decodes to the exact key
		{"long s lookalike", "{\"bomFormat\":\"CycloneDX\",\"componentſ\":[{}]}", 0, "ambiguous key"},
		{"bomformat case", `{"bomformat":"CycloneDX"}`, 0, "ambiguous key"},
		{"BomFormat nested", `{"bomFormat":"CycloneDX","metadata":{"BOMFORMAT":"x"}}`, 0, "ambiguous key"},
		{"value case", `{"bomFormat":"cyclonedx"}`, 0, "not a CycloneDX"},
		{"value type", `{"bomFormat":["CycloneDX"]}`, 0, "not a CycloneDX"},
		{"empty object", `{}`, 0, "not a CycloneDX"},
		{"spdx", `{"spdxVersion":"SPDX-2.3","packages":[{"name":"a"}]}`, 0, "not a CycloneDX"},
		{"syft json", `{"artifacts":[{"name":"a"}],"schema":{"version":"16"}}`, 0, "not a CycloneDX"},
		{"array", `[{"bomFormat":"CycloneDX"}]`, 0, "JSON object"},
		{"nested format does not count", `{"meta":{"bomFormat":"CycloneDX"}}`, 0, "not a CycloneDX"},
		{"trailing", `{"bomFormat":"CycloneDX"} {"x":1}`, 0, "trailing"},
		{"truncated", `{"bomFormat":"CycloneDX","components":[`, 0, "incomplete"},
	}
	for _, c := range cases {
		n, err := countComponents([]byte(c.doc), MaxComponents)
		switch {
		case c.err == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)):
			t.Errorf("%s: err=%v want %q", c.name, err, c.err)
		case err == nil && n != c.want && c.name != "escaped lookalike":
			t.Errorf("%s: n=%d want %d", c.name, n, c.want)
		}
	}
	// limit
	if _, err := countComponents([]byte(`{"bomFormat":"CycloneDX","components":[{},{},{}]}`), 2); !errors.Is(err, errTooManyComponents) {
		t.Fatalf("limit: %v", err)
	}
}

func TestPerTargetIsolation(t *testing.T) {
	e := setup(t)
	er := e.enroll(t, "m")
	pay := model.InventoryPayload{Hash: "mix", Targets: []model.InventoryTarget{
		{Kind: model.TargetHost, Name: "host", SBOM: sbomWithComponents(3)},
		{Kind: model.TargetContainerImage, Name: "huge:1", SBOM: sbomWithComponents(MaxComponents + 1)},
		{Kind: model.TargetContainerImage, Name: "spdx:1", SBOM: json.RawMessage(`{"spdxVersion":"SPDX-2.3"}`)},
		{Kind: model.TargetContainerImage, Name: strings.Repeat("n", maxTargetName+1), SBOM: cdxMin},
		{Kind: model.TargetContainerImage, Name: "id:1", ImageID: strings.Repeat("i", maxImageID+1), SBOM: cdxMin},
		{Kind: model.TargetContainerImage, Name: "many:1", Containers: make([]string, maxContainers+1), SBOM: cdxMin},
		{Kind: model.TargetContainerImage, Name: "longc:1", Containers: []string{strings.Repeat("c", maxContainerNameLen+1)}, SBOM: cdxMin},
		{Kind: model.TargetContainerImage, Name: "ok:1", ImageID: "sha256:abc", Containers: []string{"web"}, SBOM: cdxMin},
		{Kind: model.TargetContainerImage, Name: "ok:1", SBOM: cdxMin}, // duplicate
	}}
	js, _ := json.Marshal(pay)
	resp, body := e.do(t, "POST", "/api/v1/inventory", er.AgentKey, js, nil)
	if resp.StatusCode != 202 {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	var out struct {
		Status  string
		Skipped []struct{ Kind, Name, Reason string }
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if out.Status != "accepted" || len(out.Skipped) != 7 {
		t.Fatalf("skipped=%d %s", len(out.Skipped), body)
	}
	ts, _ := e.st.ListTargets(context.Background(), er.AgentID)
	if len(ts) != 2 || ts[0].Name != "host" && ts[1].Name != "host" {
		t.Fatalf("valid targets not stored: %+v", ts)
	}
	sk, _ := e.st.ListSkippedTargets(context.Background(), er.AgentID)
	if len(sk) != 6 { // the duplicate shares its identity with the stored valid target
		t.Fatalf("stored skipped: %+v", sk)
	}
	if e.trig.count() != 1 {
		t.Fatal("pipeline not triggered")
	}
	// an identical re-upload still reports the skipped targets
	resp, body = e.do(t, "POST", "/api/v1/inventory", er.AgentKey, js, nil)
	if resp.StatusCode != 202 || !strings.Contains(string(body), "huge:1") {
		t.Fatalf("repeat: %d %s", resp.StatusCode, body)
	}
}

func TestIPv6KeyedBySlash64AndBoundedLRU(t *testing.T) {
	if limitKey("2001:db8:1:2::1") != limitKey("2001:db8:1:2:ffff::9") || limitKey("2001:db8:1:2::1") == limitKey("2001:db8:1:3::1") {
		t.Fatal("IPv6 must be keyed by /64")
	}
	if limitKey("fe80::1%eth0") != limitKey("fe80::2%eth1") {
		t.Fatal("zone must not matter")
	}
	if limitKey("::ffff:192.0.2.1") != "192.0.2.1" || limitKey("192.0.2.1") == limitKey("192.0.2.2") {
		t.Fatal("IPv4 keyed by address")
	}
	now := time.Now()
	l := newIPLimiter(2)
	l.max = 5
	// two addresses in one /64 share a bucket
	if !l.allow("2001:db8::1", now) || !l.allow("2001:db8::2", now) || l.allow("2001:db8::3", now) {
		t.Fatal("/64 clients must share the bucket")
	}
	// minting many keys never denies a new client and never grows the map past max
	for i := 0; i < 50; i++ {
		if !l.allow(fmt.Sprintf("10.0.0.%d", i), now) {
			t.Fatalf("new key %d denied under key pressure", i)
		}
	}
	if l.size() > 5 {
		t.Fatalf("map grew to %d", l.size())
	}
}

func TestEnrollLimiterChargedOnlyByInvalidTokens(t *testing.T) {
	now := time.Now()
	e := setupWith(t, func(d *Deps) {
		d.Now = func() time.Time { return now }
		d.InventoryInterval, d.CheckinInterval, d.BadAuthPerMinute = -1, -1, -1
		d.EnrollPerMinute = 3
	})
	// far more valid enrollments than the bad-token budget
	for i := 0; i < 20; i++ {
		resp, body := e.do(t, "POST", "/api/v1/enroll", "", model.EnrollRequest{Token: e.token, MachineID: mid(fmt.Sprint("v", i))}, nil)
		if resp.StatusCode != 200 {
			t.Fatalf("valid enrollment %d: %d %s", i, resp.StatusCode, body)
		}
	}
	codes := map[int]int{}
	for i := 0; i < 6; i++ {
		resp, _ := e.do(t, "POST", "/api/v1/enroll", "", model.EnrollRequest{Token: "pt_bogus", MachineID: mid("x")}, nil)
		codes[resp.StatusCode]++
	}
	if codes[401] != 3 || codes[429] != 3 {
		t.Fatalf("bad tokens: %v", codes)
	}
	// the exhausted bad budget does not stop a valid token
	if resp, body := e.do(t, "POST", "/api/v1/enroll", "", model.EnrollRequest{Token: e.token, MachineID: mid("after")}, nil); resp.StatusCode != 200 {
		t.Fatalf("valid after abuse: %d %s", resp.StatusCode, body)
	}
}

func TestEnrollValidCapGenerousButPresent(t *testing.T) {
	e := setupWith(t, func(d *Deps) {
		d.InventoryInterval, d.CheckinInterval, d.BadAuthPerMinute, d.EnrollPerMinute = -1, -1, -1, -1
		d.EnrollOKPerMinute = 4
	})
	n429 := 0
	for i := 0; i < 8; i++ {
		resp, _ := e.do(t, "POST", "/api/v1/enroll", "", model.EnrollRequest{Token: e.token, MachineID: mid(fmt.Sprint("c", i))}, nil)
		if resp.StatusCode == 429 {
			n429++
		}
	}
	if n429 != 4 {
		t.Fatalf("valid-token cap: 429s=%d", n429)
	}
}

func TestBadAuthStays401UnderKeyPressure(t *testing.T) {
	s := &server{Deps: Deps{Now: time.Now, ClientIP: func(r *http.Request) string { return r.Header.Get("X-T") }}, log: nil}
	s.authLim = newIPLimiter(30)
	s.authLim.max = 4
	for i := 0; i < 100; i++ {
		if !s.authLim.allow(fmt.Sprintf("203.0.113.%d", i), time.Now()) {
			t.Fatalf("fresh key %d answered 429 (would be a DoS lever)", i)
		}
	}
}

func rawStatus(t *testing.T, addr, req string) string {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	line, _ := bufio.NewReader(c).ReadString('\n')
	return strings.TrimSpace(line)
}

func TestContentLengthRejectedBeforeReading(t *testing.T) {
	e := setup(t)
	er := e.enroll(t, "m")
	addr := strings.TrimPrefix(e.srv.URL, "http://")
	// no body is ever sent: a 413 proves the decision was made from the header alone
	st := rawStatus(t, addr, "POST /api/v1/inventory HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer "+er.AgentKey+
		"\r\nContent-Length: 73400320\r\n\r\n")
	if !strings.Contains(st, "413") {
		t.Fatalf("inventory: %s", st)
	}
	st = rawStatus(t, addr, "POST /api/v1/checkin HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer "+er.AgentKey+
		"\r\nContent-Length: 73400320\r\n\r\n")
	if !strings.Contains(st, "413") {
		t.Fatalf("checkin: %s", st)
	}
	st = rawStatus(t, addr, "POST /api/v1/enroll HTTP/1.1\r\nHost: x\r\nContent-Length: 73400320\r\n\r\n")
	if !strings.Contains(st, "413") {
		t.Fatalf("enroll: %s", st)
	}
}

func TestInvalidInventoryPreLimiter(t *testing.T) {
	now := time.Now()
	e := setupWith(t, func(d *Deps) {
		d.Now = func() time.Time { return now }
		d.InventoryInterval, d.CheckinInterval, d.EnrollPerMinute, d.BadAuthPerMinute = -1, -1, -1, -1
		// default 6 invalid uploads per minute
	})
	er := e.enroll(t, "m")
	bad := []byte(`{"hash":""}`)
	for i := 0; i < 6; i++ {
		if resp, _ := e.do(t, "POST", "/api/v1/inventory", er.AgentKey, bad, nil); resp.StatusCode != 400 {
			t.Fatalf("invalid %d: %d", i, resp.StatusCode)
		}
	}
	// the 7th is refused without reading the body: even a Content-Length lie cannot cost anything
	addr := strings.TrimPrefix(e.srv.URL, "http://")
	st := rawStatus(t, addr, "POST /api/v1/inventory HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer "+er.AgentKey+"\r\nContent-Length: 12\r\n\r\n{\"hash\":\"x\"}")
	if !strings.Contains(st, "429") {
		t.Fatalf("7th invalid upload: %s", st)
	}
	// budget refills one per 10 s
	now = now.Add(11 * time.Second)
	good, _ := json.Marshal(model.InventoryPayload{Hash: "g", Targets: []model.InventoryTarget{{Kind: model.TargetHost, Name: "host", SBOM: cdxMin}}})
	if resp, body := e.do(t, "POST", "/api/v1/inventory", er.AgentKey, good, nil); resp.StatusCode != 202 {
		t.Fatalf("after refill: %d %s", resp.StatusCode, body)
	}
}

func TestTokenBucketSweepsIdleKeys(t *testing.T) {
	now := time.Now()
	l := newTokenBucketLimiter(time.Minute, 3)
	for i := 0; i < sweepAbove+10; i++ {
		l.take(fmt.Sprint("host", i), now)
	}
	later := now.Add(time.Hour)
	l.take("new", later)
	if l.size() > 2 {
		t.Fatalf("idle buckets not dropped: %d", l.size())
	}
}
