package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"panoptes/internal/model"
	"panoptes/internal/server/store"
)

func (e *env) enrollReq(t *testing.T, token, machine, prevKey string) (int, model.EnrollResponse, string) {
	t.Helper()
	resp, body := e.do(t, "POST", "/api/v1/enroll", prevKey, model.EnrollRequest{Token: token, Hostname: "web1", MachineID: mid(machine), Labels: []string{"prod"}}, nil)
	var er model.EnrollResponse
	_ = json.Unmarshal(body, &er)
	return resp.StatusCode, er, string(body)
}

func TestHijackReenrollRefused(t *testing.T) {
	e := setup(t)
	victim := e.enroll(t, "victim")

	// attacker holds only the fleet-wide token (no Bearer key, or a wrong one)
	for _, key := range []string{"", "pa_wrong"} {
		code, _, body := e.enrollReq(t, e.token, "victim", key)
		if code != 409 || !strings.Contains(body, "previous key required") {
			t.Fatalf("hijack with key %q: %d %s", key, code, body)
		}
	}
	// the victim's key still works
	if resp, _ := e.do(t, "POST", "/api/v1/checkin", victim.AgentKey, model.CheckinRequest{}, nil); resp.StatusCode != 200 {
		t.Fatalf("victim key rotated out: %d", resp.StatusCode)
	}
	// legit re-enroll with the current key succeeds and rotates
	code, again, _ := e.enrollReq(t, e.token, "victim", victim.AgentKey)
	if code != 200 || again.AgentID != victim.AgentID || again.AgentKey == victim.AgentKey {
		t.Fatalf("legit re-enroll: %d %+v", code, again)
	}
	// admin allow-reenroll: works exactly once
	if err := e.st.SetReenrollAllowed(context.Background(), victim.AgentID, true); err != nil {
		t.Fatal(err)
	}
	if code, _, body := e.enrollReq(t, e.token, "victim", ""); code != 200 {
		t.Fatalf("allowed re-enroll: %d %s", code, body)
	}
	if code, _, _ := e.enrollReq(t, e.token, "victim", ""); code != 409 {
		t.Fatalf("flag must be cleared on use, got %d", code)
	}
}

func TestMachineIDValidation(t *testing.T) {
	e := setup(t)
	for _, m := range []string{"", "short", strings.Repeat("g", 40), strings.Repeat("A", 40), strings.Repeat("a", 65)} {
		resp, _ := e.do(t, "POST", "/api/v1/enroll", "", model.EnrollRequest{Token: e.token, MachineID: m}, nil)
		if resp.StatusCode != 400 {
			t.Errorf("machine_id %q: %d", m, resp.StatusCode)
		}
	}
}

func TestTokenExpiryMaxHostsAndLabels(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	mk := func(o store.EnrollTokenOpts) string {
		sec, h, _ := store.NewSecret("pt_")
		o.Hash = h
		if err := e.st.CreateEnrollTokenOpts(ctx, o); err != nil {
			t.Fatal(err)
		}
		return sec
	}
	expired := mk(store.EnrollTokenOpts{Name: "old", ExpiresAt: time.Now().Add(-time.Minute)})
	if code, _, _ := e.enrollReq(t, expired, "a", ""); code != 401 {
		t.Fatalf("expired token: %d", code)
	}
	one := mk(store.EnrollTokenOpts{Name: "one", MaxHosts: 1})
	if code, _, body := e.enrollReq(t, one, "h1", ""); code != 200 {
		t.Fatalf("first host: %d %s", code, body)
	}
	if code, _, _ := e.enrollReq(t, one, "h2", ""); code != 403 {
		t.Fatalf("exhausted token: %d", code)
	}

	labeled := mk(store.EnrollTokenOpts{Name: "prod-web", Labels: []string{"prod", "web"}})
	code, er, _ := e.enrollReq(t, labeled, "lab1", "")
	if code != 200 {
		t.Fatal(code)
	}
	h, _ := e.st.GetHost(ctx, er.AgentID)
	if strings.Join(h.Labels, ",") != "prod,web" {
		t.Fatalf("token labels not authoritative at enroll: %v", h.Labels)
	}
	// self-asserted check-in labels are ignored for such hosts
	if resp, body := e.do(t, "POST", "/api/v1/checkin", er.AgentKey, model.CheckinRequest{Labels: []string{"secops"}}, nil); resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	h, _ = e.st.GetHost(ctx, er.AgentID)
	if strings.Join(h.Labels, ",") != "prod,web" {
		t.Fatalf("check-in changed locked labels: %v", h.Labels)
	}
	// unlabelled tokens keep agent-asserted labels
	er2 := e.enroll(t, "free")
	e.do(t, "POST", "/api/v1/checkin", er2.AgentKey, model.CheckinRequest{Labels: []string{"db"}}, nil)
	if h, _ = e.st.GetHost(ctx, er2.AgentID); strings.Join(h.Labels, ",") != "db" {
		t.Fatalf("labels: %v", h.Labels)
	}
}

func TestBadEnrollDoesNotWrite(t *testing.T) {
	e := setup(t)
	last := func() time.Time {
		ts, _ := e.st.ListEnrollTokens(context.Background())
		return ts[0].LastUsed
	}
	if !last().IsZero() {
		t.Fatal("precondition")
	}
	e.do(t, "POST", "/api/v1/enroll", "", model.EnrollRequest{Token: "pt_bogus", MachineID: mid("x")}, nil)
	e.do(t, "POST", "/api/v1/enroll", "", model.EnrollRequest{Token: e.token, MachineID: "bad"}, nil) // invalid body
	if !last().IsZero() {
		t.Fatalf("last_used written by a rejected request: %v", last())
	}
	// a revoked token is not touched either
	_ = e.st.RevokeEnrollToken(context.Background(), "test")
	e.do(t, "POST", "/api/v1/enroll", "", model.EnrollRequest{Token: e.token, MachineID: mid("x")}, nil)
	if !last().IsZero() {
		t.Fatal("last_used written for revoked token")
	}
}

var cdxMin = json.RawMessage(`{"bomFormat":"CycloneDX"}`)

func sbomWithComponents(n int) json.RawMessage {
	var b strings.Builder
	b.WriteString(`{"bomFormat":"CycloneDX","components":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"name":"p%d"}`, i)
	}
	b.WriteString(`]}`)
	return json.RawMessage(b.String())
}

func TestComponentCap(t *testing.T) {
	e := setup(t)
	er := e.enroll(t, "m")
	post := func(hash string, n int) int {
		js, _ := json.Marshal(model.InventoryPayload{Hash: hash, Targets: []model.InventoryTarget{{Kind: model.TargetHost, Name: "host", SBOM: sbomWithComponents(n)}}})
		resp, _ := e.do(t, "POST", "/api/v1/inventory", er.AgentKey, js, nil)
		return resp.StatusCode
	}
	if c := post("ok", MaxComponents); c != 202 {
		t.Fatalf("at cap: %d", c)
	}
	// an oversized target is skipped (202 + skipped list), not a payload-wide 413
	if c := post("big", MaxComponents+1); c != 202 {
		t.Fatalf("over cap: %d", c)
	}
	// nested components count too
	nested := json.RawMessage(`{"bomFormat":"CycloneDX","components":[{"components":[` + strings.Repeat(`{"name":"x"},`, MaxComponents) + `{"name":"y"}]}]}`)
	js, _ := json.Marshal(model.InventoryPayload{Hash: "nest", Targets: []model.InventoryTarget{{Kind: model.TargetHost, Name: "host", SBOM: nested}}})
	resp, body := e.do(t, "POST", "/api/v1/inventory", er.AgentKey, js, nil)
	if resp.StatusCode != 202 || !strings.Contains(string(body), "more than 50000 components") {
		t.Fatalf("nested: %d %s", resp.StatusCode, body)
	}
}

func TestInventoryRateLimitAndDuplicateHash(t *testing.T) {
	now := time.Now()
	e := setupWith(t, func(d *Deps) {
		d.Now = func() time.Time { return now }
		d.CheckinInterval, d.EnrollPerMinute, d.BadAuthPerMinute = -1, -1, -1
	})
	er := e.enroll(t, "m")
	inv := func(hash string) (int, string) {
		js, _ := json.Marshal(model.InventoryPayload{Hash: hash, Targets: []model.InventoryTarget{{Kind: model.TargetHost, Name: "host", SBOM: cdxMin}}})
		resp, _ := e.do(t, "POST", "/api/v1/inventory", er.AgentKey, js, nil)
		return resp.StatusCode, resp.Header.Get("Retry-After")
	}
	// burst 3: three distinct inventories in a row are accepted
	for i := 1; i <= 3; i++ {
		if c, _ := inv(fmt.Sprintf("h%d", i)); c != 202 {
			t.Fatalf("distinct inventory %d: %d", i, c)
		}
	}
	if e.trig.count() != 3 {
		t.Fatalf("triggers=%d", e.trig.count())
	}
	// the 4th has no token left: 429 with Retry-After = time to the next token (5 min)
	if c, ra := inv("h4"); c != 429 || ra != "300" {
		t.Fatalf("4th inventory: %d Retry-After=%q", c, ra)
	}
	// one token refills after 5 min
	now = now.Add(5 * time.Minute)
	if c, _ := inv("h4"); c != 202 {
		t.Fatalf("after refill: %d", c)
	}
	if e.trig.count() != 4 {
		t.Fatalf("triggers=%d", e.trig.count())
	}
	// the bucket is empty again and the same hash repeated is still 202 without matching
	for i := 0; i < 10; i++ {
		if c, _ := inv("h4"); c != 202 {
			t.Fatalf("identical hash %d: %d", i, c)
		}
	}
	if e.trig.count() != 4 {
		t.Fatalf("identical hash re-ran matching: triggers=%d", e.trig.count())
	}
}

func TestIdenticalInventorySpendsNoToken(t *testing.T) {
	now := time.Now()
	e := setupWith(t, func(d *Deps) {
		d.Now = func() time.Time { return now }
		d.CheckinInterval, d.EnrollPerMinute, d.BadAuthPerMinute = -1, -1, -1
	})
	er := e.enroll(t, "m")
	inv := func(hash string) int {
		js, _ := json.Marshal(model.InventoryPayload{Hash: hash, Targets: []model.InventoryTarget{{Kind: model.TargetHost, Name: "host", SBOM: cdxMin}}})
		resp, _ := e.do(t, "POST", "/api/v1/inventory", er.AgentKey, js, nil)
		return resp.StatusCode
	}
	if c := inv("same"); c != 202 {
		t.Fatal(c)
	}
	for i := 0; i < 10; i++ {
		if c := inv("same"); c != 202 {
			t.Fatalf("duplicate %d: %d", i, c)
		}
	}
	// no token was spent by the duplicates: two more distinct inventories still fit the burst
	if c := inv("a"); c != 202 {
		t.Fatalf("a: %d", c)
	}
	if c := inv("b"); c != 202 {
		t.Fatalf("b: %d", c)
	}
	if c := inv("c"); c != 429 {
		t.Fatalf("c: %d", c)
	}
}

func TestCheckinRateLimit(t *testing.T) {
	now := time.Now()
	e := setupWith(t, func(d *Deps) {
		d.Now = func() time.Time { return now }
		d.InventoryInterval, d.EnrollPerMinute, d.BadAuthPerMinute = -1, -1, -1
	})
	er := e.enroll(t, "m")
	for i := 0; i < 3; i++ { // burst 3
		if resp, _ := e.do(t, "POST", "/api/v1/checkin", er.AgentKey, model.CheckinRequest{}, nil); resp.StatusCode != 200 {
			t.Fatalf("check-in %d: %d", i, resp.StatusCode)
		}
	}
	resp, _ := e.do(t, "POST", "/api/v1/checkin", er.AgentKey, model.CheckinRequest{}, nil)
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") != "20" {
		t.Fatalf("%d %q", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	now = now.Add(21 * time.Second)
	if resp, _ := e.do(t, "POST", "/api/v1/checkin", er.AgentKey, model.CheckinRequest{}, nil); resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
}

func TestFactsCaps(t *testing.T) {
	e := setup(t)
	er := e.enroll(t, "m")
	post := func(facts map[string]any) int {
		resp, _ := e.do(t, "POST", "/api/v1/checkin", er.AgentKey, map[string]any{"facts": facts, "facts_complete": true}, nil)
		return resp.StatusCode
	}
	many := map[string]any{}
	for i := 0; i < store.MaxFactKeys+1; i++ {
		many[fmt.Sprintf("k%d", i)] = 1
	}
	if c := post(many); c != 413 {
		t.Fatalf("too many keys: %d", c)
	}
	if c := post(map[string]any{"big": strings.Repeat("x", store.MaxFactValueByte+1)}); c != 413 {
		t.Fatalf("big value: %d", c)
	}
	total := map[string]any{}
	for i := 0; i < 20; i++ { // 20 x 60 KiB > 1 MiB
		total[fmt.Sprintf("v%d", i)] = strings.Repeat("y", 60<<10)
	}
	if c := post(total); c != 413 {
		t.Fatalf("total size: %d", c)
	}
	if c := post(map[string]any{"ok": "fine"}); c != 200 {
		t.Fatalf("normal facts: %d", c)
	}
}

func TestLabelAndHostnameValidation(t *testing.T) {
	e := setup(t)
	er := e.enroll(t, "m")
	bad := [][]string{{"UPPER"}, {"-lead"}, {"has space"}, {strings.Repeat("a", 65)}, make([]string, 33)}
	for i := range bad[4] {
		bad[4][i] = fmt.Sprintf("l%d", i)
	}
	for _, ls := range bad {
		if resp, _ := e.do(t, "POST", "/api/v1/checkin", er.AgentKey, model.CheckinRequest{Labels: ls}, nil); resp.StatusCode != 400 {
			t.Errorf("labels %v: %d", ls, resp.StatusCode)
		}
		if resp, _ := e.do(t, "POST", "/api/v1/enroll", "", model.EnrollRequest{Token: e.token, MachineID: mid("z"), Labels: ls}, nil); resp.StatusCode != 400 {
			t.Errorf("enroll labels %v: %d", ls, resp.StatusCode)
		}
	}
	long := "a\x1b[2J\nb" + strings.Repeat("h", 400)
	if resp, _ := e.do(t, "POST", "/api/v1/checkin", er.AgentKey, model.CheckinRequest{Hostname: long}, nil); resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	h, _ := e.st.GetHost(context.Background(), er.AgentID)
	if len(h.Hostname) > 253 || strings.ContainsAny(h.Hostname, "\x1b\n") || !strings.HasPrefix(h.Hostname, "a[2Jbhh") {
		t.Fatalf("hostname not sanitised: %q", h.Hostname)
	}
}

func TestPerIPLimiters(t *testing.T) {
	now := time.Now()
	e := setupWith(t, func(d *Deps) {
		d.Now = func() time.Time { return now }
		d.InventoryInterval, d.CheckinInterval = -1, -1
	})
	good := e.enroll(t, "m")
	// enroll: 10/min burst (one used above)
	got429 := false
	for i := 0; i < 12; i++ {
		resp, _ := e.do(t, "POST", "/api/v1/enroll", "", model.EnrollRequest{Token: "pt_bogus", MachineID: mid("x")}, nil)
		if resp.StatusCode == 429 {
			got429 = true
		}
	}
	if !got429 {
		t.Fatal("enroll never throttled")
	}
	now = now.Add(2 * time.Minute)
	// failed bearer auth: 30/min then 429; a valid key is never throttled
	n429 := 0
	for i := 0; i < 40; i++ {
		resp, _ := e.do(t, "POST", "/api/v1/checkin", "pa_bogus", []byte(`{}`), nil)
		if resp.StatusCode == 429 {
			n429++
		}
	}
	if n429 == 0 || n429 > 12 {
		t.Fatalf("429 count=%d", n429)
	}
	if resp, _ := e.do(t, "POST", "/api/v1/checkin", good.AgentKey, model.CheckinRequest{}, nil); resp.StatusCode != 200 {
		t.Fatalf("valid key throttled: %d", resp.StatusCode)
	}
}
