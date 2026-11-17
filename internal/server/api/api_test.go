package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/DonSosiska/panoptes/internal/model"
	"github.com/DonSosiska/panoptes/internal/server/core"
	"github.com/DonSosiska/panoptes/internal/server/store"
)

type recTrigger struct {
	mu  sync.Mutex
	ids []string
}

func (r *recTrigger) Trigger(id string) { r.mu.Lock(); r.ids = append(r.ids, id); r.mu.Unlock() }
func (r *recTrigger) count() int        { r.mu.Lock(); defer r.mu.Unlock(); return len(r.ids) }

type reqEval struct{ core.NoopEvaluator }

func (reqEval) FactRequests() []model.FactRequest {
	return []model.FactRequest{{Name: "file.match:x", Collector: "file.match", Params: map[string]string{"path": "/etc/x", "pattern": "a"}}}
}

type env struct {
	srv   *httptest.Server
	st    *store.SQLite
	trig  *recTrigger
	token string
}

func mid(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// setup disables the rate limits; tests of the limits use setupWith.
func setup(t *testing.T) *env {
	return setupWith(t, func(d *Deps) {
		d.InventoryInterval, d.CheckinInterval, d.EnrollPerMinute, d.BadAuthPerMinute = -1, -1, -1, -1
		d.InvalidInventoryPerMinute = 1000
	})
}

func setupWith(t *testing.T, mod func(*Deps)) *env {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	tok, hash, _ := store.NewSecret("pt_")
	if err := st.CreateEnrollToken(context.Background(), "test", hash); err != nil {
		t.Fatal(err)
	}
	trig := &recTrigger{}
	d := Deps{Store: st, Evaluator: reqEval{}, Pipeline: trig}
	if mod != nil {
		mod(&d)
	}
	srv := httptest.NewServer(NewMux(d))
	t.Cleanup(srv.Close)
	return &env{srv: srv, st: st, trig: trig, token: tok}
}

func (e *env) do(t *testing.T, method, path, key string, body any, hdr map[string]string) (*http.Response, []byte) {
	t.Helper()
	var rdr io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		rdr = bytes.NewReader(b)
	default:
		js, _ := json.Marshal(b)
		rdr = bytes.NewReader(js)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rdr)
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

func (e *env) enroll(t *testing.T, machine string) model.EnrollResponse {
	return e.enrollWith(t, machine, "")
}

func (e *env) enrollWith(t *testing.T, machine, prevKey string) model.EnrollResponse {
	t.Helper()
	resp, body := e.do(t, "POST", "/api/v1/enroll", prevKey, model.EnrollRequest{Token: e.token, Hostname: "web1", MachineID: mid(machine), Labels: []string{"prod"}}, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("enroll: %d %s", resp.StatusCode, body)
	}
	var er model.EnrollResponse
	_ = json.Unmarshal(body, &er)
	if !strings.HasPrefix(er.AgentKey, "pa_") || er.AgentID == "" {
		t.Fatalf("bad enroll response %+v", er)
	}
	return er
}

func gz(t *testing.T, b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

func TestHealthz(t *testing.T) {
	e := setup(t)
	resp, body := e.do(t, "GET", "/healthz", "", nil, nil)
	if resp.StatusCode != 200 || string(body) != "ok" {
		t.Fatalf("%d %q", resp.StatusCode, body)
	}
}

func TestFullFlow(t *testing.T) {
	e := setup(t)
	er := e.enroll(t, "machine-1")

	// check-in 1: full facts, no inventory yet
	ci := model.CheckinRequest{Hostname: "web1", Labels: []string{"prod", "web"}, OS: model.OSInfo{ID: "debian", VersionID: "12"},
		Facts: model.Facts{"os.id": "debian", "sshd.installed": true}, FactsComplete: true}
	resp, body := e.do(t, "POST", "/api/v1/checkin", er.AgentKey, ci, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("checkin: %d %s", resp.StatusCode, body)
	}
	var cr model.CheckinResponse
	_ = json.Unmarshal(body, &cr)
	if !cr.WantInventory || cr.WantFullFacts || len(cr.FactRequests) != 1 || cr.FactRequests[0].Name != "file.match:x" {
		t.Fatalf("checkin response: %+v", cr)
	}
	if e.trig.count() != 0 {
		t.Fatal("no pipeline run without inventory")
	}

	// inventory (gzip) -> 202 and pipeline trigger
	inv := model.InventoryPayload{Hash: "h1", Targets: []model.InventoryTarget{{Kind: model.TargetHost, Name: "host", SBOM: json.RawMessage(`{"bomFormat":"CycloneDX"}`)}}}
	js, _ := json.Marshal(inv)
	resp, body = e.do(t, "POST", "/api/v1/inventory", er.AgentKey, gz(t, js), map[string]string{"Content-Encoding": "gzip", "Content-Type": "application/json"})
	if resp.StatusCode != 202 {
		t.Fatalf("inventory: %d %s", resp.StatusCode, body)
	}
	if e.trig.count() != 1 {
		t.Fatalf("pipeline triggers: %d", e.trig.count())
	}
	targets, _ := e.st.ListTargets(context.Background(), er.AgentID)
	if len(targets) != 1 {
		t.Fatalf("targets: %+v", targets)
	}

	// check-in 2 with matching hash: no inventory wanted; facts unchanged -> no trigger
	ci.InventoryHash = "h1"
	_, body = e.do(t, "POST", "/api/v1/checkin", er.AgentKey, ci, nil)
	_ = json.Unmarshal(body, &cr)
	if cr.WantInventory {
		t.Fatal("inventory should not be wanted")
	}
	if e.trig.count() != 1 {
		t.Fatalf("unchanged facts must not trigger, count=%d", e.trig.count())
	}

	// check-in 3: diff with null delete and a new fact -> merged, trigger
	diff := []byte(`{"hostname":"web1","inventory_hash":"h1","facts":{"sshd.installed":null,"nginx.installed":false}}`)
	resp, body = e.do(t, "POST", "/api/v1/checkin", er.AgentKey, diff, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	h, _ := e.st.GetHost(context.Background(), er.AgentID)
	if _, ok := h.Facts["sshd.installed"]; ok || h.Facts["nginx.installed"] != false || h.Facts["os.id"] != "debian" {
		t.Fatalf("merge result: %v", h.Facts)
	}
	if e.trig.count() != 2 {
		t.Fatalf("fact change must trigger, count=%d", e.trig.count())
	}
	if h.InventoryHash != "h1" || h.LastCheckin.IsZero() || len(h.Labels) != 2 || h.OS.ID != "debian" {
		t.Fatalf("host: %+v", h)
	}

	// agent hash differs from stored -> wants inventory
	ci.InventoryHash = "other"
	_, body = e.do(t, "POST", "/api/v1/checkin", er.AgentKey, ci, nil)
	_ = json.Unmarshal(body, &cr)
	if !cr.WantInventory {
		t.Fatal("expected want_inventory for differing hash")
	}
}

func TestWantFullFactsOnFirstDiff(t *testing.T) {
	e := setup(t)
	er := e.enroll(t, "m")
	_, body := e.do(t, "POST", "/api/v1/checkin", er.AgentKey, []byte(`{"facts":{"a":1}}`), nil)
	var cr model.CheckinResponse
	_ = json.Unmarshal(body, &cr)
	if !cr.WantFullFacts {
		t.Fatalf("server without state must ask for full facts: %+v", cr)
	}
}

func TestReenrollReusesHostAndRotatesKey(t *testing.T) {
	e := setup(t)
	a := e.enroll(t, "same-machine")
	b := e.enrollWith(t, "same-machine", a.AgentKey)
	if a.AgentID != b.AgentID || a.AgentKey == b.AgentKey {
		t.Fatalf("%+v %+v", a, b)
	}
	if resp, _ := e.do(t, "POST", "/api/v1/checkin", a.AgentKey, model.CheckinRequest{}, nil); resp.StatusCode != 401 {
		t.Fatalf("old key still valid: %d", resp.StatusCode)
	}
	if resp, _ := e.do(t, "POST", "/api/v1/checkin", b.AgentKey, model.CheckinRequest{}, nil); resp.StatusCode != 200 {
		t.Fatalf("new key rejected: %d", resp.StatusCode)
	}
}

func TestAuthFailures(t *testing.T) {
	e := setup(t)
	resp, body := e.do(t, "POST", "/api/v1/enroll", "", model.EnrollRequest{Token: "pt_wrong", MachineID: mid("m")}, nil)
	if resp.StatusCode != 401 || !strings.Contains(string(body), `"error"`) {
		t.Fatalf("bad token: %d %s", resp.StatusCode, body)
	}
	if resp, _ = e.do(t, "POST", "/api/v1/enroll", "", model.EnrollRequest{MachineID: mid("m")}, nil); resp.StatusCode != 401 {
		t.Fatalf("empty token: %d", resp.StatusCode)
	}
	if resp, _ = e.do(t, "POST", "/api/v1/enroll", "", model.EnrollRequest{Token: e.token}, nil); resp.StatusCode != 400 {
		t.Fatalf("missing machine id: %d", resp.StatusCode)
	}
	for _, path := range []string{"/api/v1/checkin", "/api/v1/inventory"} {
		if resp, _ = e.do(t, "POST", path, "", []byte(`{}`), nil); resp.StatusCode != 401 {
			t.Fatalf("%s without key: %d", path, resp.StatusCode)
		}
		if resp, _ = e.do(t, "POST", path, "pa_bogus", []byte(`{}`), nil); resp.StatusCode != 401 {
			t.Fatalf("%s bad key: %d", path, resp.StatusCode)
		}
	}
	// revoked token cannot enroll
	if err := e.st.RevokeEnrollToken(context.Background(), "test"); err != nil {
		t.Fatal(err)
	}
	if resp, _ = e.do(t, "POST", "/api/v1/enroll", "", model.EnrollRequest{Token: e.token, MachineID: mid("m")}, nil); resp.StatusCode != 401 {
		t.Fatalf("revoked token: %d", resp.StatusCode)
	}
	// wrong method
	if resp, _ = e.do(t, "GET", "/api/v1/checkin", "", nil, nil); resp.StatusCode != 405 {
		t.Fatalf("GET checkin: %d", resp.StatusCode)
	}
}

func TestInventoryValidationAndLimits(t *testing.T) {
	e := setup(t)
	er := e.enroll(t, "m")
	gzh := map[string]string{"Content-Encoding": "gzip"}

	// not gzip although declared
	if resp, _ := e.do(t, "POST", "/api/v1/inventory", er.AgentKey, []byte(`{"hash":"x"}`), gzh); resp.StatusCode != 400 {
		t.Fatalf("bad gzip: %d", resp.StatusCode)
	}
	// unsupported encoding
	if resp, _ := e.do(t, "POST", "/api/v1/inventory", er.AgentKey, []byte(`{}`), map[string]string{"Content-Encoding": "br"}); resp.StatusCode != 415 {
		t.Fatalf("br: %d", resp.StatusCode)
	}
	// missing hash is a payload error
	if resp, body := e.do(t, "POST", "/api/v1/inventory", er.AgentKey, gz(t, []byte(`{"targets":[]}`)), gzh); resp.StatusCode != 400 {
		t.Fatalf("no hash: %d %s", resp.StatusCode, body)
	}
	// bad targets are skipped one by one (202 + list); all-not-CycloneDX is 415
	for js, want := range map[string]int{
		`{"hash":"h1","targets":[{"kind":"weird","name":"x","sbom":{"bomFormat":"CycloneDX"}}]}`: 202,
		`{"hash":"h2","targets":[{"kind":"host","name":"","sbom":{"bomFormat":"CycloneDX"}}]}`:   202,
		`{"hash":"h3","targets":[{"kind":"host","name":"host"}]}`:                                415,
		`{"hash":"h4","targets":[{"kind":"host","name":"host","sbom":{}}]}`:                      415,
	} {
		resp, body := e.do(t, "POST", "/api/v1/inventory", er.AgentKey, gz(t, []byte(js)), gzh)
		if resp.StatusCode != want || !strings.Contains(string(body), "skipped") {
			t.Fatalf("%s: %d %s", js, resp.StatusCode, body)
		}
	}
	// decompressed size above the cap -> 413 even though the compressed body is tiny
	var big bytes.Buffer
	big.WriteString(`{"hash":"h","targets":[],"pad":"`)
	chunk := bytes.Repeat([]byte("a"), 1<<20)
	for i := 0; i < 65; i++ {
		big.Write(chunk)
	}
	big.WriteString(`"}`)
	zipped := gz(t, big.Bytes())
	if len(zipped) > 1<<20 {
		t.Fatalf("test setup: compressed too large (%d)", len(zipped))
	}
	if resp, body := e.do(t, "POST", "/api/v1/inventory", er.AgentKey, zipped, gzh); resp.StatusCode != 413 {
		t.Fatalf("gzip bomb: %d %s", resp.StatusCode, body)
	}
	if e.trig.count() != 2 { // only the two accepted-with-skips uploads
		t.Fatal("rejected uploads must not trigger the pipeline")
	}
	// a body just under the cap is accepted (uncompressed, identity encoding)
	ok := model.InventoryPayload{Hash: "h", Targets: []model.InventoryTarget{{Kind: model.TargetHost, Name: "host", SBOM: cdxMin}}}
	js, _ := json.Marshal(ok)
	if resp, body := e.do(t, "POST", "/api/v1/inventory", er.AgentKey, js, nil); resp.StatusCode != 202 {
		t.Fatalf("identity body: %d %s", resp.StatusCode, body)
	}
}

func TestInvalidJSON(t *testing.T) {
	e := setup(t)
	er := e.enroll(t, "m")
	if resp, _ := e.do(t, "POST", "/api/v1/checkin", er.AgentKey, []byte(`{not json`), nil); resp.StatusCode != 400 {
		t.Fatalf("%d", resp.StatusCode)
	}
}
