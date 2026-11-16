package inventory

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"panoptes/internal/model"
)

func TestNormalizeSBOMDeterministic(t *testing.T) {
	a := `{"bomFormat":"CycloneDX","serialNumber":"urn:uuid:1","metadata":{"timestamp":"2026-01-01T00:00:00Z","tools":[1]},"components":[{"bom-ref":"b","name":"b"},{"bom-ref":"a","name":"a"}],"dependencies":[{"ref":"z"},{"ref":"y"}],"n":1.50}`
	b := `{"n":1.50,"components":[{"name":"a","bom-ref":"a"},{"name":"b","bom-ref":"b"}],"dependencies":[{"ref":"y"},{"ref":"z"}],"metadata":{"tools":[1],"timestamp":"2027-02-02T00:00:00Z"},"serialNumber":"urn:uuid:2","bomFormat":"CycloneDX"}`
	na, err := NormalizeSBOM([]byte(a))
	if err != nil {
		t.Fatal(err)
	}
	nb, _ := NormalizeSBOM([]byte(b))
	if string(na) != string(nb) {
		t.Fatalf("not deterministic:\n%s\n%s", na, nb)
	}
	if strings.Contains(string(na), "serialNumber") || strings.Contains(string(na), "timestamp") {
		t.Fatalf("volatile fields kept: %s", na)
	}
	if !json.Valid(na) || !strings.Contains(string(na), "1.50") {
		t.Fatalf("bad output: %s", na)
	}
	if _, err := NormalizeSBOM([]byte("nope")); err == nil {
		t.Fatal("want error")
	}
}

func TestComputeHashOrderIndependent(t *testing.T) {
	h := model.InventoryTarget{Kind: model.TargetHost, Name: "host", SBOM: json.RawMessage(`{"h":1}`)}
	i1 := model.InventoryTarget{Kind: model.TargetContainerImage, Name: "a:1", SBOM: json.RawMessage(`{"i":1}`)}
	i2 := model.InventoryTarget{Kind: model.TargetContainerImage, Name: "b:1", SBOM: json.RawMessage(`{"i":2}`)}
	x := []model.InventoryTarget{h, i2, i1}
	y := []model.InventoryTarget{i1, h, i2}
	hx, hy := ComputeHash(x), ComputeHash(y)
	if hx != hy || len(hx) != 64 {
		t.Fatalf("%s vs %s", hx, hy)
	}
	if x[0].Name != "a:1" || x[2].Name != "host" {
		t.Fatalf("not sorted: %v", x)
	}
	y[0].SBOM = json.RawMessage(`{"i":9}`)
	if ComputeHash(y) == hx {
		t.Fatal("hash should change with content")
	}
}

func TestExcludePatterns(t *testing.T) {
	got := excludePatterns([]string{"/proc", "/var/lib/docker/", "**/node_modules"})
	want := []string{"./proc", "./proc/**", "./var/lib/docker", "./var/lib/docker/**", "**/node_modules"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
}

func TestBuildImageRefs(t *testing.T) {
	imgs := []dockerImage{
		{ID: "sha256:b", RepoTags: []string{"nginx:1.25", "nginx:latest"}},
		{ID: "sha256:a", RepoTags: []string{"<none>:<none>"}},
	}
	cs := []dockerContainer{
		{Names: []string{"/web2"}, ImageID: "sha256:b"},
		{Names: []string{"/web1"}, ImageID: "sha256:b"},
		{Names: []string{"/ghost"}, ImageID: "sha256:zzz"},
	}
	refs := buildImageRefs(imgs, cs)
	if len(refs) != 2 || refs[0].Name != "nginx:1.25" || refs[1].Name != "sha256:a" {
		t.Fatalf("%+v", refs)
	}
	if !reflect.DeepEqual(refs[0].Containers, []string{"web1", "web2"}) {
		t.Fatalf("%+v", refs[0].Containers)
	}
}

func TestNewDockerClientMissingSocket(t *testing.T) {
	if newDockerClient("/nonexistent/docker.sock") != nil || newDockerClient("") != nil {
		t.Fatal("expected nil")
	}
}
