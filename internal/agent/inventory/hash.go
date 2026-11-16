package inventory

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"panoptes/internal/model"
)

// NormalizeSBOM removes the fields Syft fills with random or time-dependent values
// (CycloneDX serialNumber and metadata.timestamp) and re-encodes the document with
// sorted object keys and sorted components/dependencies, so the same package set
// always produces the same bytes.
func NormalizeSBOM(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode sbom: %w", err)
	}
	delete(doc, "serialNumber")
	if md, ok := doc["metadata"].(map[string]any); ok {
		delete(md, "timestamp")
	}
	sortByKey(doc["components"], "bom-ref")
	sortByKey(doc["dependencies"], "ref")
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func sortByKey(v any, key string) {
	list, ok := v.([]any)
	if !ok {
		return
	}
	str := func(x any) string {
		m, _ := x.(map[string]any)
		s, _ := m[key].(string)
		return s
	}
	sort.SliceStable(list, func(i, j int) bool { return str(list[i]) < str(list[j]) })
}

// SortTargets orders targets deterministically by kind, then name.
func SortTargets(targets []model.InventoryTarget) {
	sort.SliceStable(targets, func(i, j int) bool {
		if targets[i].Kind != targets[j].Kind {
			return targets[i].Kind < targets[j].Kind
		}
		return targets[i].Name < targets[j].Name
	})
}

// ComputeHash sorts targets (in place) and returns the sha256 hex over the concatenated SBOM bytes.
func ComputeHash(targets []model.InventoryTarget) string {
	SortTargets(targets)
	h := sha256.New()
	for _, t := range targets {
		h.Write(t.SBOM)
	}
	return hex.EncodeToString(h.Sum(nil))
}
