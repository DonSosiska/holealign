package runner

import (
	"encoding/json"
	"reflect"

	"panoptes/internal/model"
)

// NormalizeFacts round-trips facts through JSON so values have exactly the types the
// server will see (float64, []any, map[string]any) and can be compared reliably.
func NormalizeFacts(f model.Facts) model.Facts {
	if f == nil {
		return model.Facts{}
	}
	data, err := json.Marshal(f)
	if err != nil {
		return model.Facts{}
	}
	var out model.Facts
	if err := json.Unmarshal(data, &out); err != nil || out == nil {
		return model.Facts{}
	}
	return out
}

// DiffFacts returns the facts that changed from prev to cur: new or changed keys with
// their new value, and keys that disappeared with a nil value (JSON null = delete).
// Both inputs must be normalized (see NormalizeFacts).
func DiffFacts(prev, cur model.Facts) model.Facts {
	diff := model.Facts{}
	for k, v := range cur {
		if pv, ok := prev[k]; !ok || !reflect.DeepEqual(pv, v) {
			diff[k] = v
		}
	}
	for k := range prev {
		if _, ok := cur[k]; !ok {
			diff[k] = nil
		}
	}
	return diff
}
