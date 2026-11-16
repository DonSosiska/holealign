package rules

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"

	"panoptes/internal/model"
)

// DBSource provides rules stored in the database (LLM drafts, user edits).
// Implemented by the store.
type DBSource interface {
	ListRules(ctx context.Context) ([]model.Rule, error)
}

// ParseRule decodes one YAML rule document strictly (unknown keys are errors).
func ParseRule(data []byte) (model.Rule, error) {
	var r model.Rule
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&r); err != nil {
		if errors.Is(err, io.EOF) {
			return r, errors.New("empty rule document")
		}
		return r, err
	}
	return r, nil
}

// LoadDir parses every *.yaml / *.yml file in dir (non-recursive), sorted by
// file name. Parse errors are returned with the file name; semantic validation
// is left to Validate / the Engine.
func LoadDir(dir string) ([]model.Rule, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read rules dir: %w", err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		switch filepath.Ext(e.Name()) {
		case ".yaml", ".yml":
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	var out []model.Rule
	var errs []error
	for _, n := range names {
		data, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", n, err))
			continue
		}
		r, err := ParseRule(data)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", n, err))
			continue
		}
		out = append(out, r)
	}
	return out, errors.Join(errs...)
}
