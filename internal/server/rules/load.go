package rules

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/DonSosiska/panoptes/internal/model"
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
	rs, err := LoadFS(os.DirFS(dir), ".")
	if err != nil {
		return rs, fmt.Errorf("read rules dir: %w", err)
	}
	return rs, nil
}

// LoadFS is LoadDir over an fs.FS (used for the rules embedded in the binary).
func LoadFS(fsys fs.FS, dir string) ([]model.Rule, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		switch path.Ext(e.Name()) {
		case ".yaml", ".yml":
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	var out []model.Rule
	var errs []error
	for _, n := range names {
		data, err := fs.ReadFile(fsys, path.Join(dir, n))
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
