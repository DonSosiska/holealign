package main

import (
	"errors"
	"io/fs"
	"log/slog"
	"time"

	"github.com/DonSosiska/panoptes/internal/model"
	"github.com/DonSosiska/panoptes/internal/server/config"
	"github.com/DonSosiska/panoptes/internal/server/rules"
	shipped "github.com/DonSosiska/panoptes/rules"
)

// builtinRules returns the lowest rule layer: the rules embedded in the binary, plus the rules in
// rules_dir when that directory exists (a rules_dir rule with the same ID replaces the embedded
// one; other files are added). A missing rules_dir is normal and only logged at debug level.
func builtinRules(cfg *config.Config, log *slog.Logger) []model.Rule {
	embedded, err := rules.LoadFS(shipped.FS, ".")
	if err != nil {
		log.Error("embedded rules", "err", err) // a build defect, not a runtime condition
	}
	if cfg.RulesDir == "" {
		return embedded
	}
	dirRules, err := rules.LoadDir(cfg.RulesDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			log.Debug("rules_dir does not exist; using the embedded rules", "dir", cfg.RulesDir)
		} else {
			log.Warn("loading rules dir", "dir", cfg.RulesDir, "err", err)
		}
	}
	if len(dirRules) == 0 {
		return embedded
	}
	byID := map[string]int{}
	out := append([]model.Rule(nil), embedded...)
	for i, r := range out {
		byID[r.ID] = i
	}
	for _, r := range dirRules {
		if i, ok := byID[r.ID]; ok {
			out[i] = r
			continue
		}
		byID[r.ID] = len(out)
		out = append(out, r)
	}
	return out
}

// rulesFeedStaleAfter is the staleness limit for the health monitor, or 0 when the check does not
// apply (feed disabled, or no URL because bundles are imported by hand).
func rulesFeedStaleAfter(cfg *config.Config) time.Duration {
	f := cfg.Rules.Feed
	if !f.Enabled || f.URL == "" {
		return 0
	}
	return f.StaleAfter.Std()
}
