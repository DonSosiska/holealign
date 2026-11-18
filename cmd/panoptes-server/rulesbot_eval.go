package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/DonSosiska/panoptes/internal/server/llm"
	"github.com/DonSosiska/panoptes/internal/server/rulesbot"
)

const evalUsageLine = "usage: rules eval -rules <dir> -tests <dir> [-ids a,b] [-variants model[@effort],...] [-runs 3] [-max-attempts 2] [-concurrency 2] [-out report.json] [-provider p] [-base-url u] [-osv-url u] [-effort medium]"

// rulesEval drafts reference rules with several model variants and scores the drafts against the
// reference tests. It spends real money on the LLM provider. Failed drafts are results: the exit
// code is non-zero only for usage errors and when no LLM call could be made at all.
func rulesEval(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("eval", stderr)
	rulesDir := fs.String("rules", "", "directory with the reference rules")
	testsDir := fs.String("tests", "", "directory with the reference tests")
	ids := fs.String("ids", "", "comma-separated rule IDs (default: every reviewed rule that has tests)")
	variants := fs.String("variants", "", "comma-separated model[@effort] list, e.g. claude-sonnet-5-5@medium,claude-haiku-5-5@medium (default: the -model/PANOPTES_LLM_MODEL or claude-sonnet-5-5)")
	runs := fs.Int("runs", 3, "drafts per rule and variant")
	attempts := fs.Int("max-attempts", 2, "LLM attempts per draft, as in 'rules draft'")
	conc := fs.Int("concurrency", 2, "drafts in flight")
	out := fs.String("out", "", "write the JSON report to this file")
	provider := fs.String("provider", os.Getenv("PANOPTES_LLM_PROVIDER"), "anthropic | openai-compatible (env PANOPTES_LLM_PROVIDER)")
	model := fs.String("model", os.Getenv("PANOPTES_LLM_MODEL"), "model for a variant without one (env PANOPTES_LLM_MODEL)")
	baseURL := fs.String("base-url", os.Getenv("PANOPTES_LLM_BASE_URL"), "provider base URL (env PANOPTES_LLM_BASE_URL)")
	osv := fs.String("osv-url", rulesbot.DefaultOSVURL, "OSV API base URL (advisory source)")
	effort := fs.String("effort", defaultEffort(), "effort of a variant without @effort (env PANOPTES_LLM_EFFORT)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *rulesDir == "" || *testsDir == "" || *runs <= 0 || *attempts <= 0 || *conc <= 0 {
		return errors.New(evalUsageLine)
	}
	vs := *variants
	if vs == "" {
		m := *model
		if m == "" {
			m = "claude-sonnet-5-5"
		}
		vs = m
	}
	vlist, err := rulesbot.ParseVariants(vs, *effort)
	if err != nil {
		return fmt.Errorf("-variants: %w", err)
	}
	// Resolve the provider once (and fail early on a missing provider or key variable).
	base, err := botProviderConfig(*provider, vlist[0].Model, *baseURL, vlist[0].Effort)
	if err != nil {
		return err
	}
	rs, tests, err := rulesbot.LoadExisting(*rulesDir, *testsDir)
	if err != nil {
		return err
	}
	var idList []string
	for _, id := range strings.Split(*ids, ",") {
		if id = strings.TrimSpace(id); id != "" {
			idList = append(idList, id)
		}
	}
	ctx, stop := botContext()
	defer stop()
	osvSrc := llm.NewOSVSource()
	osvSrc.BaseURL = *osv
	rep, err := rulesbot.RunEval(ctx, rulesbot.EvalOptions{
		Rules: rs, Tests: tests, IDs: idList, Variants: vlist, Runs: *runs, MaxAttempts: *attempts, Concurrency: *conc,
		NewProvider: func(v rulesbot.Variant) (llm.Provider, error) {
			c := base
			c.Model, c.Effort = v.Model, v.Effort
			return newBotProvider(c)
		},
		Catalog: factCatalog(), Advisory: osvSrc, Logger: botLogger(stderr),
	})
	if rep != nil && len(rep.Results) > 0 {
		if *out != "" {
			b, merr := json.MarshalIndent(rep, "", "  ")
			if merr != nil {
				return merr
			}
			if werr := os.WriteFile(*out, append(b, '\n'), 0o644); werr != nil {
				return werr
			}
		}
		if _, werr := io.WriteString(stdout, rep.Markdown()); werr != nil {
			return werr
		}
	}
	return err
}
