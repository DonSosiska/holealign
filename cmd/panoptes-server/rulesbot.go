package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/DonSosiska/panoptes/internal/server/config"
	"github.com/DonSosiska/panoptes/internal/server/llm"
	"github.com/DonSosiska/panoptes/internal/server/rulesbot"
)

// Exit codes of "rules draft" (1 is any other error, 0 success).
const (
	exitDraftFailed = 2 // no valid rule after the attempts, or the model refused; nothing written
	exitIDExists    = 3 // a rule with the generated ID already exists; nothing written
)

// codedError carries a process exit code out of a rules subcommand.
type codedError struct {
	code int
	err  error
}

func (e *codedError) Error() string { return e.err.Error() }
func (e *codedError) Unwrap() error { return e.err }

// newBotProvider builds the LLM provider of "rules draft" (replaced in tests).
var newBotProvider = llm.NewProvider

func botContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func botLogger(stderr io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

func rulesCandidates(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("candidates", stderr)
	rulesDir := fs.String("rules", "", "directory with the existing rules (a CVE they already cover is skipped)")
	pkgFile := fs.String("packages", "", "file with source package names, one per line, # comments")
	ecos := fs.String("ecosystems", strings.Join(rulesbot.DefaultEcosystems, ","), "comma-separated OSV ecosystem names (Debian and Alpine use the bulk export; Ubuntu:* and Red Hat:* query package by package and are slower)")
	kev := fs.String("kev", rulesbot.DefaultKEVURL, "CISA KEV JSON, URL or file")
	epss := fs.String("epss", rulesbot.DefaultEPSSURL, "FIRST EPSS API URL; the CVE list is appended")
	since := fs.String("since", "30d", "a vulnerability published within this window is relevant (unfixed ones and recent KEV entries count regardless)")
	kevMax := fs.String("kev-max-age", "1095d", "a KEV vulnerability published within this age is relevant (unfixed ones always are)")
	cache := fs.String("cache", "", "directory for the downloaded OSV bulk exports (default $XDG_CACHE_HOME/panoptes-rules, else the user cache dir, else a temporary directory)")
	bulk := fs.String("bulk-url", rulesbot.DefaultBulkURL, "base URL of the OSV bulk exports (<base>/<Ecosystem>/all.zip)")
	max := fs.Int("max", rulesbot.DefaultMax, "maximum number of candidates")
	out := fs.String("out", "", "write the JSON array to this file (default: stdout)")
	osv := fs.String("osv-url", rulesbot.DefaultOSVURL, "OSV API base URL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pkgFile == "" || fs.NArg() != 0 {
		return errors.New("usage: rules candidates -packages <file> [-rules <dir>] [-ecosystems list] [-kev url|file] [-epss url] [-since 30d] [-kev-max-age 1095d] [-cache dir] [-max 20] [-out file]")
	}
	win, err := rulesbot.ParseSince(*since)
	if err != nil {
		return fmt.Errorf("-since: %w", err)
	}
	kevAge, err := rulesbot.ParseSince(*kevMax)
	if err != nil {
		return fmt.Errorf("-kev-max-age: %w", err)
	}
	pb, err := os.ReadFile(*pkgFile)
	if err != nil {
		return err
	}
	rs, _, err := rulesbot.LoadExisting(*rulesDir, "")
	if err != nil {
		return err
	}
	ctx, stop := botContext()
	defer stop()
	cs, err := rulesbot.FindCandidates(ctx, rulesbot.CandidateOptions{
		OSVURL: *osv, KEV: *kev, EPSSURL: *epss, Ecosystems: splitKeys(*ecos), Packages: rulesbot.ParsePackages(pb),
		Rules: rs, Since: win, KEVMaxAge: kevAge, BulkURL: *bulk, CacheDir: cacheDir(*cache), Max: *max, Logger: botLogger(stderr),
	})
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(cs, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if *out == "" {
		_, err = stdout.Write(b)
		return err
	}
	return os.WriteFile(*out, b, 0o644)
}

func rulesDraft(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("draft", stderr)
	cand := fs.String("candidate", "", "one candidate as JSON (as printed by 'rules candidates')")
	candFile := fs.String("candidate-file", "", "JSON array of candidates")
	index := fs.Int("index", 0, "index into -candidate-file")
	rulesDir := fs.String("rules", "", "directory with the existing rules (few-shot examples, ID collision)")
	testsDir := fs.String("tests", "", "directory with the existing tests")
	outRules := fs.String("out-rules", "", "directory for the new rule (default: -rules)")
	outTests := fs.String("out-tests", "", "directory for the new tests (default: -tests)")
	provider := fs.String("provider", os.Getenv("PANOPTES_LLM_PROVIDER"), "anthropic | openai-compatible (env PANOPTES_LLM_PROVIDER)")
	model := fs.String("model", os.Getenv("PANOPTES_LLM_MODEL"), "model name (env PANOPTES_LLM_MODEL)")
	baseURL := fs.String("base-url", os.Getenv("PANOPTES_LLM_BASE_URL"), "provider base URL (env PANOPTES_LLM_BASE_URL)")
	osv := fs.String("osv-url", rulesbot.DefaultOSVURL, "OSV API base URL (advisory source)")
	attempts := fs.Int("max-attempts", 2, "LLM attempts (a failed one is retried with the error messages)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || (*cand == "") == (*candFile == "") {
		return errors.New("usage: rules draft (-candidate <json> | -candidate-file <file> -index N) -rules <dir> -tests <dir> [-out-rules dir] [-out-tests dir] [-provider p -model m -base-url u] [-osv-url u] [-max-attempts 2]")
	}
	c, err := readCandidate(*cand, *candFile, *index)
	if err != nil {
		return err
	}
	if *outRules == "" {
		*outRules = *rulesDir
	}
	if *outTests == "" {
		*outTests = *testsDir
	}
	if *outRules == "" || *outTests == "" {
		return errors.New("-out-rules and -out-tests (or -rules and -tests) are required")
	}

	keyEnv := ""
	for _, e := range []string{"PANOPTES_LLM_API_KEY", "ANTHROPIC_API_KEY"} {
		if os.Getenv(e) != "" {
			keyEnv = e
			break
		}
	}
	if *provider == "" && keyEnv != "" {
		*provider = "anthropic"
	}
	if *provider == "" || *provider == "none" {
		return errors.New("no LLM provider: set -provider (or PANOPTES_LLM_PROVIDER); an API key is optional when the Anthropic SDK finds workload identity federation credentials")
	}
	if *model == "" && *provider == "anthropic" {
		*model = "claude-sonnet-5-5"
	}
	if *model == "" {
		return errors.New("-model (or PANOPTES_LLM_MODEL) is required")
	}
	prov, err := newBotProvider(config.LLM{Provider: *provider, Model: *model, BaseURL: *baseURL, APIKeyEnv: keyEnv})
	if err != nil {
		return err
	}

	rs, tests, err := rulesbot.LoadExisting(*rulesDir, *testsDir)
	if err != nil {
		return err
	}
	ctx, stop := botContext()
	defer stop()
	osvSrc := llm.NewOSVSource()
	osvSrc.BaseURL = *osv
	res, err := rulesbot.Draft(ctx, rulesbot.DraftOptions{
		Candidate: c, Provider: prov, Rules: rs, Tests: tests, Catalog: factCatalog(), Advisory: osvSrc,
		MaxAttempts: *attempts, Logger: botLogger(stderr),
	})
	if err != nil {
		var de *rulesbot.DraftError
		switch {
		case errors.As(err, &de):
			return &codedError{exitDraftFailed, err}
		case errors.Is(err, rulesbot.ErrIDExists):
			return &codedError{exitIDExists, err}
		}
		return err
	}
	rp, tp, err := rulesbot.WriteFiles(res, *outRules, *outTests)
	if err != nil {
		if errors.Is(err, rulesbot.ErrIDExists) {
			return &codedError{exitIDExists, err}
		}
		return err
	}
	fmt.Fprintf(stderr, "wrote %s\nwrote %s\n", rp, tp)
	_, err = io.WriteString(stdout, res.PRBody)
	return err
}

func readCandidate(js, file string, index int) (rulesbot.Candidate, error) {
	var c rulesbot.Candidate
	if js != "" {
		if err := json.Unmarshal([]byte(js), &c); err != nil {
			return c, fmt.Errorf("-candidate: %w", err)
		}
		return c, nil
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return c, err
	}
	var all []rulesbot.Candidate
	if err := json.Unmarshal(b, &all); err != nil {
		return c, fmt.Errorf("%s: %w", file, err)
	}
	if index < 0 || index >= len(all) {
		return c, fmt.Errorf("-index %d is out of range (%d candidates)", index, len(all))
	}
	return all[index], nil
}

// cacheDir returns the bulk export cache directory: the flag, else $XDG_CACHE_HOME/panoptes-rules or
// <user cache dir>/panoptes-rules; empty (a temporary directory) when none can be determined.
func cacheDir(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if x := os.Getenv("XDG_CACHE_HOME"); x != "" {
		return filepath.Join(x, "panoptes-rules")
	}
	if d, err := os.UserCacheDir(); err == nil {
		return filepath.Join(d, "panoptes-rules")
	}
	return ""
}
