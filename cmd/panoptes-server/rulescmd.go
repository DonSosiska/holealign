package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/DonSosiska/panoptes/internal/server/config"
	"github.com/DonSosiska/panoptes/internal/server/rulesfeed"
)

const rulesUsage = `usage: panoptes-server rules <command>

  keygen -out <file>                    create an ed25519 signing key (private key file, mode 0600)
  build  -rules <dir> -tests <dir> -seq N -out <dir>
                                        validate, test and pack a deterministic rules-<N>.tar.gz
  sign   -key <file> <tarball>          write <tarball>.sig and latest.json next to the tarball
  verify -pub <base64>[,<base64>] <tarball>
                                        check the signature and the complete bundle
  import [-sig file] <tarball>          install a bundle offline (needs rules.feed.trusted_keys)
  status                                show the installed rules feed bundle
`

// rulesCmd implements "panoptes-server rules ...". keygen, build, sign and verify need neither the
// configuration nor the database, so they work on a build machine with no server config.
func rulesCmd(cfgPath string, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, rulesUsage)
		return 2
	}
	var err error
	switch args[0] {
	case "keygen":
		err = rulesKeygen(args[1:], stdout, stderr)
	case "build":
		err = rulesBuild(args[1:], stdout, stderr)
	case "sign":
		err = rulesSign(args[1:], stdout, stderr)
	case "verify":
		err = rulesVerify(args[1:], stdout, stderr)
	case "import":
		err = rulesImport(cfgPath, args[1:], stdout, stderr)
	case "status":
		err = rulesStatus(cfgPath, args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown rules command %q\n%s", args[0], rulesUsage)
		return 2
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	return 0
}

func newFlags(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("rules "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

// parseInterspersed parses flags that may come before or after the positional arguments.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func rulesKeygen(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("keygen", stderr)
	out := fs.String("out", "", "file for the private key (created with mode 0600; never overwritten)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" || fs.NArg() != 0 {
		return errors.New("usage: rules keygen -out <private-key-file>")
	}
	pub, priv, err := rulesfeed.GenerateKey()
	if err != nil {
		return err
	}
	if err := rulesfeed.WritePrivateKey(*out, priv); err != nil {
		return err
	}
	fmt.Fprintf(stderr, "Private key written to %s. Keep it offline and back it up; anyone holding it can publish rules to every server that trusts the public key.\n", *out)
	fmt.Fprintln(stdout, "public_key: "+rulesfeed.EncodePublicKey(pub))
	fmt.Fprintln(stdout, "key_id:     "+rulesfeed.KeyID(pub))
	return nil
}

func rulesBuild(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("build", stderr)
	rulesDir := fs.String("rules", "", "directory with the rule YAML files (all must be status: reviewed)")
	testsDir := fs.String("tests", "", "directory with <rule-id>.yaml test files")
	seq := fs.Uint64("seq", 0, "bundle sequence number (must be higher than every earlier bundle)")
	outDir := fs.String("out", "", "output directory")
	created := fs.String("created-at", "", "created_at for index.json, RFC 3339 (default: $SOURCE_DATE_EPOCH, else now); the same value makes the build reproducible")
	minVer := fs.String("min-server-version", "", "optional minimum panoptes-server version, e.g. 0.5.0")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *rulesDir == "" || *testsDir == "" || *outDir == "" || *seq == 0 || fs.NArg() != 0 {
		return errors.New("usage: rules build -rules <dir> -tests <dir> -seq N -out <dir> [-created-at RFC3339] [-min-server-version V]")
	}
	at := time.Now()
	switch {
	case *created != "":
		t, err := time.Parse(time.RFC3339, *created)
		if err != nil {
			return fmt.Errorf("-created-at: %w", err)
		}
		at = t
	case os.Getenv("SOURCE_DATE_EPOCH") != "":
		n, err := strconv.ParseInt(os.Getenv("SOURCE_DATE_EPOCH"), 10, 64)
		if err != nil {
			return fmt.Errorf("SOURCE_DATE_EPOCH: %w", err)
		}
		at = time.Unix(n, 0)
	}
	tb, idx, err := rulesfeed.Build(rulesfeed.BuildOptions{RulesDir: *rulesDir, TestsDir: *testsDir, Seq: *seq,
		CreatedAt: at, MinServerVersion: *minVer})
	if err != nil {
		return fmt.Errorf("bundle not built:\n%w", err)
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(*outDir, rulesfeed.TarballName(*seq))
	if err := os.WriteFile(path, tb, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stderr, "built %s: %d rules, %d test files\n", path, len(idx.Rules), len(idx.Tests))
	fmt.Fprintln(stdout, rulesfeed.SHA256(tb))
	return nil
}

func rulesSign(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("sign", stderr)
	keyFile := fs.String("key", "", "private key file from `rules keygen`")
	url := fs.String("url", "", "url for latest.json (default: the tarball's file name, relative to latest.json)")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if *keyFile == "" || len(pos) != 1 {
		return errors.New("usage: rules sign -key <private-key-file> [-url URL] <tarball>")
	}
	tbPath := pos[0]
	tb, err := os.ReadFile(tbPath)
	if err != nil {
		return err
	}
	b, err := rulesfeed.Open(tb, "")
	if err != nil {
		return fmt.Errorf("refusing to sign an invalid bundle: %w", err)
	}
	priv, err := rulesfeed.ReadPrivateKey(*keyFile)
	if err != nil {
		return err
	}
	sig := rulesfeed.Sign(priv, tb)
	sb, err := rulesfeed.MarshalJSONFile(sig)
	if err != nil {
		return err
	}
	if err := os.WriteFile(tbPath+".sig", sb, 0o644); err != nil {
		return err
	}
	u := *url
	if u == "" {
		u = filepath.Base(tbPath)
	}
	pb, err := rulesfeed.MarshalJSONFile(rulesfeed.MakePointer(b.Index.Seq, u, tb, sig))
	if err != nil {
		return err
	}
	latest := filepath.Join(filepath.Dir(tbPath), "latest.json")
	if err := os.WriteFile(latest, pb, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stderr, "signed bundle %d with key %s\n", b.Index.Seq, sig.KeyID)
	fmt.Fprintf(stdout, "%s\n%s\n", tbPath+".sig", latest)
	return nil
}

func readSig(path string) (rulesfeed.Sig, error) {
	var sig rulesfeed.Sig
	b, err := os.ReadFile(path)
	if err != nil {
		return sig, err
	}
	if err := json.Unmarshal(b, &sig); err != nil {
		return sig, fmt.Errorf("%s: %w", path, err)
	}
	return sig, nil
}

func splitKeys(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func rulesVerify(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("verify", stderr)
	pub := fs.String("pub", "", "trusted public key(s), base64, comma-separated")
	sigPath := fs.String("sig", "", "signature file (default: <tarball>.sig)")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if *pub == "" || len(pos) != 1 {
		return errors.New("usage: rules verify -pub <base64> [-sig file] <tarball>")
	}
	keys, err := rulesfeed.ParsePublicKeys(splitKeys(*pub))
	if err != nil {
		return err
	}
	tb, err := os.ReadFile(pos[0])
	if err != nil {
		return err
	}
	sp := *sigPath
	if sp == "" {
		sp = pos[0] + ".sig"
	}
	sig, err := readSig(sp)
	if err != nil {
		return err
	}
	if err := rulesfeed.VerifySig(tb, sig, keys); err != nil {
		return err
	}
	b, err := rulesfeed.Open(tb, version)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "OK: bundle %d, %d rules, %d test files, signed by key %s, sha256 %s\n",
		b.Index.Seq, len(b.Rules), len(b.Tests), sig.KeyID, rulesfeed.SHA256(tb))
	return nil
}

func loadFeedConfig(cfgPath string, fs *flag.FlagSet, args []string) (*config.Config, []string, error) {
	fs.StringVar(&cfgPath, "config", cfgPath, "path to server.yaml")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return nil, nil, err
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, nil, fmt.Errorf("config: %w", err)
	}
	return cfg, pos, nil
}

func rulesImport(cfgPath string, args []string, stdout, stderr io.Writer) error {
	fs := newFlags("import", stderr)
	sigPath := fs.String("sig", "", "signature file (default: <tarball>.sig)")
	cfg, pos, err := loadFeedConfig(cfgPath, fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: rules import [-sig file] <tarball>")
	}
	keys, err := rulesfeed.ParsePublicKeys(cfg.Rules.Feed.TrustedKeys)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return errors.New("rules.feed.trusted_keys is empty: configure the public key(s) that sign your bundles first")
	}
	tb, err := os.ReadFile(pos[0])
	if err != nil {
		return err
	}
	sp := *sigPath
	if sp == "" {
		sp = pos[0] + ".sig"
	}
	sig, err := readSig(sp)
	if err != nil {
		return err
	}
	if err := prepareCLI(cfg); err != nil {
		return err
	}
	b, err := rulesfeed.Import(cfg.RulesFeedDir(), keys, version, tb, sig, time.Now())
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "installed rules bundle %d (%d rules). A running server activates it within a minute (rules.feed.enabled must be true).\n", b.Index.Seq, len(b.Rules))
	return nil
}

func rulesStatus(cfgPath string, args []string, stdout, stderr io.Writer) error {
	fs := newFlags("status", stderr)
	cfg, pos, err := loadFeedConfig(cfgPath, fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 0 {
		return errors.New("usage: rules status")
	}
	keys, err := rulesfeed.ParsePublicKeys(cfg.Rules.Feed.TrustedKeys)
	if err != nil {
		return err
	}
	dir := cfg.RulesFeedDir()
	st := rulesfeed.ReadState(dir)
	fmt.Fprintf(stdout, "feed enabled:   %v\n", cfg.Rules.Feed.Enabled)
	if cfg.Rules.Feed.URL != "" {
		fmt.Fprintf(stdout, "feed url:       %s\n", cfg.Rules.Feed.URL)
	}
	inst, skipped := rulesfeed.LoadInstalled(dir, keys, version)
	if inst == nil {
		fmt.Fprintln(stdout, "installed:      none (only the built-in rules are active)")
	} else {
		b := inst.Bundle
		fmt.Fprintf(stdout, "installed:      seq %d (source: feed, signed by key %s), created %s\n", b.Index.Seq, inst.Sig.KeyID, b.Index.CreatedAt)
		fmt.Fprintf(stdout, "rules:          %d (tests: %d files)\n", len(b.Rules), len(b.Tests))
	}
	for _, e := range skipped {
		fmt.Fprintf(stdout, "ignored:        %v\n", e)
	}
	fmt.Fprintf(stdout, "last installed: %s\n", orDash(st.UpdatedAt))
	fmt.Fprintf(stdout, "last poll ok:   %s\n", orDash(st.CheckedAt))
	fmt.Fprintf(stdout, "last error:     %s\n", orDash(st.LastError))
	if st.Failures > 0 {
		fmt.Fprintf(stdout, "failed polls:   %d in a row\n", st.Failures)
	}
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
