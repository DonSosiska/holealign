# Central rules feed

A rule says when a vulnerable package is actually exploitable. The host-specific part is the facts the
rule reads, so a rule can be written and reviewed once and delivered to every server like the Grype DB.
The central rules feed does that. This page covers what servers fetch and verify, how the public feed
is built and signed, how to run your own feed, and the repository bot that drafts rules.

```
holealign-rules repository (YAML + tests, reviewed pull requests; the trust root)
        |  merge to main -> release workflow (protected environment, required reviewer)
        |  rules build  ->  rules-<seq>.tar.gz   (deterministic)
        |  rules sign   ->  rules-<seq>.tar.gz.sig + latest.json   (ed25519)
        v
static HTTPS host  (GitHub Pages: latest.json, rules-<seq>.tar.gz)
        |  every rules.feed.interval:  GET latest.json -> download -> verify -> validate -> test -> install
        v
holealign-server:  built-in rules  <  feed rules  <  local rules (DB)
```

The feed is **off by default**. A server without it works exactly as before, with the rules shipped in the
binary (and optionally `rules_dir`).

## The public feed

| | |
|---|---|
| Pointer URL | `https://donsosiska.github.io/holealign-rules/latest.json` |
| Public key (base64 ed25519) | `UuFW4nYSCwI3xfHhwapVhYrjYhVO6i7yaxOTv9KFCuM=` |
| `key_id` | `75eef42e119d4dda` (first 16 hex characters of the SHA-256 of the raw public key) |
| Canonical key location | [keys/rules-public.key](https://github.com/DonSosiska/holealign-rules/blob/main/keys/rules-public.key) in the rules repository |
| Source | [DonSosiska/holealign-rules](https://github.com/DonSosiska/holealign-rules) |

Turn it on:

```yaml
rules:
  feed:
    enabled: true
    url: https://donsosiska.github.io/holealign-rules/latest.json
    trusted_keys:
      - "UuFW4nYSCwI3xfHhwapVhYrjYhVO6i7yaxOTv9KFCuM="
```

Do not copy the key from a web page you cannot trust: take it from the repository (the canonical
location above), compare it with this page, and check that the signature `key_id` in the pointer matches
`75eef42e119d4dda`. The key is the only thing that makes the feed trustworthy; a key you got from the
same place as a tampered feed proves nothing.

## Terminology

The same three layers appear under different names:

| Layer | Web UI label | API / engine value (`Engine.Sources()`) | Where it comes from |
|---|---|---|---|
| Built-in | `built-in` | `builtin` | the eight shipped rules, embedded in the binary; `rules_dir` adds to or replaces them |
| Feed | `feed #<seq>` | `feed:<seq>` | the installed, verified bundle |
| Local | `local` | `db` | the server's database: edits made in the web UI and LLM drafts |

The rule file field `source` (`builtin`, `user`, `llm:<model>`) is a different thing: it records who wrote
the rule, not which layer delivered it.

## Layers and precedence

| Layer | Source | Reported as |
|---|---|---|
| built-in | the eight shipped rules, embedded in the binary (`go:embed` of `rules/`); `rules_dir` adds rules and replaces embedded ones with the same `id` | `built-in` (`builtin`) |
| feed | the installed, verified bundle | `feed #<seq>` (`feed:<seq>`) |
| local | the database: user edits and LLM drafts | `local` (`db`) |

- A rule from a higher layer replaces a rule with the same `id` from a lower layer.
- When several rules cover the same CVE and package, the winner is chosen by status (`reviewed` over
  `draft`), then by layer (local over feed over built-in), then by `id`.
- A local **draft** never replaces a reviewed rule with the same `id` (a problem is reported, the
  reviewed rule is kept). A local reviewed rule (a user edit) does replace a feed or built-in rule:
  editing a feed rule in the web UI (with password re-authentication) stores a local override on
  this server only. Feed rules are read-only in the UI.
- The LLM drafter treats a CVE covered by any rule, including a feed rule, as covered and makes no
  call for it.

## Rule tests

Every rule in a bundle has a test file `tests/<rule-id>.yaml`, a YAML list of cases evaluated by the real
engine (`rules.RunTests`). The case format and every key are in
[rules.md](rules.md#test-case-reference). A case passes only when the rule under test is the rule that
matched and the verdict equals `want`. The shipped rules' tests are in [`rules-tests/`](../rules-tests/)
and run with `go test ./internal/server/rules/`.

`rules build` additionally requires, per rule, at least one case with `want: exploitable` and at least one
non-exploitable case (`affected_not_exploitable` or `not_affected`). The only exemption from the first is a
rule whose `exploitable_if` is the literal `false` (such as `CVE-2024-4577`), which cannot be exploitable by
design.

## Bundle format

`rules-<seq>.tar.gz` (gzip, tar) contains exactly:

```
index.json
rules/<id>.yaml
tests/<id>.yaml
```

`index.json`:

```json
{
  "format": 1,
  "seq": 42,
  "created_at": "2026-03-04T05:06:07Z",
  "min_server_version": "0.5.0",
  "catalog": ["os.libc", "sshd.config"],
  "rules": [{"id": "CVE-2024-6387", "file": "rules/CVE-2024-6387.yaml", "sha256": "<hex>"}],
  "tests": [{"id": "CVE-2024-6387", "file": "tests/CVE-2024-6387.yaml", "sha256": "<hex>"}]
}
```

- `seq` is a strictly increasing unsigned integer chosen by the publisher; it is the version.
- `min_server_version` is optional (dotted numbers; `dev` builds ignore it).
- `catalog` lists the fact names the rules read (without `file.match:*`). A server that does not know
  one of them rejects the bundle and asks to be upgraded.
- `id` is the rule id (`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`); the YAML's `id` must equal it. `sha256`
  is the lowercase hex SHA-256 of the file bytes.

`rules build` writes the archive deterministically: entries sorted by name, mtime 0, uid and gid 0,
no owner names, mode 0644, USTAR headers, gzip without name or time. The same inputs and the same
`-created-at` (or `SOURCE_DATE_EPOCH`) always give the same SHA-256.

Every rule in a bundle must be `status: reviewed`.

## Signature and pointer

`rules-<seq>.tar.gz.sig`:

```json
{"alg": "ed25519", "key_id": "9f2c41aa07be3d15", "sig": "<base64>"}
```

- `key_id`: the first 16 hex characters of `sha256(public key)`.
- `sig`: `base64(ed25519.Sign(private, sha256(tarball)))`.

`latest.json` is the small file servers poll:

```json
{
  "seq": 42,
  "url": "rules-42.tar.gz",
  "sha256": "<hex sha256 of the tarball>",
  "sig": {"alg": "ed25519", "key_id": "9f2c41aa07be3d15", "sig": "<base64>"}
}
```

`url` is relative to `latest.json` or absolute with the same scheme, host and port as the pointer (no
user info), so an unsigned pointer cannot make the server fetch from another host. Only the tarball is signed; the pointer
is a convenience. The server therefore also requires that `index.json`'s `seq` equals the pointer's
`seq`, so a validly signed old bundle cannot be replayed under a newer number.

## What the server checks

Per poll (`rules.feed.interval`, default 6 h, plus once at start):

1. `GET` `latest.json`: at most 64 KiB, HTTPS only (`file://` for tests and mirrors), no redirects,
   30 s timeout. `seq` not greater than the installed one: nothing happens (a lower `seq` is logged at
   WARN as a possible rollback).
2. Download the tarball: at most 10 MiB; its SHA-256 must equal the pointer's.
3. Verify the signature with a trusted key: `alg` is `ed25519`, `key_id` names a key in
   `rules.feed.trusted_keys`, the signature matches.
4. Extract **in memory**. Only regular files named exactly `index.json`, `rules/<id>.yaml` or
   `tests/<id>.yaml`; no `..`, absolute paths, directories, symlinks, hardlinks or devices; at most
   5000 entries, each at most 256 KiB; every file listed in the index with a matching SHA-256 and
   nothing unlisted; duplicates rejected.
5. Parse and `Validate` every rule; all must be `reviewed`; `min_server_version` and `catalog` must fit
   this server. **One bad rule rejects the whole bundle** (atomic).
6. Run the bundle's tests with the real engine. Any failure rejects the bundle.
7. Persist the bundle and its signature to `data_dir/rules-feed/` (temp file and rename), record
   `rulesfeed.seq`, `rulesfeed.updated_at`, `rulesfeed.checked_at`, `rulesfeed.last_error` (and
   `rulesfeed.failures`) in the kv table, reload the engine and re-run the pipeline for all hosts.

On start the persisted bundle is re-verified (signature, hashes, rules, tests) before the first poll,
so tampering on disk or a key that was removed from `trusted_keys` takes effect immediately. A rejected
bundle never changes the installed one.

A failed poll keeps the previous rules, sets `rulesfeed.last_error` and counts toward the health alert.

## Health

When `rules.feed.enabled` is set and `rules.feed.url` is not empty, the health monitor raises a
`feed_stale` alert (detail starts with "rules feed", so it is distinct from the "vulnerability DB"
alert) and a dashboard banner when no poll succeeded for `rules.feed.stale_after` (default 7 d) or the
last 3 polls failed. A feed that answers but has nothing new counts as fresh; publishing is not
required on a schedule. `feed_ok` is sent on recovery.

## Configuration

```yaml
rules:
  feed:
    enabled: false                      # HOLEALIGN_RULES_FEED_ENABLED
    url: https://donsosiska.github.io/holealign-rules/latest.json   # https:// (file:// allowed); empty = import only
    interval: 6h                        # >= 1m
    trusted_keys:                       # base64 ed25519 public keys; required when enabled
      - "UuFW4nYSCwI3xfHhwapVhYrjYhVO6i7yaxOTv9KFCuM="
    stale_after: 7d
```

Enabled with an empty `trusted_keys` is a configuration error. See
[configuration.md](configuration.md#rules-feed).

## How servers verify a bundle

See [What the server checks](#what-the-server-checks) for the full list. The four properties that matter:

- **Signature.** The tarball is signed with ed25519; the server accepts only a `key_id` that is in
  `rules.feed.trusted_keys`. Without a valid signature nothing is installed, whatever the pointer says.
- **Anti-rollback.** A bundle is installed only if its `seq` is higher than the installed one; a pointer
  to a lower `seq` is logged and ignored. Because the pointer is not signed, `index.json` inside the
  signed tarball must carry the same `seq`, so an old signed bundle cannot be replayed under a new number.
- **Same-host rule.** The pointer's `url` must have the same scheme, host and port as the pointer itself
  (relative URLs resolve against it), with no user info. A tampered pointer cannot send the server to
  another host. Redirects are never followed.
- **Strict extraction.** In memory only; fixed file names, regular files, bounded counts and sizes, every
  file listed with a matching SHA-256 and nothing unlisted. One bad rule or failing test rejects the whole
  bundle.

## How the public feed is built and signed

The rules repository is the trust root: whoever can get a change merged there and approve its release
can publish rules to every server that trusts the key. Its CI is built around that.

- **Pull requests are validated without secrets** (`validate.yml`, `pull_request`, never
  `pull_request_target`): it builds `holealign-server` from the commit pinned in the repository's
  `HOLEALIGN_REF`, runs `rules build` (validation, tests, coverage policy; rules must be `reviewed`, so an
  unreviewed bot draft fails by design) and checks that the eight rules shared with this repository are
  byte-identical to the copies in `rules/` and `rules-tests/` here.
- **`HOLEALIGN_REF` must be an ancestor of holealign `main`.** The build action checks out the full
  history at that commit and refuses it when it is not on `main`, so a commit from a fork, an unmerged
  branch or rewritten history cannot become the build tool.
- **Release only from the tip of `main`.** The release workflow runs on pushes to `main` that change
  `rules/` or `tests/` (or manually) and stops unless `HEAD` equals the current tip of `main`, so an old
  commit or a re-run of an old run cannot republish an older rule set under a newer `seq`.
- **Protected environment.** The release job runs in the `rules-release` environment: a required
  reviewer must approve each run, deployment is limited to `main`, and the signing key
  (`RULES_SIGNING_KEY`) exists only there.
- **Key handed over by file only.** One step writes the secret to a mode 0600 file under the runner's
  temp directory; the signer (`rules sign -key <file>`) reads the file and never has the secret in its
  environment; the file is deleted in an `always()` step.
- **Verify before publishing.** The job verifies the signature with the public key committed at
  `keys/rules-public.key`, not with the key it just used, then creates a GitHub release `rules-<seq>`
  (tag and assets) and publishes `latest.json` plus the newest bundles to the `gh-pages` branch in one
  commit (the pointer last, so servers never see a pointer to a missing file). `seq` is the highest
  existing `rules-<n>` tag or release plus one.
- **Offline backup.** The private key is also kept offline, on encrypted media, backed up. Losing it
  means rotating the key (below).

## Key rotation

Servers accept a bundle signed by any key in `rules.feed.trusted_keys`, so rotation overlaps two keys:

1. Generate the new key (`holealign-server rules keygen -out <file>`; prints the public key and `key_id`).
2. Publish the new public key to operators and ask them to list **both** keys in `trusted_keys`.
3. Wait until the servers run with both keys.
4. Replace the `RULES_SIGNING_KEY` secret with the new private key and commit the new
   `keys/rules-public.key`; the next release is signed with it.
5. Operators remove the old key from `trusted_keys` once they run a bundle signed by the new key.

If the signing key leaks, operators must drop it from `trusted_keys` at once: the persisted bundle is
re-verified at every start and a bundle signed only by a removed key is ignored. Then rotate as above
(skip the overlap, ship the new key directly). A lost private key is the same situation: distribute a new
`trusted_keys` entry before the feed works again.

## Running your own feed

Use your own repository and key when you want rules the public feed does not carry, or no dependency on
it. You need only `holealign-server` and a static HTTPS host.

```sh
holealign-server rules keygen -out rules-signing.key      # offline machine; prints the public key
# in your rules repository: rules/<id>.yaml and tests/<id>.yaml, every rule status: reviewed
holealign-server rules build -rules rules -tests tests -seq 1 -out dist
holealign-server rules sign -key rules-signing.key dist/rules-1.tar.gz     # writes .sig and latest.json
holealign-server rules verify -pub <base64 public key> dist/rules-1.tar.gz # optional
# upload rules-1.tar.gz and rules-1.tar.gz.sig first, latest.json last
```

Then point servers at it with your public key in `trusted_keys`. Rules for your own feed go through
the same validation, so a rule that does not pass `rules build` is not published. Increase `-seq` for every
release. `-created-at` (RFC 3339) or `SOURCE_DATE_EPOCH` fixes `created_at` for reproducible builds,
`-min-server-version` sets `min_server_version`, and `rules sign -url <URL>` sets the pointer's `url` when
the tarball is not next to `latest.json` (it must still be on the same host). In this repository
`make rules-bundle` builds the shipped rules (`RULES_SEQ=N`, optional `RULES_KEY=<file>` to sign).

`keygen`, `build`, `sign` and `verify` need neither a server configuration nor a database. Handle the
private key like a release-signing key: anyone holding it can publish rules, and rules can request file
reads from agents. Prefer building and signing in a protected CI environment as the public feed does,
or on an offline machine, and keep an offline backup.

## Air-gapped servers

Copy `rules-<seq>.tar.gz` and `rules-<seq>.tar.gz.sig` over your usual channel, then on the server:

```sh
holealign-server rules import rules-43.tar.gz          # uses rules-43.tar.gz.sig; -sig <file> to override
holealign-server rules status
```

`import` verifies against `rules.feed.trusted_keys`, applies the anti-rollback rule (the `seq` must be
higher than the installed one) and installs into `data_dir/rules-feed/`. A running server with
`rules.feed.enabled: true` activates it within a minute. For a fully offline server leave
`rules.feed.url` empty. A local mirror also works: `url: file:///srv/rules/latest.json`.

`rules status` prints the installed `seq`, the source, the rule and test counts, the last install and
poll times and the last error.

## Repository bot

The rules repository runs a scheduled workflow (`bot.yml`, daily and on demand) that finds CVEs worth a
rule, drafts a rule and tests with an LLM, and opens one pull request per draft. A human reviews and sets
`status: reviewed`; CI accepts a bundle only then, so a draft cannot reach the feed by itself, and a merge
is still subject to the `rules-release` approval. The workflow calls Anthropic through workload identity
federation, so no API key is stored anywhere. Setup:
<https://github.com/DonSosiska/holealign-rules/blob/main/docs/bot-setup.md>.

Three `holealign-server` commands do the work (the third, `rules eval`, is a measurement tool and not part of the workflow). Neither needs a server configuration or database, and neither
sends host data anywhere (there is none): only advisory and candidate fields go to OSV, KEV, EPSS and the
LLM provider.

### `rules candidates`

Selects CVEs worth a rule that the repository does not cover yet and prints a JSON array.

```sh
holealign-server rules candidates -rules rules -packages packages.txt -max 20 -out candidates.json
```

| Flag | Default | Meaning |
|---|---|---|
| `-rules <dir>` | | existing rules; a CVE is covered when a rule lists it (or an alias) in `vulns` for a matching package |
| `-packages <file>` | required | source package names, one per line, `#` comments |
| `-ecosystems <list>` | `Debian:12,Alpine:v3.20` | comma-separated OSV ecosystem releases (spaces and empty items ignored); Debian and Ubuntu give type `deb`, Alpine `apk`, `Red Hat` `rpm`. Debian and Alpine are read from the bulk export; `Ubuntu:*` and `Red Hat:*` are queried package by package (slower, capped by the request limit) |
| `-kev <url\|file>` | CISA KEV JSON URL | known exploited vulnerabilities |
| `-epss <url>` | `https://api.first.org/data/v1/epss?cve=` | EPSS API; the CVE list is appended, 100 per request |
| `-since` | `30d` | a vulnerability *published* (not modified) within this window is relevant |
| `-kev-max-age` | `1095d` | a KEV vulnerability published within this age is relevant |
| `-cache <dir>` | `$XDG_CACHE_HOME/holealign-rules`, else the user cache dir, else a temporary directory | where the OSV bulk exports are kept between runs |
| `-bulk-url` | `https://osv-vulnerabilities.storage.googleapis.com` | base URL of the bulk exports (mirrors, tests) |
| `-max` | `20` | cap on the result |
| `-out <file>` | stdout | |
| `-osv-url` | `https://api.osv.dev` | OSV base URL (mirrors, tests) |

Data. For Debian and Alpine it downloads OSV's per-ecosystem export
(`<bulk-url>/<Ecosystem>/all.zip`; Debian is about 82 MB, Alpine about 9 MB) once per run into the
cache directory, reusing the cached copy when the server answers `304` to `If-None-Match` /
`If-Modified-Since` (and when the download fails but a copy exists). The zip is read as a stream,
nothing is extracted; limits: 200 MB per downloaded file, 4 MiB per JSON entry. Records are filtered
to the requested release (`affected[].package.ecosystem` equal, e.g. `Debian:12`) and to `-packages`.
Ubuntu (about 820 MB) is not downloaded: `Ubuntu:*` and `Red Hat:*` releases still query
`/v1/querybatch` per package and fetch `/v1/vulns/{id}` for each hit (skipping records unmodified for
longer than `-kev-max-age` unless in KEV), within 2000 HTTP requests per run.

Relevance. For the requested release a record is a candidate when it has a CVE id (or CVE alias),
is not withdrawn, and
- it is **unfixed**: an affected range of the package has no `fixed` event; or
- it was **published** within `-since`; or
- it is in **KEV** and published within `-kev-max-age`, or in KEV and unfixed.

Outside KEV the severity must be High or Critical: the CVSS v3 base score is computed from the
vector; a CVSS v4 vector is not computed, the record's qualitative `database_specific.severity` is used
if present, otherwise the record is skipped. KEV entries of any severity pass. A CVE is dropped when
`-rules` already covers it (the CVE or an alias in `vulns`, and a selector that matches: `source`
against the package, `name` globs against the package and `binary_packages`). So a long-fixed
vulnerability such as Heartbleed (CVE-2014-0160) or CVE-2015-7547 no longer shows up, however often
OSV re-modifies the record. Sorting (the bot drafts in list order, so this is the drafting priority): first the records published
inside the `-since` window, newest `published` first (ties: KEV, then CVSS, then EPSS, then ID and package);
then everything else (older KEV or unfixed records, and records with a missing or unparsable `published`) by
KEV, then EPSS (batches of 100), then CVSS. Fresh records come first because the EPSS of a new CVE stays
near 0 for days. `-max` caps the list after sorting. A CVE appearing for the same package in several ecosystems is listed once (the first wins).
Each entry: `vuln, aliases, package, source, binary_packages, type, ecosystem, severity, cvss, epss,
kev, published`. `package` and `source` are the source package; `binary_packages` is best effort
(Debian records carry no binaries: it is `[package]`) and the draft does not depend on it. Further
limits: 8 MiB per API response, 30 s API timeouts, `User-Agent: holealign-rules-bot`. Failures for
single packages are logged and skipped; exit 1 when every OSV source fails or KEV cannot be read.

Expected cost of a run with the six packages openssh, openssl, nginx, sudo, glibc and curl on the
default ecosystems: one download per ecosystem the first time, then a conditional request; well under
a minute once the cache is warm, with a handful of HTTP requests instead of the thousand the per-package
path needed.

### `rules draft`

Writes one rule and its tests for one candidate and prints a Markdown pull request body.

```sh
holealign-server rules draft -candidate-file candidates.json -index 0 \
  -rules rules -tests tests -out-rules rules -out-tests tests > pr-body.md
```

Flags: `-candidate <json>` or `-candidate-file <file> -index N`; `-rules`, `-tests` (existing rules
and tests: few-shot examples and ID collision); `-out-rules`, `-out-tests` (default: `-rules`,
`-tests`); `-provider`, `-model`, `-base-url` (defaults from `HOLEALIGN_LLM_PROVIDER`,
`HOLEALIGN_LLM_MODEL`, `HOLEALIGN_LLM_BASE_URL`; key from `HOLEALIGN_LLM_API_KEY` or
`ANTHROPIC_API_KEY`; provider `anthropic` is assumed when only a key is set); `-max-attempts`
(default 2); `-osv-url`; `-effort low|medium|high|xhigh|max` (default `HOLEALIGN_LLM_EFFORT`, else `medium`). A
summary line `usage: model=... calls=N in=... out=... cache_read=... cache_write=... est_usd=...` goes to
stderr after the run (see [llm.md](llm.md#prompt-caching-usage-and-effort)); stdout and the exit codes are
unchanged. `rules candidates` makes no LLM call and has no `-effort`.

Keyless authentication. When neither `HOLEALIGN_LLM_API_KEY` nor `ANTHROPIC_API_KEY` is set, the
Anthropic SDK looks for workload identity federation credentials in the environment:
`ANTHROPIC_FEDERATION_RULE_ID`, `ANTHROPIC_ORGANIZATION_ID`, `ANTHROPIC_SERVICE_ACCOUNT_ID` and
`ANTHROPIC_IDENTITY_TOKEN_FILE` (optionally `ANTHROPIC_WORKSPACE_ID`). Then no API key is needed;
set `-provider anthropic` (or `HOLEALIGN_LLM_PROVIDER`) explicitly, because without a key the provider
is not inferred. Setup for the rules repository's workflow:
<https://github.com/DonSosiska/holealign-rules/blob/main/docs/bot-setup.md>.

The model sees the same prompt as the server drafter (fact catalog, CEL environment, untrusted-data
delimiters, sanitising) plus a repository variant that asks for `{rule, tests}` with at least one
`exploitable` and one non-exploitable case (the exploitable case is not needed when `exploitable_if`
is `false`). Cleaning is as in the server: `vulns` are the candidate and its aliases (see below), the package
selector is `{source: <candidate package>, type: <candidate type>}` (the rule covers every binary built
from the source; the model is told to use `pkg["name"]` / `pkg["source"]` in expressions to tell
binaries apart), test findings carry `source` and a realistic binary `package`, the ID is `<VULN>-<source>`
(refused when it exists), texts are capped, references must appear in the advisory, test facts must
be catalog facts. The rule is written with `status: draft` and `source: llm:<model>`. It is checked
with `Validate`, the bundle coverage rules and `RunTests` (evaluated as if `reviewed`, because drafts
never lower verdicts at runtime); a failure is retried once with the messages (2 KB at most).
Nothing is written unless everything passes.

Aliases. Only identifiers of the candidate's own vulnerability reach `vulns`: GHSA IDs
(`GHSA-xxxx-xxxx-xxxx`) and the ecosystem's own CVE-derived IDs (`DEBIAN-CVE-...`, `ALPINE-CVE-...`,
`UBUNTU-CVE-...`, matching the candidate's CVE). Other CVEs, other distributions' IDs and anything
else are dropped (and logged). A record that names more than one distinct CVE keeps only the candidate's
CVE and its own distro ID, because its GHSA IDs cannot be tied to one CVE. The same filter runs again
in `rules draft`, so a hand-edited candidate file cannot widen a rule.

Pull request body. Everything the model or the feed wrote (title, explanation, fix text, test names,
facts, references) is shown as inline code or in fenced code blocks, never as Markdown, so links,
images, HTML, `@mentions` and emphasis in it are inert; references are plain text, not links. The only
links are the advisory links the bot builds from validated IDs (OSV, NVD, CISA KEV search, GitHub
advisories). A "Rule scope" section lists the full `vulns` and `packages` of the rule exactly as in the
rule file; the reviewer checks each ID there.

A reviewer checks the pull request and sets `status: reviewed`; CI validates the bundle only then.

Exit codes: 0 success; 1 other error (usage, provider or network error); 2 no valid draft or the
model refused (nothing written); 3 a rule with that ID already exists.

### `rules eval`

Measures how well a model drafts rules, against human-reviewed rules and their tests, to decide whether a
cheaper model is good enough. **It makes real LLM calls and spends real money** (see below).

```sh
holealign-server rules eval -rules rules -tests tests \
  -variants claude-sonnet-5-5@medium,claude-haiku-5-5@medium,claude-haiku-5-5@high \
  -runs 3 -out report.json > summary.md
```

Usage: `rules eval -rules <dir> -tests <dir> [-ids a,b] [-variants model[@effort],...] [-runs 3] [-max-attempts 2] [-concurrency 2] [-out report.json] [-provider p] [-model m] [-base-url u] [-osv-url u] [-effort e]`

| Flag | Default | Meaning |
|---|---|---|
| `-rules`, `-tests` | required | the reference rules and tests, for example a `holealign-rules` checkout |
| `-ids` | every rule with `status: reviewed` that has tests | comma-separated rule IDs |
| `-variants` | one variant: `-model` / `HOLEALIGN_LLM_MODEL`, else `claude-sonnet-5-5` | comma-separated `model[@effort]`; without `@effort`, `-effort` applies |
| `-runs` | `3` | drafts per rule and variant (a model is not deterministic) |
| `-max-attempts` | `2` | attempts per draft, as in `rules draft` |
| `-concurrency` | `2` | drafts in flight; raise it with care, rate limits apply |
| `-out` | | JSON report with every run |
| `-provider`, `-base-url`, `-osv-url`, `-effort` | as in `rules draft` | the key comes from `HOLEALIGN_LLM_API_KEY` or `ANTHROPIC_API_KEY` |

For every reference rule, variant and run the command builds a candidate from the rule (vuln: the first
`CVE-*` in `vulns`, else the first ID; its other vulns are aliases; package: the `source` of the `deb`
selector if there is one, else its `name` without `*`; type `deb`, ecosystem `Debian:12`; severity, KEV
and EPSS are left empty; a rule with only `apk` selectors uses `apk`), fetches the advisory from OSV once
per vulnerability, and runs the same draft pipeline as `rules draft` (validation, the draft's own tests,
retries). The reference rule is removed from the rules passed to the pipeline, so it is neither a
few-shot example nor an ID collision, and nothing is written to `-rules` or `-tests`.

A successful draft is then scored against the reference rule's test cases: each case is evaluated with
the drafted rule (status forced to `reviewed`, as rule tests are) and its verdict compared with the case's
`want`. A case counts only when the drafted rule matches its finding (same package selector and type,
for example `deb` cases); the others are *skipped*. A case without `source` whose package the reference
rule selects by name gets the candidate's source package.

| Metric | Meaning |
|---|---|
| success | the pipeline produced a valid rule with passing own tests within the attempts |
| agreement | matched / compared reference cases of one draft, averaged over successful drafts with at least one compared case |
| unsafe | compared cases where the reference wants `exploitable` or `conditions_unknown` and the draft says `affected_not_exploitable` or `not_affected` (the dangerous direction; drafts never lower verdicts at runtime, but a reviewer may trust one) |
| missed exploitable | compared cases where the reference wants `exploitable` and the draft does not |
| attempts, tokens | LLM calls per run and input + output + cache tokens per run, means over all runs |
| est. USD per success | the estimated cost of all runs (failed ones included) divided by the number of successful drafts |

Output: a Markdown summary on stdout (one table per variant with a row per rule, then a table comparing
the variants: success rate, mean agreement, unsafe, missed exploitable, USD per success, total USD) and,
with `-out`, a JSON report with every run (success, attempts, refusal, capped error text, wall time,
usage, estimated USD, score). Costs are estimated from list prices ([llm.md](llm.md#prompt-caching-usage-and-effort));
`n/a` means a model without a price. The exit code is 0 even when drafts fail, because this is a
measurement; it is non-zero only for usage errors and when no LLM call returned at all (the summary is
still printed).

Cost. Every run is one to `-max-attempts` LLM calls with a prompt of roughly 10-15k input tokens (the
system prompt is cached after the first call within five minutes) and a few thousand output tokens. As a
rough guide that is a few cents per Sonnet 5.5 draft and a fraction of a cent per Haiku 5.5 draft, so
20 rules x 3 runs x 3 variants (180 drafts) costs of the order of ten dollars, most of it the Sonnet
variant. Start with `-ids` of two or three rules and `-runs 1`, read the `usage:` figures, then scale up.
The estimate in the report is the authority on your own prompts.
