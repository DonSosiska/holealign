# Central rules feed

A rule says when a vulnerable package is actually exploitable, and it does not depend on the host
(the host-specific part is the facts the rule reads). So rules can be written and reviewed once, in
one place, and delivered to every server like the Grype DB. The central rules feed does that:

```
rules repository (YAML + tests, reviewed)
        |  rules build  ->  rules-<seq>.tar.gz   (deterministic)
        |  rules sign   ->  rules-<seq>.tar.gz.sig + latest.json   (ed25519, key kept offline)
        v
static HTTPS host  (latest.json, rules-<seq>.tar.gz)
        |  every rules.feed.interval:  GET latest.json -> download -> verify -> validate -> test -> install
        v
panoptes-server:  built-in rules  <  feed rules  <  local rules (DB)
```

Phase 1 covers the bundle format, signing, the server poller and the CLI. The separate rules
repository and its CI are set up separately; everything the repository needs is the
`panoptes-server rules build|sign` commands described here.

The feed is **off by default**. A server without it works exactly as before, with the rules shipped
in the binary (and optionally `rules_dir`).

## Layers and precedence

| Layer | Source | Reported as |
|---|---|---|
| built-in | the eight shipped rules, embedded in the binary (`go:embed` of `rules/`); `rules_dir` adds rules and replaces embedded ones with the same `id` | `built-in` |
| feed | the installed, verified bundle | `feed #<seq>` |
| local | the database: user edits and LLM drafts | `local` |

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

Every rule has a test file `tests/<rule-id>.yaml`: a YAML list of cases evaluated by the real engine
(`rules.RunTests`).

```yaml
- name: glibc, default LoginGraceTime
  finding: {vuln: CVE-2024-6387, package: openssh-server, type: deb, severity: High, kev: false}
  facts:
    os.libc: glibc
    sshd.config: {logingracetime: "120"}
  host: {os_id: debian, arch: amd64, labels: [prod]}
  want: exploitable
```

| Key | Meaning |
|---|---|
| `name` | Required, shown in failures. |
| `finding` | `vuln` and `package` (the binary package) are required; `source`, `type`, `version`, `severity`, `kev` optional. With `source` the finding gets a PURL with that `upstream` qualifier, so `source` selectors apply; without it the source is the package name. The case is matched like a real finding (aliases are not used). |
| `facts` | The host facts, as the agent would send them. Numbers are handled like on the wire. Absent facts give `conditions_unknown`. |
| `host` | `os_id`, `os_version_id`, `arch`, `labels` (the `host.*` CEL variables). |
| `want` | `exploitable`, `affected_not_exploitable`, `conditions_unknown` or `not_affected`. |

A case passes only when the rule under test (the file name) is the rule that matched **and** the
verdict equals `want`. Unknown keys are errors. The shipped rules' tests are in
[`rules-tests/`](../rules-tests/) and run with `go test ./internal/server/rules/`.

`rules build` additionally requires, per rule, at least one case with `want: exploitable` and at
least one non-exploitable case (`affected_not_exploitable` or `not_affected`). The only exemption is
a rule whose `exploitable_if` is the literal `false` (such as `CVE-2024-4577`), which cannot be
exploitable by design.

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
    enabled: false                      # PANOPTES_RULES_FEED_ENABLED
    url: https://rules.example.com/panoptes/latest.json   # https:// (file:// allowed); empty = import only
    interval: 6h                        # >= 1m
    trusted_keys:                       # base64 ed25519 public keys; required when enabled
      - "q3fYk0J6X0s2m3zH0wC1o9h1kQwq8m1r8mZ0Xo7bV1A="
    stale_after: 7d
```

Enabled with an empty `trusted_keys` is a configuration error. See
[configuration.md](configuration.md#rules-feed).

## Key management

- **Generate** on an offline machine: `panoptes-server rules keygen -out rules-signing.key`. The file
  (mode 0600, base64 of the ed25519 seed) is the private key; the command prints the public key
  (base64) and its `key_id`. It never overwrites an existing file.
- **Keep the private key offline** (encrypted removable media or a hardware-backed vault) and back it
  up. Anyone holding it can publish rules to every server that trusts the public key, and rules can
  request files from agents, so treat it like a release-signing key. Build in CI if you like, but sign
  on the offline machine.
- **Publish the public key** in your server configuration management (`rules.feed.trusted_keys`).
- **Rotation**: generate the new key, add its public key to `trusted_keys` next to the old one on every
  server and roll that out. Then sign new bundles with the new key. When every server has the new
  list and installed a bundle signed by the new key, remove the old key. A server accepts a bundle
  signed by any listed key. If the signing key leaks, ship a configuration without it; persisted
  bundles signed only by it are ignored at the next start.
- A lost private key means distributing a new `trusted_keys` entry to every server before the feed works
  again.

## Building and publishing

```sh
# in the rules repository: rules/*.yaml and tests/*.yaml (one test file per rule)
panoptes-server rules build -rules rules -tests tests -seq 43 -out dist
#   prints the SHA-256; any invalid, non-reviewed or untested rule, or failing test, produces no bundle
panoptes-server rules sign -key /offline/rules-signing.key dist/rules-43.tar.gz
#   writes dist/rules-43.tar.gz.sig and dist/latest.json
panoptes-server rules verify -pub <base64 public key> dist/rules-43.tar.gz     # optional check

# publish: upload the tarball and the .sig first, latest.json last
```

Upload `latest.json` last so servers never see a pointer to a missing file. `seq` must be higher than
every earlier bundle; `-created-at` (RFC 3339) or the `SOURCE_DATE_EPOCH` environment variable fixes
`created_at` for reproducible builds. `-min-server-version` sets `min_server_version`. In this
repository `make rules-bundle` builds the shipped rules (`RULES_SEQ=N`, optional `RULES_KEY=<file>` to
sign).

`keygen`, `build`, `sign` and `verify` need neither a server configuration nor a database.

## Air-gapped servers

Copy `rules-<seq>.tar.gz` and `rules-<seq>.tar.gz.sig` over your usual channel, then on the server:

```sh
panoptes-server rules import rules-43.tar.gz          # uses rules-43.tar.gz.sig; -sig <file> to override
panoptes-server rules status
```

`import` verifies against `rules.feed.trusted_keys`, applies the anti-rollback rule (the `seq` must be
higher than the installed one) and installs into `data_dir/rules-feed/`. A running server with
`rules.feed.enabled: true` activates it within a minute. For a fully offline server leave
`rules.feed.url` empty. A local mirror also works: `url: file:///srv/rules/latest.json`.

`rules status` prints the installed `seq`, the source, the rule and test counts, the last install and
poll times and the last error.

## Repository bot

Two commands help the rules repository's CI bot find and draft rules. Neither needs a server
configuration or database, and neither sends host data anywhere (there is none): only advisory and
candidate fields go to OSV, KEV, EPSS and the LLM provider.

### `rules candidates`

Selects CVEs worth a rule that the repository does not cover yet and prints a JSON array.

```sh
panoptes-server rules candidates -rules rules -packages packages.txt -max 20 -out candidates.json
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
| `-cache <dir>` | `$XDG_CACHE_HOME/panoptes-rules`, else the user cache dir, else a temporary directory | where the OSV bulk exports are kept between runs |
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
OSV re-modifies the record. Sorting: KEV first, then EPSS (batches of 100), then CVSS; `-max` caps the
list. A CVE appearing for the same package in several ecosystems is listed once (the first wins).
Each entry: `vuln, aliases, package, source, binary_packages, type, ecosystem, severity, cvss, epss,
kev, published`. `package` and `source` are the source package; `binary_packages` is best effort
(Debian records carry no binaries: it is `[package]`) and the draft does not depend on it. Further
limits: 8 MiB per API response, 30 s API timeouts, `User-Agent: panoptes-rules-bot`. Failures for
single packages are logged and skipped; exit 1 when every OSV source fails or KEV cannot be read.

Expected cost of a run with the six packages openssh, openssl, nginx, sudo, glibc and curl on the
default ecosystems: one download per ecosystem the first time, then a conditional request; well under
a minute once the cache is warm, with a handful of HTTP requests instead of the thousand the per-package
path needed.

### `rules draft`

Writes one rule and its tests for one candidate and prints a Markdown pull request body.

```sh
panoptes-server rules draft -candidate-file candidates.json -index 0 \
  -rules rules -tests tests -out-rules rules -out-tests tests > pr-body.md
```

Flags: `-candidate <json>` or `-candidate-file <file> -index N`; `-rules`, `-tests` (existing rules
and tests: few-shot examples and ID collision); `-out-rules`, `-out-tests` (default: `-rules`,
`-tests`); `-provider`, `-model`, `-base-url` (defaults from `PANOPTES_LLM_PROVIDER`,
`PANOPTES_LLM_MODEL`, `PANOPTES_LLM_BASE_URL`; key from `PANOPTES_LLM_API_KEY` or
`ANTHROPIC_API_KEY`; provider `anthropic` is assumed when only a key is set); `-max-attempts`
(default 2); `-osv-url`.

Keyless authentication. When neither `PANOPTES_LLM_API_KEY` nor `ANTHROPIC_API_KEY` is set, the
Anthropic SDK looks for workload identity federation credentials in the environment:
`ANTHROPIC_FEDERATION_RULE_ID`, `ANTHROPIC_ORGANIZATION_ID`, `ANTHROPIC_SERVICE_ACCOUNT_ID` and
`ANTHROPIC_IDENTITY_TOKEN_FILE` (optionally `ANTHROPIC_WORKSPACE_ID`). Then no API key is needed;
set `-provider anthropic` (or `PANOPTES_LLM_PROVIDER`) explicitly, because without a key the provider
is not inferred. Setup for the rules repository's workflow:
<https://github.com/DonSosiska/panoptes-rules/blob/main/docs/bot-setup.md>.

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
