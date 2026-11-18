# Development

How the repository is organised, how to build and test it, the constraints that keep the design
safe, and how a release is made. If you want to contribute, read [CONTRIBUTING.md](../CONTRIBUTING.md)
too. The protocol and interfaces are defined in [contracts.md](contracts.md), which is the source of
truth.

Contents: [Repository layout](#repository-layout) - [Building](#building) - [Tests](#tests) -
[Vulnerability check](#vulnerability-check) - [Coding constraints](#coding-constraints) -
[Bumping the rules repository](#bumping-the-rules-repository) - [Release process](#release-process)

## Repository layout

| Path | Contents |
|---|---|
| `cmd/panoptes-agent/` | Agent entry point: `-mode all\|collector\|sender`, `-once`, `-print-facts`, `-print-inventory`, `-print-server-pin` |
| `cmd/panoptes-server/` | Server entry point and CLI: `serve`, `token`, `host`, `user`, `rules ...`; listeners, TLS, privilege drop, retention job ([api.md](api.md#panoptes-server)) |
| `internal/model/` | Types shared by agent and server (wire format, findings, rules, events). A change here is a contract change. |
| `internal/agent/collector/` | Root collector: unix socket server, peer-credential check |
| `internal/agent/hostdata/` | The facts and inventory source: local (in-process) or the collector client |
| `internal/agent/facts/` | Fact collectors (sshd, nginx, Apache, PHP, kernel, sockets, services, Docker, `file.match`), command runner, trust checks |
| `internal/agent/inventory/` | Syft scanning of the host and of Docker images, change detection |
| `internal/agent/runner/` | Enroll, check-in loop, back-off and clamping |
| `internal/agent/transport/`, `config/` | HTTPS client with CA/pin/mTLS; agent configuration |
| `internal/server/api/` | Agent HTTP API, rate limits, validation |
| `internal/server/pipeline/` | Match, evaluate, diff, notify |
| `internal/server/match/` | Grype wrapper |
| `internal/server/rules/` | Rule loading, validation, the CEL engine, the fact catalog, `file.match` policy |
| `internal/server/llm/` | Providers (Anthropic, OpenAI-compatible), drafter, prompts, OSV advisory source |
| `internal/server/notify/` | Matrix notifier, grouping, rendering |
| `internal/server/health/` | Silence, feed and pipeline alerts; delivery-problem recorder |
| `internal/server/feeds/` | Vulnerability DB updater |
| `internal/server/rulesfeed/` | Signed central rules feed: bundle build/open, ed25519 signing, poller, persisted bundle |
| `internal/server/rulesbot/` | `rules candidates` / `rules draft` / `rules eval`: CVE selection (OSV, KEV, EPSS, CVSS v3), LLM rule drafting for the rules repository bot, and the drafting evaluation harness (see [rules-feed.md](rules-feed.md#repository-bot)) |
| `internal/server/store/` | SQLite store and migrations |
| `internal/server/web/` | Admin web UI: templates, static files, auth |
| `internal/server/config/`, `clientip/`, `core/` | Server configuration, client address handling, interfaces between components |
| `rules/`, `rules-tests/` | The eight shipped rules (embedded in the binary by `rules/embed.go`) and their test cases |
| `deploy/` | `install.sh`, systemd units, nfpm scripts, Dockerfiles, Compose file, example configs, e2e harness |
| `docs/` | This documentation; `contracts.md` is the normative contract, `api.md` the readable API reference |
| `scripts/` | `govulncheck.sh` (binary-mode vulnerability check) |
| `.goreleaser.yaml`, `.github/workflows/` | Release and CI |

## Building

Go 1.27.4 (see `go.mod`). Binaries are built with `CGO_ENABLED=0`.

```sh
make build              # binaries in bin/
CGO_ENABLED=0 go build ./...
make docker             # server image from source (deploy/Dockerfile.server.build)
make release-snapshot   # local goreleaser dry run: archives, .deb/.rpm, checksums (needs goreleaser)
```

`make vet`, `make lint` (runs `staticcheck` when installed) and `make tidy` are also available.

## Tests

| Kind | Command | Notes |
|---|---|---|
| Unit | `go test ./...` | What CI runs, after `go vet ./...`, `go build ./...` and `bash scripts/govulncheck.sh`. |
| Race detector | `go test -race ./...` | Slow for the whole tree; run it for the packages you changed. |
| Web UI package | `go test -race -timeout 30m ./internal/server/web/` | The slowest package. The default 10 minute timeout can be too short under `-race`; give it 30 minutes. |
| Linux-only | `go test ./internal/agent/...` on Linux | Some tests use `//go:build linux` (symlink-safe opens, ancestor permission checks). On macOS or Windows, run them in a Linux container, for example `docker run --rm -v "$PWD":/src -w /src golang:1.27.4 go test ./internal/agent/...`. |
| Rules | `go test ./internal/server/rules/ ./internal/server/rulesfeed/` | Loads the shipped rules and runs every `rules-tests/*.yaml` through the real engine; feed bundle build, signing and verification. |
| Drafting evaluation | `panoptes-server rules eval -rules rules -tests rules-tests -ids <a,b> -runs 1 -variants claude-haiku-5-5@medium` | Not part of CI and **spends real money**: drafts the reference rules with the listed models and scores them against the reference tests (metrics in [rules-feed.md](rules-feed.md#rules-eval)). Its unit tests use a fake provider and make no network calls. |
| Matcher integration | `PANOPTES_TEST_GRYPE_DB=<dir> go test -tags integration ./internal/server/match/` | Needs a Grype DB; skips when none is available. |
| Shell checks | `sh -n deploy/install.sh`, `shellcheck deploy/install.sh deploy/e2e/*.sh scripts/govulncheck.sh` | Also in CI. |
| End to end | `deploy/e2e/run.sh` | Docker Compose: a Matrix homeserver, the server, three Debian hosts with the real agent; asserts alerts, routing, dedup, the fix flow and the web login. Needs Docker, `curl`, `jq`, `openssl`. See below. |
| Privilege separation | `deploy/e2e/split-mode.sh` | Runs the collector as root and the sender as `panoptes` in a container against a fake server; checks that facts and inventory arrive through the socket and that the sender user cannot read `/etc/shadow`. |

Add a unit test for every behaviour change. Rules get cases in `rules-tests/` (and a test in
`internal/server/rules/` for engine behaviour); parsers get fixtures under
`internal/agent/facts/testdata/`.

### End-to-end harness

`deploy/e2e/run.sh` needs no arguments. Environment variables (full list and the assertions:
[deploy/e2e/README.md](../deploy/e2e/README.md)):

| Variable | Default | Meaning |
|---|---|---|
| `GRYPE_DB_CACHE` | unset | Host directory with a ready Grype DB (contains `6/vulnerability.db`); skips the ~100 MB download and disables feed updates. |
| `E2E_WAIT_TIMEOUT` | `180` | Seconds to wait for the first alerts. |
| `E2E_KEEP` | `0` | `1` leaves the stack running (otherwise `docker compose down -v` runs on exit). |
| `E2E_MATRIX_PORT`, `E2E_SERVER_PORT`, `E2E_ADMIN_PORT` | `18008`, `18080`, `18081` | Host ports, bound to 127.0.0.1. |
| `E2E_ADMIN_PASSWORD`, `E2E_OBSERVER_PASSWORD`, `E2E_REG_TOKEN` | random per run | Override so a kept stack can be logged into. |
| `E2E_LOCAL_AGENT` | `true` | Enables the built-in local agent in the server container. |
| `E2E_LLM_PROVIDER`, `E2E_LLM_BASE_URL`, `E2E_LLM_MODEL`, `E2E_LLM_DAILY_LIMIT` | `none`, empty, `claude-sonnet-5-5`, `50` | Run the stack with an LLM drafter (for example a local OpenAI-compatible server). |
| `MATRIX_IMAGE` | `ghcr.io/continuwuity/continuwuity:latest` | Alternative homeserver image. |

## Vulnerability check

`make vulncheck` (also run in CI and by the release workflow) is `bash scripts/govulncheck.sh`: it builds
`panoptes-agent` and `panoptes-server` and runs `govulncheck -mode=binary` on each (needs `govulncheck` and
`jq`; CI installs `golang.org/x/vuln/cmd/govulncheck@v1.9.0`). Source-mode `govulncheck ./...` does not finish
in CI, so it is not used. The check fails on any finding that is not listed in `.govulncheck-allow` **for that
binary**.

Format of `.govulncheck-allow` (one entry per line; `#` starts a comment; blank lines ignored):

```
ID BINARY  # reason, reviewed YYYY-MM-DD
GO-2026-6905 panoptes-agent  # github.com/blakesmith/ar via Syft deb parser; no upstream fix; reviewed 2026-11-17
GO-2026-6905 panoptes-server # same module via Syft; no upstream fix; reviewed 2026-11-18
```

`BINARY` is `panoptes-agent` or `panoptes-server`. A line with only an ID is rejected as malformed. A finding
allowed for the agent still fails if it shows up in the server, so each binary is reviewed separately.
Accept a finding only when it has no fix (or the fix is not available yet), explain why it is not reachable or
mitigated, and date the review. Delete a line as soon as the finding is no longer reported (the script warns
about stale entries). Re-review entries at least when their date is old, and always after a dependency
upgrade.

## Coding constraints

- **`docs/contracts.md` is the source of truth.** If you change a wire format, a rule policy, a
  fact or a limit, change the Go types in `internal/model` (or the code) **and** the contract in the
  same change.
- **The agent never runs a shell** and only runs hard-coded commands with fixed argv, a timeout and
  capped output, from root-owned trusted binaries. The server must not be able to widen that.
- **Collector code must not import the HTTP transport.** A test (`go list -deps`) enforces it.
- **Never import agent packages from the server or the reverse**, except `internal/model`.
- **SQLite driver split.** The server uses `github.com/glebarez/go-sqlite` (Grype already links it and
  registers the driver name `sqlite`). Importing `modernc.org/sqlite` in any server package panics at
  start-up ("Register called twice"). The agent does not link Grype and imports `modernc.org/sqlite`
  for Syft's RPM cataloger.
- **Treat all external text as hostile**: hostnames, package names, advisory text, LLM output. Cap
  and clean it before it reaches the database, a prompt, the web UI or Matrix.
- **Bounded everything**: sizes, counts, time, concurrency.
- Keep the agent small and dependency-light; keep new server dependencies to what is needed.
- Documentation and comments are English. Do not add marketing language to docs.

## Bumping the rules repository

The rules repository ([panoptes-rules](https://github.com/DonSosiska/panoptes-rules)) builds, tests and signs
bundles with a `panoptes-server` built from this repository at the commit in its `PANOPTES_REF` file. That
commit must be on `main` here. When a change here affects rules, update the rules repository as well:

| You changed here | Do in the rules repository |
|---|---|
| A **fact** (name, format, new fact), a fact description, the CEL environment, `file.match` policy | Wait until the change is on `main` here. Bump `PANOPTES_REF` to a commit that contains it (`git ls-remote https://github.com/DonSosiska/panoptes refs/heads/main`), open a pull request; its validation rebuilds with the new binary. Then add rules that use the new fact. |
| One of the eight **shipped rules** (`rules/`, `rules-tests/`) | Apply the identical change to `rules/` and `tests/` there; its CI fails when the copies differ. Bump `PANOPTES_REF` first if the change needs engine support. |
| The **bundle format** or the validation rules | Bump `PANOPTES_REF`; consider `min_server_version`, because servers that are older than a bundle's requirement ignore it. |

A bundle whose `catalog` lists a fact an older server does not know is rejected by that server as a whole
(it keeps its previous bundle and asks to be upgraded), so release the code first, and tell operators, before
publishing rules that depend on it. Fact descriptions live in `factDescriptions` in
`cmd/panoptes-server/main.go` and feed the LLM prompt (a test requires one per catalog fact except `agent.*`);
update them together with [contracts.md](contracts.md#3-fact-catalog) and [rules.md](rules.md#fact-catalog).
`PANOPTES_REF` is a full 40-character SHA, not managed by Dependabot.

## Release process

Releases are made by the release workflow ([.github/workflows/release.yml](../.github/workflows/release.yml))
using [GoReleaser](../.goreleaser.yaml). You do not build releases locally.

1. Merge to `main` and wait for CI (`go vet`, `go test`, `go build`, vulnerability check, shell checks).
2. Tag a commit that is on `main` and push the tag: `git tag vX.Y.Z && git push origin vX.Y.Z`. The workflow
   runs on tags matching `v*`.
3. The workflow re-runs the checks (`test` job). The `goreleaser` job then **waits for approval** because it
   runs in the protected `release` environment; a designated reviewer approves it in the GitHub Actions UI.
4. The job refuses any tag that is not an ancestor of `origin/main`, then builds linux amd64 and arm64
   archives, `.deb` and `.rpm` packages, SPDX SBOMs (Syft) and `checksums.txt`; signs `checksums.txt` and the
   container images with keyless **cosign**; pushes the multi-arch image
   `ghcr.io/donsosiska/panoptes-server:X.Y.Z` (and `latest` for final releases, not for pre-releases such as
   `-rc1`); and attests build **provenance** for the archives and packages.
5. Verify the result with [the commands in installation.md](installation.md#verifying-releases). Update
   [CHANGELOG.md](../CHANGELOG.md).

The `.deb` and `.rpm` packages are not apt- or rpm-signed; their integrity rests on the signed
`checksums.txt`.

One-time repository settings (Settings, Environments, `release`): required reviewers, and deployment
restricted to protected `v*` tags; also tag protection for `v*` and branch protection on `main`. Tooling
versions (cosign, Syft, GoReleaser) are pinned in the workflow; upgrade them deliberately. Action versions and
base-image digests are pinned and updated by Dependabot. The rules feed has its own, separate release path
in the rules repository ([rules-feed.md](rules-feed.md#how-the-public-feed-is-built-and-signed)); releasing
Panoptes does not publish rules and publishing rules does not release Panoptes.
