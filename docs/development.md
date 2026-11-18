# Development

How the repository is organised, how to build and test it, the constraints that keep the design
safe, and how a release is made. If you want to contribute, read [CONTRIBUTING.md](../CONTRIBUTING.md)
too. The protocol and interfaces are defined in [contracts.md](contracts.md), which is the source of
truth.

Contents: [Repository layout](#repository-layout) - [Building](#building) - [Tests](#tests) -
[Coding constraints](#coding-constraints) - [Release process](#release-process)

## Repository layout

| Path | Contents |
|---|---|
| `cmd/panoptes-agent/` | Agent entry point: `-mode all\|collector\|sender`, `-once`, `-print-facts`, `-print-inventory`, `-print-server-pin` |
| `cmd/panoptes-server/` | Server entry point and CLI: `serve`, `token`, `host`, `user`; listeners, TLS, privilege drop, retention job |
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
| `internal/server/rulesbot/` | `rules candidates` / `rules draft`: CVE selection (OSV, KEV, EPSS, CVSS v3) and LLM rule drafting for the rules repository bot (see [rules-feed.md](rules-feed.md#repository-bot)) |
| `internal/server/store/` | SQLite store and migrations |
| `internal/server/web/` | Admin web UI: templates, static files, auth |
| `internal/server/config/`, `clientip/`, `core/` | Server configuration, client address handling, interfaces between components |
| `rules/`, `rules-tests/` | The eight shipped rules (embedded in the binary by `rules/embed.go`) and their test cases |
| `deploy/` | `install.sh`, systemd units, nfpm scripts, Dockerfiles, Compose file, example configs, e2e harness |
| `docs/` | This documentation and `contracts.md` |
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
| Unit | `go test ./...` | This is what CI runs, after `go vet ./...`, `go build ./...` and `bash scripts/govulncheck.sh`. |
| Linux-only | `go test ./internal/agent/...` on Linux | Some tests use `//go:build linux` (symlink-safe opens, ancestor permission checks). On macOS or Windows, run them in a Linux container, for example `docker run --rm -v "$PWD":/src -w /src golang:1.27.4 go test ./internal/agent/...`. |
| Matcher integration | `PANOPTES_TEST_GRYPE_DB=<dir> go test -tags integration ./internal/server/match/` | Needs a Grype DB; skips when none is available. |
| Shell checks | `sh -n deploy/install.sh`, `shellcheck deploy/install.sh deploy/e2e/*.sh` | Also in CI. |
| End to end | `deploy/e2e/run.sh` | Docker Compose: a Matrix homeserver, the server, three Debian hosts with the real agent; asserts alerts, routing, dedup, the fix flow and the web login. Needs Docker, `curl`, `jq`, `openssl`. See [deploy/e2e/README.md](../deploy/e2e/README.md). |
| Privilege separation | `deploy/e2e/split-mode.sh` | Runs the collector as root and the sender as `panoptes` in a container against a fake server; checks that facts and inventory arrive through the socket and that the sender user cannot read `/etc/shadow`. |

Add a unit test for every behaviour change; rules get cases in `internal/server/rules/engine_test.go`
(shipped rules are loaded by that test), and parsers get fixtures under
`internal/agent/facts/testdata/`.

**Vulnerability check.** `make vulncheck` (also run in CI) builds `panoptes-agent` and `panoptes-server` and runs `govulncheck -mode=binary` on each. Source-mode `govulncheck ./...` does not finish in CI, so it is not used. The check fails on any finding not listed in `.govulncheck-allow` for that binary. Entries are per binary: to accept a finding that has no fix, add a line `ID panoptes-agent  # reason, reviewed YYYY-MM-DD` (or `panoptes-server`); a finding allowed for the agent still fails if it shows up in the server. to drop one, delete its line once it is no longer reported (the script warns about stale entries). Review each entry at least when its date is old, and always after a dependency upgrade.

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

## Release process

Releases are made by the release workflow ([.github/workflows/release.yml](../.github/workflows/release.yml))
using [GoReleaser](../.goreleaser.yaml). You do not build releases locally.

1. Merge to `main` and wait for CI (`go vet`, `go test`, `go build`, vulnerability check, shell checks).
2. Tag a commit that is on `main` and push the tag: `git tag vX.Y.Z && git push origin vX.Y.Z`.
3. The workflow re-runs the checks (`test` job). The `goreleaser` job then **waits for approval**
   because it runs in the `release` environment; a designated reviewer approves it in the GitHub
   Actions UI.
4. The job refuses any tag that is not an ancestor of `origin/main`, then builds linux amd64 and
   arm64 archives, `.deb` and `.rpm` packages, SPDX SBOMs (Syft) and `checksums.txt`; signs
   `checksums.txt` and the container images with keyless cosign; pushes the multi-arch image
   `ghcr.io/donsosiska/panoptes-server:X.Y.Z` (and `latest` for final releases, not for
   pre-releases such as `-rc1`); and attests build provenance for the archives and packages.
5. Verify the result with [the commands in installation.md](installation.md#verifying-releases).
   Update [CHANGELOG.md](../CHANGELOG.md).

One-time repository settings (Settings, Environments, `release`): required reviewers, and deployment
restricted to protected `v*` tags; also tag protection for `v*` and branch protection on `main`.
Tooling versions (cosign, Syft, GoReleaser) are pinned in the workflow; upgrade them deliberately.
Action versions and base-image digests are pinned and updated by Dependabot.
