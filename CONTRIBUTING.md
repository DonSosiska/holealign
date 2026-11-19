# Contributing

Thanks for helping. Holealign is open source under the
[AGPL-3.0-only](LICENSE) license and is also offered under other terms (see
[License of contributions](#license-of-contributions)). Please read this page before opening an issue or a
pull request.

## Reporting bugs

Open an issue with the **Bug report** template. Include the version (`holealign-server -version`,
`holealign-agent -version`), how you run it (Docker, package, binary), the distribution of the affected
host, the relevant log lines (`journalctl -u holealign-server`, `holealign-agent`, `holealign-collector`) and
the steps to reproduce. Remove tokens, keys and anything private first.

**Security problems are not bug reports.** Do not open a public issue. Use GitHub's private reporting as
described in [SECURITY.md](SECURITY.md).

## Where things go

Holealign has two repositories:

| You want to | Where |
|---|---|
| Fix or extend code: server, agent, rule engine, web UI, a new **fact**, a new CEL function, the installer, the docs | this repository, [DonSosiska/holealign](https://github.com/DonSosiska/holealign) |
| Add or fix a **rule** for a CVE (YAML plus tests) for everyone | [DonSosiska/holealign-rules](https://github.com/DonSosiska/holealign-rules): a pull request with `rules/<id>.yaml` and `tests/<id>.yaml` |
| Change one of the eight rules shipped in the binary | **both** repositories: `rules/` and `rules-tests/` here, the same files in the rules repository (its CI requires them to be byte-identical) |
| Write rules only for your own servers | your own `rules_dir`, the web UI, or [your own feed](docs/rules-feed.md#running-your-own-feed) |
| Report a wrong or malicious rule from the feed | [holealign-rules](https://github.com/DonSosiska/holealign-rules) (private reporting for anything security-relevant) |

Rule authoring is documented in [docs/rules.md](docs/rules.md). A rule that needs a fact that does not
exist yet starts as a code change here (a collector in `internal/agent/facts/`, the catalog entry and a
description, the contract) and only then becomes a rule.

## Proposing changes

- For anything larger than a small fix, open an issue (**Feature request**) first and describe the
  problem you want to solve, so we can agree on the approach before you write code.
- Small fixes and documentation can go straight to a pull request.
- Keep a pull request focused on one thing and fill in the pull request template.
- A change to a wire format, a fact, a limit or the rule policy must update
  [docs/contracts.md](docs/contracts.md) in the same pull request (it is the source of truth). Add tests
  for behaviour changes and update the documentation and [CHANGELOG.md](CHANGELOG.md) (the `Unreleased`
  section).
- Changing a fact, a fact description or a shipped rule also affects the rules repository: see
  [Bumping the rules repository](docs/development.md#bumping-the-rules-repository).

## Development setup and tests

Set-up, repository layout, the constraints you must respect (the agent never runs a shell, the SQLite
driver split, treat external text as hostile) and the release process are in
[docs/development.md](docs/development.md). Before you submit, run:

```sh
go vet ./...
go test ./...
CGO_ENABLED=0 go build ./...
```

Also, depending on what you touched:

```sh
go test -race -timeout 30m ./internal/server/web/   # the web package is slow; run it with the race detector
go test -race ./internal/server/api/ ./internal/server/pipeline/ ./internal/server/notify/
bash scripts/govulncheck.sh                          # needs govulncheck and jq
shellcheck deploy/install.sh deploy/e2e/*.sh scripts/*.sh   # if you touched shell scripts
deploy/e2e/run.sh                                    # end to end, needs Docker; for agent, API or alerting changes
```

Agent tests that use `//go:build linux` need a Linux machine or container; see
[docs/development.md](docs/development.md#tests).

## Commit messages

Short imperative subject in the style `Area: what changed`, at most about 72 characters, with a body when
the reason is not obvious (what was wrong, why this fix). Examples from the history:
`Agent hardening: FIFO-safe opens, symlink-aware tree trust, nginx data blocks`,
`API tests: wait for the decode slot to be released before the follow-up upload`. One logical change per
commit; do not mix a refactor with a fix.

## License of contributions

Holealign is dual-licensed: it is available to everyone under the GNU Affero General Public License v3.0 only (AGPL-3.0-only), and
the author also offers it under other terms, for example a commercial license. To make that possible,
**code contributions from external contributors require agreeing to a contributor license agreement (CLA)
before they are merged.** The maintainer will send it on your first pull request; there is nothing to sign
before you open one. The agreement:

1. **Inbound = outbound.** Your contribution is licensed to the project and its users under the same
   license as the project, the AGPL-3.0-only.
2. **Right to relicense.** The author may also offer the project, including your contribution, under other
   terms, for example a commercial license. You grant the author a perpetual, worldwide, non-exclusive,
   royalty-free right to use, modify, sublicense and relicense your contribution under any terms, including
   commercial ones.
3. You wrote the contribution or have the right to submit it under these terms, and it does not contain code
   you are not allowed to share.

If you cannot agree to this, please do not submit code; an issue describing the idea is still welcome.
Contributions to the separate rules repository follow the terms in its own `CONTRIBUTING.md`.

## Conduct

Be respectful. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
