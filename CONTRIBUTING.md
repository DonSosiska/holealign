# Contributing

Thanks for helping. Panoptes is source-available under the
[PolyForm Noncommercial License 1.0.0](LICENSE). Please read this page before opening an issue or a
pull request.

## Reporting bugs

Open an issue with the **Bug report** template. Include the version (`panoptes-server -version`,
`panoptes-agent -version`), how you run it (Docker, package, binary), the distribution of the
affected host, the relevant log lines (`journalctl -u panoptes-server`, `panoptes-agent`,
`panoptes-collector`) and the steps to reproduce. Remove tokens, keys and anything private first.

**Security problems are not bug reports.** Do not open a public issue. Use GitHub's private
reporting as described in [SECURITY.md](SECURITY.md).

## Proposing changes

- For anything larger than a small fix, open an issue (**Feature request**) first and describe the
  problem you want to solve, so we can agree on the approach before you write code.
- Small fixes, documentation and new or improved rules can go straight to a pull request.
- Keep a pull request focused on one thing and fill in the pull request template.

Before you submit, run:

```sh
go vet ./...
go test ./...
CGO_ENABLED=0 go build ./...
```

and, if you touched shell scripts, `shellcheck deploy/install.sh deploy/e2e/*.sh`. How to build and
test, the repository layout and the constraints you must respect (`docs/contracts.md` is the source
of truth, the agent never runs a shell, the SQLite driver split) are in
[docs/development.md](docs/development.md). A change to a wire format, a fact, a limit or the rule
policy must update [docs/contracts.md](docs/contracts.md) in the same pull request. Add tests for
behaviour changes and update the documentation and [CHANGELOG.md](CHANGELOG.md) (the `Unreleased`
section).

For a new rule: follow [docs/rules.md](docs/rules.md), keep it reachability-based and as simple as
the advisory allows, and add a test case.

## License of contributions

By submitting a contribution (a pull request, a patch or any other code or documentation) you agree
that:

1. **Inbound = outbound.** Your contribution is licensed to the project and its users under the same
   license as the project, the PolyForm Noncommercial License 1.0.0.
2. **Right to relicense.** The author may also offer the project, including your contribution, under
   other terms, for example a commercial license. You grant the author a perpetual, worldwide,
   non-exclusive, royalty-free right to use, modify, sublicense and relicense your contribution
   under any terms, including commercial ones.
3. You wrote the contribution or have the right to submit it under these terms, and it does not
   contain code you are not allowed to share.

If you cannot agree to this, please do not submit code; an issue describing the idea is still
welcome.

## Conduct

Be respectful. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
