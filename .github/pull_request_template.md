## What and why

<!-- One or two sentences. Link the issue if there is one. -->

## Checklist

- [ ] `go vet ./...`, `go test ./...` and `CGO_ENABLED=0 go build ./...` pass
- [ ] Tests added or updated for the behaviour change
- [ ] `docs/contracts.md` updated if a wire format, fact, limit or rule policy changed
- [ ] Documentation and `CHANGELOG.md` (Unreleased) updated
- [ ] No secrets, tokens or private hostnames in the diff
- [ ] I have read [CONTRIBUTING.md](../CONTRIBUTING.md); for code contributions I will sign the contributor license agreement the maintainer sends on my first pull request

## Security impact

<!-- Does this touch authentication, file.match, the agent's commands, TLS, the LLM prompt or the
release pipeline? If yes, explain how the change stays safe. Otherwise write "none". -->
