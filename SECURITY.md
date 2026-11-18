# Security Policy

## Reporting a vulnerability

Please do not open a public GitHub issue for security problems.

Report them privately through GitHub private vulnerability reporting. There are two repositories:

| What | Where to report |
|---|---|
| The Panoptes product: server, agent, rule engine, web UI, packages, release pipeline | [Report a vulnerability](https://github.com/DonSosiska/panoptes/security/advisories/new) (Security tab of [DonSosiska/panoptes](https://github.com/DonSosiska/panoptes)) |
| The rules feed: a wrong or malicious rule, the rules signing key, the feed hosting, the rules CI or bot | [Report a vulnerability](https://github.com/DonSosiska/panoptes-rules/security/advisories/new) (Security tab of [DonSosiska/panoptes-rules](https://github.com/DonSosiska/panoptes-rules)) |

If you are not sure which one applies, use the Panoptes repository. If a private reporting link does not
work, contact the [repository owner](https://github.com/DonSosiska) through GitHub without putting details
in a public place.

Include the affected version or commit, the steps to reproduce, and the impact as you understand it.

### What to expect

These are goals, not guarantees; this is a small project.

- We aim to acknowledge a report within 5 working days.
- For high and critical issues we aim to publish a fix or a mitigation plan within 30 days of the report.
  Lower severities are handled as time allows.
- We prefer coordinated disclosure: please give us the time above before publishing details. We credit
  reporters who want to be credited.

## Supported versions

Only the latest minor release line receives security fixes. Older releases do not; upgrade to the latest
release. Fixes land on `main` and ship in a new release.

| Version | Supported |
|---|---|
| Latest minor release | Yes |
| Older releases | No |

## Trust model

The full threat model, the operator hardening checklist and the known limitations are in
[docs/security-model.md](docs/security-model.md). Summary:

- The agent is split in two processes: a root collector with no network (it parses untrusted local
  files and serves the results on a unix socket, peer-checked with `SO_PEERCRED`) and an unprivileged
  sender (user `panoptes`) that is the only process talking to the server. Only `-mode all`
  (containers, `-once`, tests) runs both roles in one root process.
- Agentless mode (`local_agent.enabled`, off by default) lets the server monitor its own host. With
  `source: collector` privilege separation is kept: the root collector has no network and the server stays
  unprivileged. With `source: inprocess` the internet-facing server process itself runs the collectors and
  parses untrusted local files (with the server's privileges, so facts are less complete when it is not root);
  use it only for dev and single-box setups. The local agent reaches the API through an in-memory transport,
  so all API validation, limits and authentication apply to it as to any agent.
- The agent runs with root privileges on each host, so it treats the server as untrusted input.
- The server cannot run commands on a host. The agent runs only fixed argv commands with no shell.
- `file.match` reads are limited to an allowlist of configuration directories and a
  denylist of secret-looking paths. Secret-looking values are masked before they leave the host.
- The agent verifies the server's TLS chain and can pin the server (`ca_file` as the only trust
  root, `server_cert_sha256` SPKI pins, optional mTLS client certificate), so a network attacker
  or a rogue CA cannot impersonate the server.
- Enrollment tokens and agent keys are stored on the server only as SHA-256 hashes.
- There are no roles in the web UI: every account is a full administrator. Keep the admin listener on a
  trusted network.
- The optional central rules feed is trusted only through its signature. Rules come from the
  [panoptes-rules](https://github.com/DonSosiska/panoptes-rules) repository (the trust root: reviewed pull
  requests, a protected `rules-release` environment with a required reviewer, release only from the tip of
  `main`); servers install a bundle only if it is signed by a key in `rules.feed.trusted_keys`, newer than the
  installed one, fetched from the pointer's own host, and valid and tested rule by rule. A feed rule can
  change verdicts and request reads of configuration files, which agents re-check against their own policy.
  If the signing key is exposed, operators remove it from `trusted_keys`. See
  [docs/rules-feed.md](docs/rules-feed.md) and [docs/security-model.md](docs/security-model.md#the-rules-feed-trust-chain).
- LLM output is never trusted. An LLM-drafted rule is inert until a human reviews and approves it, and it
  never lowers a verdict. Drafts are AI-assisted and can be wrong: review them.
- Releases are signed with keyless Sigstore (cosign), ship SBOMs, and have build provenance
  attestations. See [docs/installation.md](docs/installation.md#verifying-releases).
- Build and CI inputs are pinned: GitHub Actions to commit SHAs, and base images to digests.

## Release integrity

Releases are made only by the release workflow (`.github/workflows/release.yml`), and only
after its tests pass. The release job runs in the `release` environment, so a designated
reviewer must approve each release. Tags must point at a commit on `main`; the workflow
refuses any other tag. Artifacts are signed keyless with Sigstore, and the signing identity
is the exact workflow path and tag. The Linux packages (`.deb`, `.rpm`) are not apt- or
rpm-signed, so verify `checksums.txt` against its signature and then check the package
checksums. See [docs/installation.md](docs/installation.md#verifying-releases) for the exact commands.

## License

Panoptes is source-available under the PolyForm Noncommercial License 1.0.0 (see [LICENSE](LICENSE)).
Reporting a vulnerability does not change the license terms.
