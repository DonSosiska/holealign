# Security Policy

## Reporting a vulnerability

Please do not open a public GitHub issue for security problems.

Report them privately through GitHub private vulnerability reporting: open the
[Security tab](https://github.com/DonSosiska/panoptes/security/advisories/new) of the
repository and choose "Report a vulnerability".

Include the affected version or commit, the steps to reproduce, and the impact as you
understand it. We aim to acknowledge reports within a few working days.
<!-- TODO: state the response and disclosure timeline the maintainers commit to. -->

## Supported versions

<!-- TODO: confirm this policy. Assumed: only the latest tagged release (v*) receives fixes. -->

| Version         | Supported |
|-----------------|-----------|
| Latest release  | Yes       |
| Older releases  | No        |

## Trust model

- The agent is split in two processes: a root collector with no network (it parses untrusted local
  files and serves the results on a unix socket, peer-checked with `SO_PEERCRED`) and an unprivileged
  sender (user `panoptes`) that is the only process talking to the server. Only `-mode all`
  (containers, `-once`, tests) runs both roles in one root process.
- The agent runs with root privileges on each host, so it treats the server as untrusted input.
- The server cannot run commands on a host. The agent runs only fixed argv commands with no shell.
- `file.match` reads are limited to an allowlist of configuration directories and a
  denylist of secret-looking paths. Secret-looking values are masked before they leave the host.
- The agent verifies the server's TLS chain and can pin the server (`ca_file` as the only trust
  root, `server_cert_sha256` SPKI pins, optional mTLS client certificate), so a network attacker
  or a rogue CA cannot impersonate the server.
- Enrollment tokens and agent keys are stored on the server only as SHA-256 hashes.
- LLM output is never trusted. An LLM-drafted rule is inert until a human reviews and approves it.
- Releases are signed with keyless Sigstore (cosign), ship SBOMs, and have build provenance
  attestations. See README.md, "Verifying releases".
- Build and CI inputs are pinned: GitHub Actions to commit SHAs, and base images to digests.

## Release integrity

Releases are made only by the release workflow (`.github/workflows/release.yml`), and only
after its tests pass. The release job runs in the `release` environment, so a designated
reviewer must approve each release. Tags must point at a commit on `main`; the workflow
refuses any other tag. Artifacts are signed keyless with Sigstore, and the signing identity
is the exact workflow path and tag. The Linux packages (`.deb`, `.rpm`) are not apt- or
rpm-signed, so verify `checksums.txt` against its signature and then check the package
checksums. See README.md, "Verifying releases", for the exact commands.
