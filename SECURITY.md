# Security Policy

## Reporting a vulnerability

Please do not open a public GitHub issue for security problems.

Report them privately by email to **security@OWNER.example**. <!-- TODO: replace with the real security contact before publishing -->
If GitHub private vulnerability reporting is enabled for the repository, you can use
that instead (Security tab, "Report a vulnerability").

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

- The agent runs as root on each host, so it treats the server as untrusted input.
- The server cannot run commands on a host. The agent runs only fixed argv commands with no shell.
- `file.match` reads are limited to an allowlist of configuration directories and a
  denylist of secret-looking paths. Secret-looking values are masked before they leave the host.
- Enrollment tokens and agent keys are stored on the server only as SHA-256 hashes.
- LLM output is never trusted. An LLM-drafted rule is inert until a human reviews and approves it.
- Releases are signed with keyless Sigstore (cosign), ship SBOMs, and have build provenance
  attestations. See README.md, "Verifying releases".
- Build and CI inputs are pinned: GitHub Actions to commit SHAs, and base images to digests.
