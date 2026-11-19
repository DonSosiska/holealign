# Holealign

[![ci](https://github.com/DonSosiska/holealign/actions/workflows/ci.yml/badge.svg)](https://github.com/DonSosiska/holealign/actions/workflows/ci.yml)
License: [AGPL-3.0-only](LICENSE) (open source)

English | [Українська](README.uk.md)

> The name comes from the Swiss cheese model of failures: every layer of defence has holes, and an
> incident happens only when the holes in all layers line up. A vulnerable package is one hole, an
> enabled feature another, an exposed configuration a third. Holealign tells you when they align.

Holealign finds vulnerabilities on Linux hosts and decides whether each one is **actually
exploitable given that host's configuration**. Agents on your hosts push a software inventory
(SBOM) and a set of configuration facts to a central server. The server matches vulnerabilities
with Grype (including CISA KEV and EPSS data), evaluates CEL rules against the facts, and alerts
Matrix/Element rooms chosen by host labels. It is one binary plus one SQLite file, with no external
database.

## The problem

A scanner that compares package versions with vulnerability data reports hundreds of findings per
host, and most of them cannot be exploited where they run: the vulnerable feature is off, the port is
not open, the libc is different. Teams either drown in the list or stop reading it, and the one
finding that matters is lost among the rest.

## How Holealign is different

Holealign also reads the host. regreSSHion (CVE-2024-6387) is exploitable only on glibc systems
where `LoginGraceTime` is not `0`. On a musl host, or with `LoginGraceTime 0`, the finding is
recorded as `affected_not_exploitable` and nobody gets paged. When Holealign cannot tell (no rule,
or a fact is missing) the verdict is `conditions_unknown`, never "safe". Rules that do not exist
yet can be drafted by an LLM; a draft stays inert, and can never lower a verdict, until a human
approves it.

```
 host: collector (root, no network) -> sender -- HTTPS, outbound only --> server
                                                                           |
        SBOM (Syft)  +  facts (sshd -T, nginx -T, sysctl, sockets, ...)    |
                                                                           v
   Grype + KEV + EPSS  ->  rules (CEL) on this host's facts  ->  verdict  ->  web UI + Matrix
```

| Verdict | Meaning |
|---|---|
| `exploitable` | Package is vulnerable and the rule's conditions hold on this host. Alerts. |
| `affected_not_exploitable` | Package is vulnerable, conditions are not met or are mitigated. |
| `conditions_unknown` | No rule, or a required fact is missing, or the rule failed to evaluate. |
| `not_affected` | A rule says the package is not affected at all. |
| `resolved` | The finding disappeared (package upgraded or removed). |

## Features

- Privilege-separated agent: a root collector with no network access, and an unprivileged sender
  that is the only process talking to the server.
- Host and container-image inventory (Syft), OS and language packages.
- Vulnerability matching with Grype; KEV and EPSS shown and used for ordering and alerts.
- Configuration facts: sshd, nginx, Apache, PHP, kernel sysctl and modules, listening sockets,
  services, Docker containers, and bounded `file.match` reads. Catalog: [docs/rules.md](docs/rules.md#fact-catalog).
- CEL rules, eight shipped. Verdicts and the draft guard: [docs/rules.md](docs/rules.md).
- Optional signed central rules feed (ed25519, atomic verification, air-gapped import):
  [docs/rules-feed.md](docs/rules-feed.md).
- Optional LLM rule drafting (Anthropic or any OpenAI-compatible endpoint such as Ollama):
  [docs/llm.md](docs/llm.md).
- Matrix, Slack, Telegram, Discord, Teams, signed webhook and email alerts routed by host label, with dedup, grouping and burst summaries:
  [docs/notifications.md](docs/notifications.md).
- Admin web UI: hosts, findings grouped per CVE with "needs attention" and "background" tiers,
  rule review, enrollment tokens, notification routes, users: [docs/user-guide.md](docs/user-guide.md).
- Health alerts: silent agents, stale vulnerability feed, failing pipeline.
- Agentless mode: the server monitors its own host: [docs/installation.md](docs/installation.md#agentless-mode).
- Signed releases: cosign signatures, SBOMs, build provenance.

## Architecture

```
  Monitored Linux host (any number)                Holealign server
 +-------------------------------------+        +----------------------------------------+
 | holealign-collector (root, NO network)|        | agent API  :8080  /api/v1/*  /healthz  |
 |   sshd -T, nginx -T, sysctl, /proc, |        |   enroll, check-in, inventory          |
 |   Syft scan, file.match             |        |                                        |
 |        |  unix socket               | HTTPS  | SQLite + Grype DB      (data_dir)      |
 | holealign-agent sender (user         |------->| pipeline: Grype -> CEL rules -> verdict|
 |   "holealign", the only one with     | push,  |                                        |
 |   network access)                   | out-   | admin UI   :8081  (loopback default)   |
 +-------------------------------------+ bound  |        ^  SSH tunnel / VPN / proxy     |
   no inbound connection to the host     only   |        |                               |
                                                | Matrix notifier ---> Matrix rooms      |
                                                | LLM drafter (optional) ---> LLM API    |
                                                +----------------------------------------+
```

Details: [docs/architecture.md](docs/architecture.md).

## Requirements

- Monitored hosts: Linux on amd64 or arm64 with systemd (for the installer and packages), and an
  OS package database that Syft and Grype understand (dpkg, rpm, apk).
- Server: Docker with Compose (container image), or a Linux host with systemd (`.deb`, `.rpm` or
  binary). About 4 GiB of memory is allotted to it in the shipped Compose file and systemd unit,
  and the first start downloads the Grype database (about 100 MB).
- Optional: a Matrix homeserver and bot account for alerts; an LLM API for rule drafting.
- Building from source: Go 1.27.4 (see `go.mod`). See [docs/development.md](docs/development.md).

## Quick start

The full 15-minute path (agentless server, first findings, Matrix alert, first remote agent) is in
[docs/quickstart.md](docs/quickstart.md). In short, to try the server and one agent:

```sh
git clone https://github.com/DonSosiska/holealign.git
cd holealign/deploy
cp server.env.example .env       # set HOLEALIGN_ADMIN_PASSWORD (at least 12 characters)
docker compose up -d --build
docker compose exec holealign-server holealign-server token create first -labels prod,web -max-hosts 5 -expires 72h
```

Agents require `https://`: put TLS in front of port 8080 ([TLS options](docs/installation.md#tls)).
Then, on a monitored host as root, take `install.sh` from a **release tag** (not `main`), read it, and run it
with the token saved in a file:

```sh
V=X.Y.Z    # a release version from https://github.com/DonSosiska/holealign/releases
curl --proto '=https' --tlsv1.2 -fsSLO https://raw.githubusercontent.com/DonSosiska/holealign/v$V/deploy/install.sh
less install.sh
sudo sh install.sh --version $V --server https://holealign.example.com --token-file /root/holealign.token
```

The installer verifies the release signature with [cosign](https://docs.sigstore.dev/cosign/system_config/installation/)
and installs the collector and the agent as systemd services. Open the admin UI (loopback only) through
an SSH tunnel, `ssh -L 8081:127.0.0.1:8081 you@docker-host`, at <http://127.0.0.1:8081>, log in as
`admin`. To monitor the server's own host without a separate agent, see
[agentless mode](docs/installation.md#agentless-mode).

## Documentation

All documents are indexed in [docs/README.md](docs/README.md), grouped by what you want to do:

- Use: [quick start](docs/quickstart.md), [user guide](docs/user-guide.md),
  [notifications](docs/notifications.md), [FAQ](docs/faq.md), [troubleshooting](docs/troubleshooting.md).
- Operate: [installation](docs/installation.md), [configuration](docs/configuration.md),
  [operations](docs/operations.md).
- Write rules: [rules](docs/rules.md), [rules feed](docs/rules-feed.md), [LLM drafting](docs/llm.md).
- Develop: [architecture](docs/architecture.md), [contracts](docs/contracts.md),
  [development](docs/development.md), [CONTRIBUTING.md](CONTRIBUTING.md), [CHANGELOG.md](CHANGELOG.md).
- Security: [security model](docs/security-model.md), [SECURITY.md](SECURITY.md).

## Security summary

- **No remote commands.** The agent never executes anything the server sends. Every command is a
  hard-coded argv without a shell; the server can only ask for `file.match` reads.
- **Privilege separation.** The root collector has no network; the sender with the network is not
  root. A parser bug cannot reach the network.
- **The agent does not trust the server.** TLS 1.2+, chain always verified, optional private CA
  only (`ca_file`), SPKI pinning and mTLS.
- **Bounded file reads.** `file.match` only reads world-readable files under a few configuration
  roots, behind a denylist, and masks secrets before anything leaves the host.
- **Hashed secrets, rate limits, re-enrollment protection.** Enrollment tokens and agent keys are
  stored as SHA-256 hashes; an enrolled host cannot be silently re-enrolled.
- **LLM output is inert until a human approves it.** A draft can never lower a verdict, and
  approving needs the reviewer's password.
- **Signed releases.** Cosign keyless signatures with an exact identity, SBOMs, provenance.

Full model and operator checklist: [docs/security-model.md](docs/security-model.md). Report
vulnerabilities privately: [SECURITY.md](SECURITY.md). To check a release by hand (cosign,
`gh attestation`, server image): [docs/installation.md](docs/installation.md#verifying-releases).

## Packages and building from source

Release archives, `.deb`/`.rpm` packages and the server image
`ghcr.io/donsosiska/holealign-server` are published from tags `v*`. `make build` builds the
binaries into `bin/`; `make docker` builds the server image from source. See
[docs/development.md](docs/development.md).

## License

Holealign is open source under the [GNU Affero General Public License v3.0 only](LICENSE)
(AGPL-3.0-only). You may use, modify and run it for any purpose, including commercial use, at no cost.
If you distribute Holealign, or let users interact with a modified version of it over a network, you must
offer the complete source of your modified version to those users under the same license. Third-party
dependencies keep their own licenses: [NOTICE](NOTICE).

A commercial license without the AGPL obligations is available from the maintainer for those who cannot
accept the AGPL terms. Contact the maintainer through [GitHub](https://github.com/DonSosiska/holealign)
(do not post confidential details in a public issue).
