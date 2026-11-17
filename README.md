# Panoptes

[![ci](https://github.com/DonSosiska/panoptes/actions/workflows/ci.yml/badge.svg)](https://github.com/DonSosiska/panoptes/actions/workflows/ci.yml)
License: [PolyForm Noncommercial 1.0.0](LICENSE) (source-available, not open source)

English | [Українська](README.uk.md)

Panoptes finds vulnerabilities on Linux hosts and decides whether each one is **actually
exploitable given that host's configuration**. Agents on your hosts push a software inventory
(SBOM) and a set of configuration facts to a central server. The server matches vulnerabilities
with Grype (including CISA KEV and EPSS data), evaluates CEL rules against the facts, and alerts
Matrix/Element rooms chosen by host labels. Rules that do not exist yet can be drafted by an LLM;
a draft stays inert until a human reviews it. It is one binary plus one SQLite file, with no
external database.

## How it differs from version-only scanners

A version-only scanner flags every OpenSSH build in an affected range. Panoptes also reads the
host. regreSSHion (CVE-2024-6387) is exploitable only on glibc systems where `LoginGraceTime` is
not `0`. On a musl host, or with `LoginGraceTime 0`, the finding is recorded as
`affected_not_exploitable` and nobody gets paged. When Panoptes cannot tell (no rule, or a fact is
missing) the verdict is `conditions_unknown`, never "safe".

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
- Optional signed central rules feed: rules are written and tested once in a separate repository,
  packed into an ed25519-signed bundle and downloaded by every server like the Grype DB (built-in <
  feed < local precedence, atomic verification, air-gapped import): [docs/rules-feed.md](docs/rules-feed.md).
- Optional LLM rule drafting (Anthropic or any OpenAI-compatible endpoint such as Ollama):
  [docs/llm.md](docs/llm.md).
- Matrix/Element alerts routed by host label, with dedup, grouping and burst summaries:
  [docs/notifications.md](docs/notifications.md).
- Admin web UI: hosts, findings grouped per CVE with a "needs attention" vs "background" triage
  ([docs/rules.md](docs/rules.md#reading-the-dashboard-attention-vs-background)), rule review,
  enrollment tokens, Matrix routes, users.
- Health alerts: silent agents, stale vulnerability feed, failing pipeline.
- Agentless mode (server monitors its own host): [docs/installation.md](docs/installation.md#agentless-mode).
- Signed releases: cosign signatures, SBOMs, build provenance.

## Architecture

```
  Monitored Linux host (any number)                Panoptes server
 +-------------------------------------+        +----------------------------------------+
 | panoptes-collector (root, NO network)|        | agent API  :8080  /api/v1/*  /healthz  |
 |   sshd -T, nginx -T, sysctl, /proc, |        |   enroll, check-in, inventory          |
 |   Syft scan, file.match             |        |                                        |
 |        |  unix socket               | HTTPS  | SQLite + Grype DB      (data_dir)      |
 | panoptes-agent sender (user         |------->| pipeline: Grype -> CEL rules -> verdict|
 |   "panoptes", the only one with     | push,  |                                        |
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

About five minutes. For a real deployment read [docs/installation.md](docs/installation.md) and the
[hardening checklist](docs/security-model.md#operator-hardening-checklist) first.

### 1. Start the server

```sh
git clone https://github.com/DonSosiska/panoptes.git
cd panoptes/deploy
cp server.env.example .env
# edit .env: set PANOPTES_ADMIN_PASSWORD (at least 12 characters)
docker compose up -d --build
docker compose logs -f panoptes-server      # wait for "panoptes-server listening"
```

The user `admin` is created on first start from `PANOPTES_ADMIN_PASSWORD` (or from the file named by
`PANOPTES_ADMIN_PASSWORD_FILE`). The agent API listens on `:8080`, the admin UI on
`127.0.0.1:8081` only. Agents require `https://`, so put TLS in front of port 8080 (a reverse
proxy, or native `tls_cert`/`tls_key`): [TLS options](docs/installation.md#tls).

### 2. Create an enrollment token

```sh
docker compose exec panoptes-server panoptes-server token create first -labels prod,web -max-hosts 5 -expires 72h
```

The token (`pt_...`) is printed once. Labels on a token are authoritative: hosts that enroll
with it get exactly these labels, which select the Matrix rooms for their alerts.

### 3. Install the agent on a host

On the monitored host, as root. Save the token to a file (not to the command line), download the
installer, read it, run it:

```sh
install -m 0600 /dev/null /root/panoptes.token && vi /root/panoptes.token   # paste the pt_... token
curl --proto '=https' --tlsv1.2 -fsSLO https://raw.githubusercontent.com/DonSosiska/panoptes/main/deploy/install.sh
less install.sh
sh install.sh --server https://panoptes.example.com --token-file /root/panoptes.token
```

The installer needs [cosign](https://docs.sigstore.dev/cosign/system_config/installation/): it
verifies the keyless signature of `checksums.txt` against the exact release workflow and tag, then
the archive checksum, and aborts if cosign is missing (`--skip-signature-check` overrides this;
not recommended). It installs `/usr/bin/panoptes-agent`, creates the system user `panoptes`,
writes `/etc/panoptes/agent.yaml` (`root:panoptes`, 0640) and starts `panoptes-collector` and
`panoptes-agent`. Check with `journalctl -u panoptes-agent -f`. Private CA, server key pinning,
air-gapped hosts and every other flag: [docs/installation.md](docs/installation.md#agents).

For a throwaway test without TLS only, use `--server http://SERVER:8080 --allow-insecure-http`.
Agent keys then cross the network in cleartext.

### 4. Open the admin UI

The admin listener is bound to loopback on purpose. Reach it through an SSH tunnel:

```sh
ssh -L 8081:127.0.0.1:8081 you@panoptes-docker-host
```

then open <http://127.0.0.1:8081> and log in as `admin`. The host appears after its first
check-in; findings follow after the first inventory upload (a few minutes, longer on the first
scan). Set `PANOPTES_PUBLIC_URL` in `.env` to the URL people will actually open: it is used for
links in alerts.

Next: [Matrix alerts](docs/notifications.md), [LLM drafting](docs/llm.md) (optional),
[operations](docs/operations.md).

## Agentless quick start

The server can monitor its own host through a built-in local agent, so no separate agent install or
enrollment is needed. It is disabled by default.

On a host that runs the server from the `.deb`/`.rpm` package or as a binary with systemd:

```sh
sudo sh install.sh --collector-only      # installs only the root collector and the panoptes user
```

then in `/etc/panoptes/server.yaml`:

```yaml
local_agent:
  enabled: true
  source: collector        # collector | inprocess | auto (default auto)
  labels: [server]
```

The collector accepts only root and the user `panoptes`, so the server must run as that user, not as
a systemd `DynamicUser`. Add a drop-in with `systemctl edit panoptes-server`:

```ini
[Service]
DynamicUser=no
User=panoptes
Group=panoptes
```

then `systemctl restart panoptes-server`. This static-user setup is not yet verified on a real host
(see the comments in the unit file). In Docker, `source: inprocess` scans the container, not the host:
use the host collector socket instead. Details, all `local_agent.*` keys and caveats:
[docs/installation.md](docs/installation.md#agentless-mode).

## Documentation

| Document | Contents |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Components, data flow, privilege separation, trust boundaries, storage |
| [docs/installation.md](docs/installation.md) | Server and agent install, TLS, every `install.sh` flag, verifying releases, upgrades, agentless mode |
| [docs/configuration.md](docs/configuration.md) | Every server and agent config key, with defaults and environment overrides |
| [docs/rules.md](docs/rules.md) | Verdicts, writing rules, CEL environment, fact catalog, `file.match` policy, shipped rules, draft review |
| [docs/rules-feed.md](docs/rules-feed.md) | Signed central rules feed: bundle format, signing, key management, publishing, air-gapped import |
| [docs/llm.md](docs/llm.md) | LLM providers, cost control, what is sent, prompt-injection defenses |
| [docs/notifications.md](docs/notifications.md) | Matrix setup, routing, message types, dedup, delivery problems |
| [docs/operations.md](docs/operations.md) | CLI, backup and restore, retention, health alerts, air-gapped feeds, troubleshooting |
| [docs/security-model.md](docs/security-model.md) | Threat model, mitigations, hardening checklist, known limitations |
| [docs/development.md](docs/development.md) | Repository layout, building, tests, release process |
| [docs/contracts.md](docs/contracts.md) | Protocol and interface contracts (source of truth) |
| [SECURITY.md](SECURITY.md) | Reporting vulnerabilities, supported versions |
| [CONTRIBUTING.md](CONTRIBUTING.md), [CHANGELOG.md](CHANGELOG.md) | Contributing, release notes |

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
vulnerabilities privately: [SECURITY.md](SECURITY.md).

## Verifying releases

Every release has `checksums.txt` with a keyless cosign signature, SPDX SBOMs and GitHub build
provenance. `install.sh` checks the signature for you. To check by hand (cosign, `gh attestation`,
server image), see [docs/installation.md](docs/installation.md#verifying-releases).

## Packages and building from source

Release archives, `.deb`/`.rpm` packages and the server image
`ghcr.io/donsosiska/panoptes-server` are published from tags `v*`. `make build` builds the
binaries into `bin/`; `make docker` builds the server image from source. See
[docs/development.md](docs/development.md).

## License

Panoptes is **source-available** under the [PolyForm Noncommercial License
1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0/) (see [LICENSE](LICENSE)). You
may use, modify and distribute it for any noncommercial purpose: personal use, research,
education, hobby projects, and use by charities, educational institutions, public research and
safety organizations, environmental organizations and government institutions. It is not an OSI
open-source license. Third-party dependencies keep their own licenses: [NOTICE](NOTICE).

### Commercial use

The PolyForm Noncommercial License does not cover commercial use, for example use by a
for-profit company for its business. Commercial use requires a separate license from the author.
Contact the author through [GitHub](https://github.com/DonSosiska/panoptes) (the repository
owner's profile or a GitHub Discussion; do not post confidential details in a public issue).
