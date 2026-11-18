# FAQ

Short answers. Links lead to the full explanation.

Contents: [How is it different?](#how-is-panoptes-different-from-trivy-grype-wazuh-or-vuls) -
[Internet](#does-it-need-internet-access) - [Data leaving a host](#what-data-leaves-a-monitored-host) -
[LLM](#can-it-run-without-an-llm) - [Distros](#which-distributions-are-supported) -
[Resources](#how-much-cpu-memory-and-disk-does-it-use) - [Containers](#does-it-scan-containers) -
[Licence](#licensing) - [Other](#other-questions)

## How is Panoptes different from Trivy, Grype, Wazuh or Vuls?

Panoptes uses Syft and Grype internally, so its package matching is Grype's. What it adds is a second
question: **is this vulnerability actually exploitable on this host's configuration?** A rule reads
configuration facts (`sshd -T`, `nginx -T`, kernel sysctl, listening sockets, running services, Docker
containers and a few bounded file reads) and gives a verdict. regreSSHion (CVE-2024-6387) is
`exploitable` on glibc with `LoginGraceTime` not `0`, and `affected_not_exploitable` otherwise. When
Panoptes cannot tell, the verdict is `conditions_unknown`, never "safe".

| Tool | What it is | Compared with Panoptes |
|---|---|---|
| Trivy, Grype | Scanners: package versions against vulnerability data, run on demand or in CI | Version-only results. Panoptes keeps them continuous for a fleet and adds the configuration check and alerting. |
| Wazuh | A full security platform: agents, log analysis, FIM, compliance, vulnerability detection | Much broader. Panoptes does one thing (exploitability of vulnerabilities) and is one binary plus SQLite. If you already run Wazuh for everything else, Panoptes does not replace it. |
| Vuls | Agentless (SSH) or agent vulnerability scanner for Linux | Closest in purpose. Panoptes uses pushing agents instead of SSH, a signed rules feed and an exploitability verdict per host; it has far fewer integrations and a smaller rule set. |

Honest limits: only eight rules ship in the binary, so most findings start as `conditions_unknown`
until a rule covers them (a signed [rules feed](rules-feed.md) and [LLM drafting](llm.md) exist to
grow that set). Panoptes does not scan source code, cloud configuration or web applications, and it
does not remediate.

## Does it need internet access?

The **server** needs outbound HTTPS for the Grype vulnerability DB (refreshed every 6 h, about 100 MB
at first), and optionally for the rules feed, Matrix, an LLM provider and `api.osv.dev` (advisory text
for drafting). All of these can be switched off or pointed at internal services; an air-gapped setup
is documented in [operations.md](operations.md#air-gapped-and-feed-updates), and rules can be
imported from a tarball (`panoptes-server rules import`). **Agents** only connect to your
`server_url`, outbound; no inbound connection to a monitored host is ever made.

## What data leaves a monitored host?

Only the agent's sender talks to the server, over TLS, and only to `server_url`. It sends:

- At enrollment: the enrollment token, hostname, a **hashed** machine ID (SHA-256 of the raw
  `/etc/machine-id` with a fixed prefix; the raw value never leaves the host), labels, agent version.
- At every check-in (5 minutes): hostname, labels, agent version, OS (`id`, `version_id`, pretty name,
  kernel release, architecture), and the facts below.
- When packages change (and every 6 h): an inventory per target, a CycloneDX SBOM produced by Syft:
  names, versions, PURLs and related package metadata of OS and language packages on the host and of
  Docker images, plus image IDs and the names of containers that use them.

**Facts** (the complete built-in list; see [rules.md](rules.md#fact-catalog)):
`os.id`, `os.version_id`, `os.libc`, `os.libc_version`, `kernel.release`, `kernel.modules` (names),
`kernel.sysctl` (13 allow-listed keys), `services.active` and `services.source`, `sockets.listening` and
`sockets.ports` (protocol, address, port, owning process name), `sshd.*` (installed, version, effective
configuration from `sshd -T`), `nginx.*` (version, modules, directives from `nginx -T`, `http2`),
`apache.*`, `php.*` (selected `php.ini` values), `openssl.version`, `docker.*` (version, containers with
name, image, ports, privileged flag), `runc.version`, `sudo.version`, and the agent's own
`agent.inventory_error`, `agent.collector_error`, `agent.skipped`.

**Masking.** In `nginx -T` output comments are stripped, values that look like secrets become `***`
and values are capped at 256 bytes. `file.match` is the only thing the server can ask an agent to
collect beyond that list: only for reviewed rules, only under a few configuration roots, behind a
denylist (`shadow`, `passwd`, `*.key`, `*.pem`, `.env`, anything named like `secret`, `token`,
`credential`, and credential directories), world-readable regular files only, at most 200 lines per
request. Values after keys named like `key`, `secret`, `token`, `pass`, `psk`, `credential`, `auth` or
`community`, bearer tokens, URL user info and long random-looking strings are masked on the host,
before the pattern is applied ([rules.md](rules.md#filematch-policy)). Hostnames and package lists
are not masked: they are the point of the product. You can see the exact payloads with
`panoptes-agent -print-facts` and `-print-inventory`, with no server involved.

The agent never executes anything the server sends: every command is a fixed argv without a shell
([security-model.md](security-model.md)).

## Can it run without an LLM?

Yes, and that is the default (`llm.provider: none`). The LLM only drafts rules for a human to review;
everything else (matching, verdicts, alerts) works without it, and shipped rules and the signed feed
need no model. With an LLM, a draft is inert until a person approves it, can never lower a verdict, and
the model only receives package and vulnerability data, never host facts, hostnames or file contents
([llm.md](llm.md#what-is-sent-to-the-llm)). You can point it at a local OpenAI-compatible endpoint such
as Ollama.

## Which distributions are supported?

Linux on amd64 or arm64 with systemd, and an OS package database that Syft and Grype understand
(dpkg, rpm, apk). Facts come from `/etc/os-release`, `/proc`, `/sys` and standard tools, so
mainstream Debian, Ubuntu, RHEL-family and Alpine systems are the intended targets. The end-to-end test
runs on Debian 12 only; other distributions are not tested in CI. Musl (Alpine) is detected (`os.libc`).
Windows, macOS and BSD are not supported, and the installer, packages and shipped units need
systemd.

## How much CPU, memory and disk does it use?

No benchmarks are published, so these are what the shipped configuration enforces, not measurements:

- **Agent**: the collector unit is capped at 1 GiB memory and 50 % CPU, low priority (`Nice=10`, idle
  IO); scans have time limits (`host_scan_timeout` 10 m, `image_scan_timeout` 5 m). A check-in every
  5 minutes is a small request; the SBOM is uploaded only when packages change or every 6 h.
- **Server**: the shipped Compose file and unit allot 4 GiB of memory. At most 2 hosts are matched
  at once. Disk is the SQLite database plus the Grype DB (about 100 MB download); retention deletes
  resolved findings after 30 days and notification records after 90.
- Measure on your fleet; see [operations.md](operations.md#scaling-notes).

## Does it scan containers?

Docker images present on a host are scanned (when the Docker socket exists) and findings are attributed
to the image and the containers using it. Container facts (`docker.containers`, `runc.version`) feed
rules such as CVE-2024-21626. Running a server in Docker with agentless mode scans the container itself
unless you mount the host collector socket ([installation.md](installation.md#agentless-mode)). The
Docker API socket is the only image source; images of other runtimes (Podman, containerd,
Kubernetes) are not listed.

## Licensing

Panoptes is source-available under the [PolyForm Noncommercial License 1.0.0](../LICENSE). You may use,
modify and share it for noncommercial purposes: personal use, research, education, hobby projects, and
use by charities, educational institutions, public research and safety organizations, environmental
organizations and government institutions. It is not an OSI open-source licence. **Commercial use
requires a separate licence**: contact the maintainer through
[GitHub](https://github.com/DonSosiska/panoptes) (do not post confidential details in a public issue).
Dependencies keep their own licences ([NOTICE](../NOTICE)). This page is a summary, not legal advice;
the LICENSE file is what applies.

## Other questions

**Is there an API?** Agents use the HTTP API in [contracts.md](contracts.md); the admin UI is not an
API. See [api.md](api.md) for the documented endpoints.

**Does it fix vulnerabilities?** No. It shows the fixed version and a package-manager command for the
host's OS; you run it.

**Can several teams share one server?** Hosts are separated by labels for alert routing only. Every web
user sees everything and there are no roles.

**What happens if the server is down?** Agents keep retrying with backoff and keep their state; nothing
is lost on the host. Back up the server database ([operations.md](operations.md#backup-and-restore)).

**Where do I report a security issue?** Privately, see [SECURITY.md](../SECURITY.md).
