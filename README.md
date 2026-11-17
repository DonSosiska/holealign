# Panoptes

Panoptes finds vulnerabilities on Linux hosts and checks whether they are actually
exploitable given the host's real configuration. A small agent on each host pushes
facts and a software inventory to a central server; the server matches vulnerabilities
with Grype, evaluates rules against the facts, and sends alerts to Matrix/Element.

Design goals: very simple install and configuration, and low cost (one SQLite file,
no external database, optional LLM).

## How it differs from version-only scanners

A version-only scanner flags every OpenSSH build in an affected range. Panoptes also
reads the host. regreSSHion (CVE-2024-6387) is exploitable only on glibc systems where
`LoginGraceTime` is not `0`. On a musl host, or with `LoginGraceTime 0`, the finding is
recorded as not exploitable and does not page anyone.

## Architecture

```
  Linux host (agent, root)                    Panoptes server
 +--------------------------+   HTTPS, push   +---------------------------------+
 | panoptes-agent           | --------------> | API -> SQLite                   |
 |  sshd -T, nginx -T,      |  facts, labels, |  Grype: packages -> CVEs        |
 |  sysctl, services,       |  inventory      |  rules (CEL): CVE + facts       |
 |  packages, containers    |                 |   -> exploitable / not / unknown|
 +--------------------------+                 |  Matrix alerts   web UI         |
                                              |  LLM drafts rules (optional)    |
                                              +---------------------------------+
```

The agent only connects out to the server. There is no inbound connection to the host.

## Quickstart (about 5 minutes)

You need Docker with Compose, and a Linux host with systemd for the agent.

1. **Start the server.**

   ```sh
   cp deploy/server.env.example deploy/.env
   # edit deploy/.env: set PANOPTES_ADMIN_PASSWORD (at least 8 characters)
   cd deploy
   docker compose up -d --build
   ```

   The admin user `admin` is created on first start from `PANOPTES_ADMIN_PASSWORD`.

2. **Create an enrollment token** for the first agent. It is printed once.

   ```sh
   docker compose exec panoptes-server panoptes-server token create first
   ```

3. **Install the agent** on a host. Use a URL the host can reach, for example
   `https://panoptes.example.com` or `http://192.0.2.10:8080`.

   ```sh
   curl -fsSL https://raw.githubusercontent.com/DonSosiska/panoptes/main/deploy/install.sh | \
     sudo sh -s -- --server https://panoptes.example.com --token pt_xxx --labels prod,web
   ```

   The script verifies the keyless cosign signature of `checksums.txt` and then the
   archive checksum (it aborts when `cosign` is missing unless you pass
   `--skip-signature-check`; or install the signed `.deb`/`.rpm` instead), installs the
   binary to `/usr/bin/panoptes-agent`, writes `/etc/panoptes/agent.yaml` (`root:panoptes`, mode 0640),
   creates the system user `panoptes`, and starts the `panoptes-collector` and `panoptes-agent` services. Logs: `journalctl -u panoptes-agent -f`.
   For air-gapped hosts, use `--binary PATH`.

   To trust only your own CA and/or pin the server key, add `--ca-file PATH` and
   `--server-pin HEX` (repeatable; get the value with `panoptes-agent -print-server-pin`,
   which validates the chain first, so compare it out of band). See
   `deploy/agent.yaml.example` (`ca_file`, `server_cert_sha256`, `client_cert`/`client_key` for mTLS).

4. **Open the web UI** at `http://localhost:8081` (the admin listener, bound to loopback; or your public URL) and log in as
   `admin`. The host appears after its first check-in, and findings follow after the
   first inventory upload.

Set `PANOPTES_PUBLIC_URL` in `deploy/.env` to the URL users will open. It is used in
links inside alerts.

## Matrix setup

1. Create a bot user on your homeserver, for example `@panoptes:matrix.example.com`.
2. Get an access token for the bot. In Element, log in as the bot and open
   Settings, then Help & About, then Access Token. Or call the login API with
   `POST /_matrix/client/v3/login`.
3. Invite the bot to each alert room and make sure it joins.
4. In `deploy/.env`, set `PANOPTES_MATRIX_TOKEN` to the token and
   `PANOPTES_MATRIX_HOMESERVER` to the homeserver URL. Restart the server.
5. In the web UI, under Settings, set the default rooms and the label-to-room routes.
   For example, hosts labelled `prod` go to `#prod-alerts`. Hosts that match no route
   use the default rooms. The same settings can also be made in `server.yaml`.

## LLM setup (optional)

The LLM only drafts rules. It never decides exploitability on its own. Set the provider
in `deploy/.env`:

| Setting | Value |
|---|---|
| none (default) | `PANOPTES_LLM_PROVIDER=none`. No drafting. Only shipped and hand-written rules apply. |
| Anthropic | `PANOPTES_LLM_PROVIDER=anthropic`, `PANOPTES_LLM_API_KEY=...`, optionally `PANOPTES_LLM_MODEL`. |
| OpenAI-compatible (for example Ollama) | `PANOPTES_LLM_PROVIDER=openai-compatible`, `PANOPTES_LLM_BASE_URL=http://ollama:11434/v1`, `PANOPTES_LLM_MODEL=llama3.1`. Set the API key only if your endpoint needs one. |

When a High or Critical finding, or a KEV finding, has no rule, Panoptes asks the LLM
for a draft. The draft is applied right away but flagged as unapproved until someone
approves it in the web UI. `PANOPTES_LLM_DAILY_LIMIT` (`llm.daily_limit`) caps the calls
per day.

## Writing rules

Rules are YAML files. Shipped rules are in `rules/`; the server reads them from
`/usr/share/panoptes/rules` in packages and images. The full format, the CEL
environment and the verdict algorithm are in [docs/contracts.md §4](docs/contracts.md).

A rule for CVE-2024-6387 (`rules/CVE-2024-6387.yaml`, abridged):

```yaml
id: CVE-2024-6387
vulns: [CVE-2024-6387]
packages:
  - {name: openssh-server, type: deb}
  - {name: openssh-server, type: rpm}
facts: [os.libc, sshd.config]
exploitable_if: >
  facts["os.libc"] == "glibc" &&
  facts["sshd.config"].?["logingracetime"].orValue("120") != "0"
explanation: "Exploitable only on glibc systems while LoginGraceTime is non-zero."
fix:
  upgrade: "Upgrade OpenSSH to the distribution's patched package and restart sshd."
  mitigation: "Set 'LoginGraceTime 0' in /etc/ssh/sshd_config and reload sshd."
status: reviewed
```

Facts come from the agent (`os.libc`, `sshd.config`, `nginx.directives`, `kernel.sysctl`,
and more, listed in the contract). A fact that is missing on a host means the verdict is
`conditions_unknown`, not `not exploitable`.

## Security notes

- The agent never runs commands sent by the server. Every command the agent runs is
  hard-coded as a fixed argv, with no shell.
- The agent runs as root because it has to read sshd, nginx, package and container
  state. Its systemd unit is hardened, and it uses CPU, memory and I/O limits.
- `file.match` (reading config files for a rule) is limited to `/etc/`, `/opt/*/conf/`,
  `/opt/*/etc/` and `/usr/local/etc/`. Secret-looking values such as passwords and
  tokens are masked before they leave the host.
- The server stores only SHA-256 hashes of enrollment tokens and agent keys.
- Put the server behind HTTPS (a reverse proxy or a load balancer). Agents send their
  keys with every request.

## Packages and building from source

- Release archives, `.deb` and `.rpm` packages, and the server image are published
  from tags `v*` (see `.goreleaser.yaml`). Packages install the service units but
  do not start them. Set `/etc/panoptes/agent.yaml` or `/etc/panoptes/server.env`
  first, then `systemctl enable --now panoptes-collector panoptes-agent` (or `panoptes-server`). The
  agent package creates the system user `panoptes` and makes `agent.yaml` `root:panoptes` 0640.
- `make build` builds the binaries into `bin/`. `make docker` builds the server image
  from source. `make release-snapshot` runs a local goreleaser dry run.
- Configuration reference: [deploy/agent.yaml.example](deploy/agent.yaml.example),
  [deploy/server.yaml.example](deploy/server.yaml.example),
  [deploy/server.env.example](deploy/server.env.example).

## Privilege separation

The agent runs as two services from one binary. `panoptes-collector` runs as root, has no network
(`PrivateNetwork=yes`, `IPAddressDeny=any`, unix sockets only) and is the only process that parses
untrusted local files (configs, package databases, images). It serves the results on
`/run/panoptes/collector.sock`. `panoptes-agent` is the sender: it runs as the unprivileged user
`panoptes`, holds the agent key, and is the only process that talks to the server. A bug in a parser
cannot reach the network, and a compromised sender is not root. `-mode all` (the default, used by
`-once`, containers and the e2e tests) keeps the single-process behaviour. Details:
[docs/contracts.md](docs/contracts.md) section 2. Test it with `deploy/e2e/split-mode.sh`.
The server's own host can use the same collector without any sender, see "Agentless mode".

## Agentless mode (server monitors itself)

The server host does not need a separate `panoptes-agent`: with `local_agent.enabled: true` the installed
`panoptes-server` monitors its own host and shows it like any other host (labelled `server` and marked
"local (built-in)" in the web UI; findings, rules, Matrix alerts and silence alerts work unchanged). It is off by
default. Two ways to feed it host data (`local_agent.source`, default `auto`):

- **`collector` (recommended).** Install only the collector on the server host: `install.sh --collector-only`
  (or the agent package, then `systemctl enable --now panoptes-collector` and nothing else). The server reads facts
  and inventory from `/run/panoptes/collector.sock`, so privilege separation is kept: the root collector has no
  network and the internet-facing server stays unprivileged. The collector only accepts root and the user
  `panoptes`, so run the server as that user instead of a `DynamicUser` (see the commented lines in
  `deploy/systemd/panoptes-server.service`).
- **`inprocess`.** The server process itself collects (sshd -T, package databases, Docker images ...) with its own
  privileges. Nothing else to install, intended for development and single-box setups. The trade-off: the
  network-facing server process now runs the collectors and parses untrusted local files, and when it is not
  root some facts are missing (one WARN is logged). Inside a container it scans the container, not the host.
- `auto` picks `collector` when the socket answers, otherwise `inprocess`, and logs which.

```yaml
local_agent:
  enabled: true        # or PANOPTES_LOCAL_AGENT_ENABLED=true
  source: collector    # collector | inprocess | auto
  labels: [server]     # locked, like enrollment token labels
```

No enrollment token is needed: the server creates the host record itself and keeps the agent key in
`<data_dir>/local-agent/credentials.json`. If a standalone agent already enrolled this machine, the server does not
take that host over; it logs an error: delete the host (`panoptes-server host delete <hostname>`) or disable
`local_agent`. Reference: [docs/contracts.md](docs/contracts.md) section 6.

## Verifying releases

Each release publishes `checksums.txt`, a keyless Sigstore signature for it
(`checksums.txt.sig` and `checksums.txt.pem`), SPDX SBOMs for the archives, and
GitHub build provenance attestations. Signatures are made by the release workflow
in this repository, so the certificate identity must match that workflow and the
exact release tag. Replace
`X.Y.Z` with the release version (the tag is `vX.Y.Z`). The identity is an exact
string, not a pattern: a signature from any other workflow or tag is rejected.

1. Verify the checksum file was signed by the release workflow:

   ```sh
   cosign verify-blob --certificate checksums.txt.pem --signature checksums.txt.sig --certificate-identity "https://github.com/DonSosiska/panoptes/.github/workflows/release.yml@refs/tags/vX.Y.Z" --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt
   ```

2. Check the files you downloaded against the verified checksums. `--ignore-missing`
   skips the files you did not download:

   ```sh
   sha256sum -c checksums.txt --ignore-missing
   ```

3. Verify the server image signature. Use the same exact identity as step 1. Replace
   `X.Y.Z` with the release version, for example `1.2.3` for tag `v1.2.3`:

   ```sh
   cosign verify ghcr.io/donsosiska/panoptes-server:X.Y.Z --certificate-identity "https://github.com/DonSosiska/panoptes/.github/workflows/release.yml@refs/tags/vX.Y.Z" --certificate-oidc-issuer https://token.actions.githubusercontent.com
   ```

4. Verify the build provenance of a downloaded archive, `.deb` or `.rpm` (requires the
   [GitHub CLI](https://cli.github.com/)):

   ```sh
   gh attestation verify panoptes-agent_X.Y.Z_linux_amd64.tar.gz --repo DonSosiska/panoptes --signer-workflow DonSosiska/panoptes/.github/workflows/release.yml
   ```

Linux packages (`.deb`, `.rpm`) are not signed with apt or rpm keys. Verify them
through `checksums.txt` as in steps 1 and 2.

## License

Apache License 2.0. See [LICENSE](LICENSE).
