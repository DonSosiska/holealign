# Installation

How to install the Holealign server (Docker Compose, `.deb`/`.rpm` packages, or a plain binary with
systemd), how to put TLS in front of it, how to install agents on monitored hosts (`install.sh`,
packages, or by hand), how to verify releases, how to upgrade and uninstall, and how to run
agentless mode. Every configuration key is listed in [configuration.md](configuration.md).

Contents: [Choosing a mode](#choosing-a-mode) - [Server](#server) - [TLS](#tls) -
[First admin user](#first-admin-user) - [Agents](#agents) - [Privilege separation](#privilege-separation) -
[systemd units](#systemd-units) - [Verifying releases](#verifying-releases) - [Upgrading](#upgrading) -
[Uninstalling](#uninstalling) - [Agentless mode](#agentless-mode)

In commands, `X.Y.Z` is a release version and `vX.Y.Z` its Git tag. Use the releases page to find the
current one; the project had no tagged release when this page was written, in which case build from
source ([development.md](development.md)) or use the Compose build.

## Choosing a mode

| You want | Use | Needs |
|---|---|---|
| Try it on one machine, see the UI | [Docker Compose](#docker-compose) server, then [agentless](#agentless-mode) or one agent | Docker |
| Monitor the server's own host only | [Agentless mode](#agentless-mode) | server install plus `install.sh --collector-only` |
| Monitor a fleet | Server (any method) plus [`install.sh`](#installsh) or [packages](#packages) on each host | an enrollment token per group of hosts, TLS in front of the agent port |
| Hosts without internet | `--binary`, [air-gapped feeds](operations.md#air-gapped-and-feed-updates) | files copied by hand |

## Server

Pick one. Docker image: `ghcr.io/donsosiska/holealign-server:X.Y.Z` (distroless, uid 65532, signed; there is
no agent image, the agent is a host service). All three run the same `holealign-server serve`. The server needs outbound HTTPS for the
vulnerability feed (Grype DB, about 100 MB on first start) and, if configured, Matrix, the LLM and
OSV (advisory text for drafting). Without outbound access see
[air-gapped feeds](operations.md#air-gapped-and-feed-updates).

### Docker Compose

```sh
git clone https://github.com/DonSosiska/holealign.git
cd holealign/deploy
cp server.env.example .env       # edit: HOLEALIGN_ADMIN_PASSWORD (12+ chars), HOLEALIGN_PUBLIC_URL, Matrix, LLM
docker compose up -d --build     # builds from source (deploy/Dockerfile.server.build)
docker compose logs -f holealign-server
```

To use the signed prebuilt image instead of building, edit `deploy/docker-compose.yml`: remove the
`build:` block and set `image: ghcr.io/donsosiska/holealign-server:X.Y.Z` (pin a version; verify the
image first, see [Verifying releases](#verifying-releases)).

What the shipped Compose file does:

| Setting | Value |
|---|---|
| Ports | `8080:8080` (agent API, all interfaces) and `127.0.0.1:8081:8081` (admin UI, host loopback only) |
| Container | read-only root filesystem, `/tmp` tmpfs, all capabilities dropped, `no-new-privileges`, 4 GiB memory limit, 512 pids |
| Data | named volume `holealign-data` at `/var/lib/holealign` (database and Grype DB) |
| Config | no `server.yaml`: defaults plus `HOLEALIGN_*` environment variables from `deploy/.env` |
| Admin listener | `HOLEALIGN_ADMIN_LISTEN=0.0.0.0:8081` inside the container; the published port restricts it to the host's loopback |
| Healthcheck | none (the image is distroless: no shell, no curl). Use `docker compose logs`, or `GET /healthz` on port 8080 |

To use a `server.yaml`, mount it and point `HOLEALIGN_CONFIG` at it:

```yaml
# deploy/docker-compose.override.yml
services:
  holealign-server:
    environment:
      HOLEALIGN_CONFIG: /etc/holealign/server.yaml
    volumes:
      - ./server.yaml:/etc/holealign/server.yaml:ro
```

An explicitly named config file that does not exist is a startup error, so do not set
`HOLEALIGN_CONFIG` without mounting the file.

### Packages (.deb, .rpm)

Download `holealign-server_X.Y.Z_<arch>.deb` or `.rpm` from the
[releases page](https://github.com/DonSosiska/holealign/releases), verify it
([Verifying releases](#verifying-releases)), then:

```sh
sudo apt install ./holealign-server_X.Y.Z_amd64.deb        # Debian, Ubuntu
sudo dnf install ./holealign-server_X.Y.Z_<arch>.rpm       # RHEL family (use the file name of the release asset)
```

The package installs `/usr/bin/holealign-server`, the unit `holealign-server.service`,
`/etc/holealign/server.yaml` (a copy of `deploy/server.yaml.example`, kept on upgrade) and the
shipped rules in `/usr/share/holealign/rules/`. It does **not** enable or start the service and does
not create `server.env`. Create it (secrets, mode 0600), then start:

```sh
sudo install -m 0600 /dev/null /etc/holealign/server.env
sudoedit /etc/holealign/server.env        # HOLEALIGN_ADMIN_PASSWORD=..., HOLEALIGN_MATRIX_TOKEN=..., HOLEALIGN_LLM_API_KEY=...
sudoedit /etc/holealign/server.yaml       # at least public_url, matrix, TLS or trusted_proxies
sudo systemctl enable --now holealign-server
journalctl -u holealign-server -f
```

The unit runs as a systemd dynamic user with full sandboxing; state is in `/var/lib/holealign`
(`StateDirectory=holealign`, which must match `data_dir`). See `deploy/systemd/holealign-server.service`.

### Binary and systemd

```sh
V=X.Y.Z; A=amd64                         # or arm64
curl -fsSLO https://github.com/DonSosiska/holealign/releases/download/v$V/holealign-server_${V}_linux_${A}.tar.gz
curl -fsSLO https://github.com/DonSosiska/holealign/releases/download/v$V/checksums.txt
curl -fsSLO https://github.com/DonSosiska/holealign/releases/download/v$V/checksums.txt.sig
curl -fsSLO https://github.com/DonSosiska/holealign/releases/download/v$V/checksums.txt.pem
# verify (see "Verifying releases"), then:
tar -xzf holealign-server_${V}_linux_${A}.tar.gz holealign-server
sudo install -m 0755 holealign-server /usr/bin/holealign-server
# from a checkout of the same tag:
sudo install -d /etc/holealign /usr/share/holealign/rules
sudo install -m 0644 deploy/server.yaml.example /etc/holealign/server.yaml
sudo install -m 0644 rules/*.yaml /usr/share/holealign/rules/
sudo install -m 0644 deploy/systemd/holealign-server.service /etc/systemd/system/
sudo systemctl daemon-reload
```

Then create `/etc/holealign/server.env` and start the service as in the package instructions. The
server also runs without systemd (`holealign-server -config server.yaml serve`); then you provide the
sandboxing and the data directory yourself.

## TLS

Agents require `https://` (unless `allow_insecure_http` is set, for tests only) and always verify
the chain. The server logs a WARN when it is reachable without TLS (non-loopback `listen` with no
`tls_cert` and no `trusted_proxies`, or a non-loopback `admin_listen` without `admin_tls_cert`).
There are two supported setups.

### Native TLS

```yaml
# /etc/holealign/server.yaml
tls_cert: /etc/holealign/agent.crt       # agent API listener; TLS 1.2 minimum
tls_key:  /etc/holealign/agent.key
admin_tls_cert: /etc/holealign/admin.crt # admin UI listener (optional; keep it on loopback or a VPN anyway)
admin_tls_key:  /etc/holealign/admin.key
public_url: https://holealign-admin.example.com
```

Both files of a pair are required. Certificates are read at start: restart the server after
renewing them. With the packaged unit the service runs as a dynamic user that cannot read a
root-only key; hand the files to it with a drop-in (systemd 247 or newer):

```ini
# systemctl edit holealign-server
[Service]
LoadCredential=agent.key:/etc/holealign/agent.key
LoadCredential=agent.crt:/etc/holealign/agent.crt
```

and set `tls_key: /run/credentials/holealign-server.service/agent.key` and `tls_cert` likewise. In
Docker, mount the files read-only and set `HOLEALIGN_TLS_CERT` / `HOLEALIGN_TLS_KEY` to their paths
inside the container (the container user is uid 65532).

With a private CA or a self-signed certificate, agents need `ca_file` (and optionally a pin):
see [Agents](#agents) (`--ca-file`, `--server-pin`).

### Reverse proxy

Terminate TLS in a proxy on the same machine and forward to the loopback or container ports.
Set `trusted_proxies` to the proxy address so rate limits and the audit log see real client
addresses, and set `public_url` to the HTTPS URL users open (a `https` public URL makes the
session cookie `Secure`).

```nginx
server {
    listen 443 ssl;
    server_name holealign.example.com;
    # ssl_certificate / ssl_certificate_key ...
    client_max_body_size 64m;                       # inventory uploads, up to 64 MiB
    location / {
        proxy_pass http://127.0.0.1:8080;           # agent API only
        proxy_set_header X-Forwarded-For $remote_addr;   # overwrite, never append client input
        proxy_read_timeout 300s;
    }
}
```

```yaml
trusted_proxies: [127.0.0.1]
```

Rules for `trusted_proxies`: list only the addresses of your proxies. `X-Forwarded-For` is honoured
only when the TCP peer is in the list, and the right-most entry that is not itself a trusted proxy
is used. The server warns for entries wider than /16 (IPv4) or /48 (IPv6) and for `0.0.0.0/0`.

The admin UI should not be exposed with the agent API. Prefer an SSH tunnel or a VPN to
`127.0.0.1:8081`; if you proxy it, use a separate server block, restrict it by source network,
and set `HOLEALIGN_PUBLIC_URL`. Single-port mode (`admin_listen` empty or equal to `listen`)
exists for legacy setups and logs a WARN: every monitored host could then reach the login page.

## First admin user

On first start, when no web user exists, the server creates the user `admin` with the password from
`HOLEALIGN_ADMIN_PASSWORD` (the variable named by `admin.initial_password_env`), or from the file
named by `HOLEALIGN_ADMIN_PASSWORD_FILE`, which takes precedence and keeps the secret out of the
process environment and `docker inspect`. The password must have at least 12 characters, otherwise
the server refuses to start. After the first start the variable is unused: remove it from
`server.env` / `.env`.

With Compose, a file-based secret:

```yaml
# deploy/docker-compose.override.yml (the file must be readable by uid 65532)
services:
  holealign-server:
    environment:
      HOLEALIGN_ADMIN_PASSWORD_FILE: /run/secrets/holealign_admin
    secrets: [holealign_admin]
secrets:
  holealign_admin:
    file: ./admin_password.txt
```

If no password is configured the server starts without any user and logs a WARN. Create or change a
user later from the command line (password on stdin, 12+ characters):

```sh
docker compose exec -T holealign-server holealign-server user set-password admin <<< 'a-long-password'
```

For packages, start the service once first so the data directory exists, then run
`sudo holealign-server user set-password admin` and type the password on stdin. More: [operations.md](operations.md#cli-reference).

## Agents

The agent is one binary with two services: `holealign-collector` (root, no network) and
`holealign-agent` (user `holealign`). See [architecture.md](architecture.md#privilege-separation).
Create an enrollment token on the server first:

```sh
holealign-server token create web-prod -labels prod,web -max-hosts 20 -expires 72h
```

Use short-lived tokens per group of hosts with labels and a `max_hosts` cap
([security-model.md](security-model.md#operator-hardening-checklist)). Labels are lowercase:
`^[a-z0-9][a-z0-9._-]{0,63}$`, at most 32.

### install.sh

Download the script from a **release tag**, not from `main`: a tag is a fixed, reviewable version, while
`main` changes. Read it before you run it, and install the same version it belongs to:

```sh
V=X.Y.Z
curl --proto '=https' --tlsv1.2 -fsSLO https://raw.githubusercontent.com/DonSosiska/holealign/v$V/deploy/install.sh
less install.sh
sudo sh install.sh --version $V --server https://holealign.example.com --token-file /root/holealign.token --labels prod,web
```

Without `--version` the script installs the latest release. Do not pipe it into a shell (`curl | sh`)
on a production host; the script itself is built so a truncated download cannot run half of it, but you
should still read what you run as root.

`install.sh` needs root, Linux, systemd, `curl`, `tar` and a SHA-256 tool (it installs missing
ones with the system package manager). It supports amd64 and arm64. It creates the system user
`holealign` (it aborts if a `holealign` user exists that is not a plain system account), downloads the
release for your architecture, verifies it, installs `/usr/bin/holealign-agent`, writes the config,
installs both units, and runs `systemctl enable --now` for `holealign-collector` and
`holealign-agent`. The token is written only to the config file and never printed. It is removed from
the file after the first successful check-in.

| Flag | Meaning |
|---|---|
| `--server URL` | Server base URL: `https://`, no `user:password@`. Required when writing a config. |
| `--token-file PATH` | Read the enrollment token from this file. Preferred. |
| `--token TOKEN` | Token on the command line (visible in `ps` and shell history; a warning is printed). |
| *(env)* `HOLEALIGN_ENROLL_TOKEN` | Token from the environment. One of the three is required on first install. |
| `--labels a,b` | Comma-separated labels (letters, digits, `.`, `_`, `-`). Ignored by the server when the token itself has labels. |
| `--ca-file PATH` | PEM bundle of the CA(s) signing the server certificate. Copied to `/etc/holealign/ca.pem`; when set, **only** these roots are trusted. |
| `--server-pin HEX` | Pin the server key: SHA-256 of the certificate's SubjectPublicKeyInfo (64 hex chars). Repeatable. Get it with `holealign-agent -print-server-pin`. |
| `--allow-insecure-http` | Accept an `http://` `--server` (testing only; the agent key travels in cleartext). |
| `--version VER` | Release to install (`1.2.3` or `v1.2.3`); default: latest. The signature identity is pinned to exactly this tag. |
| `--min-version X.Y.Z` | Refuse to install an older release. |
| `--allow-downgrade` | Allow installing an older release than the installed one (refused by default). |
| `--binary PATH` | Install this local `holealign-agent` binary instead of downloading (air-gapped). No signature check is done for it. |
| `--skip-signature-check` | Do not verify the release signature (not recommended). Without it the install aborts when cosign is missing. |
| `--collector-only` | For agentless mode: install the root collector (`holealign-collector.service`), the `holealign` user and group, and a minimal `agent.yaml`, but no sender (`holealign-agent.service`). No `--server` or token. The release is still downloaded and verified (or use `--binary`). See [Agentless mode](#agentless-mode). |
| `--force` | Overwrite an existing `/etc/holealign/agent.yaml`. With `--uninstall`: also remove the config and state. |
| `--uninstall` | Stop and remove the units and the binary. |
| `-h`, `--help` | Show the built-in help. |
| *(env)* `HOLEALIGN_REPO` | Download from another GitHub `owner/name` (default `DonSosiska/holealign`). The signature identity then names that repository. |

Notes:

- With an existing `/etc/holealign/agent.yaml` and no `--force`, the config is kept and `--server`,
  `--token` and `--labels` are not applied (a warning says so). Re-running the script is the
  upgrade path.
- Private CA example: `--ca-file ./ca.pem --server-pin "$(holealign-agent -print-server-pin)"`.
  `-print-server-pin` validates the chain first, so it is a convenience, not trust on first use:
  compare the value out of band. List the next key too before rotating a certificate.
- Hosts without internet: download the archive on another machine, verify it, copy it over, and
  use `--binary`.

### Packages

```sh
sudo apt install ./holealign-agent_X.Y.Z_amd64.deb      # or: sudo dnf install ./holealign-agent_X.Y.Z_<arch>.rpm
sudoedit /etc/holealign/agent.yaml                      # server_url, enroll_token, labels
sudo systemctl restart holealign-collector holealign-agent
```

The package creates the user `holealign`, installs both units and `/etc/holealign/agent.yaml`
(`root:holealign`, 0640, kept on upgrade) and enables the services without starting them. Verify the
package as described in [Verifying releases](#verifying-releases). Packages are not signed with apt
or rpm keys.

### Manual install

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin holealign
sudo install -m 0755 holealign-agent /usr/bin/holealign-agent
sudo install -d /etc/holealign
sudo install -o root -g holealign -m 0640 deploy/agent.yaml.example /etc/holealign/agent.yaml   # then edit
sudo install -m 0644 deploy/systemd/holealign-collector.service deploy/systemd/holealign-agent.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now holealign-collector holealign-agent
```

For a one-off check on any host without services:

```sh
holealign-agent -print-facts          # collected facts as JSON, no server needed
holealign-agent -print-inventory      # SBOM payload as JSON
holealign-agent -config agent.yaml -once   # one check-in and upload, then exit (-mode all)
```

All agent flags: `-config`, `-mode all|collector|sender`, `-once`, `-print-facts`,
`-print-inventory`, `-print-server-pin`, `-log-level debug|info|warn|error`, `-version`.
Config keys: [configuration.md](configuration.md#agent-configuration).

## Privilege separation

The agent is one binary run as two processes. Reading `sshd -T`, `nginx -T`, `/proc/*/fd` and the
whole filesystem for the SBOM needs root, and talking to a network server must not.

| Process | Unit | User | Network | Does |
|---|---|---|---|---|
| collector | `holealign-collector.service` | root, group `holealign` | none (`PrivateNetwork=yes`, only `AF_UNIX`) | runs the fixed set of collectors and Syft, answers on `/run/holealign/collector.sock` |
| sender | `holealign-agent.service` | `holealign` | outbound HTTPS to `server_url` | enrolls, checks in, uploads inventories; the only process that talks to the server |

A bug in a parser that handles untrusted host data (a crafted config file or package database) is
therefore in a process that cannot open a connection, and the process with network access has no
root. The collector accepts only root and `collector_user`, checked by uid on the socket. `-mode all`
runs both roles in one process (used by `-once`, containers and tests); it gives up the separation.
More: [architecture.md](architecture.md#privilege-separation).

## systemd units

| Unit | Installed by | Notes |
|---|---|---|
| `holealign-server.service` | server package, or by hand | dynamic user, full sandboxing, `StateDirectory=holealign`, reads `/etc/holealign/server.env` |
| `holealign-collector.service` | agent package, `install.sh` (also `--collector-only`) | root, no network, 1 GiB memory and 50 % CPU cap |
| `holealign-agent.service` | agent package, `install.sh` (not `--collector-only`) | user `holealign`, requires the collector |

The units in `deploy/systemd/` are the source; `install.sh` embeds identical copies (a test compares
them). Change a unit with `systemctl edit`, not by editing the installed file.

## Verifying releases

Each release contains `checksums.txt`, its keyless Sigstore signature (`checksums.txt.sig` and
`checksums.txt.pem`), SPDX SBOMs for the archives (`*.spdx.json`), and GitHub build provenance
attestations. Signatures are made by the release workflow of this repository, and the certificate
identity is an exact string, not a pattern: a signature from any other workflow or tag is rejected.
Replace `X.Y.Z` with the release version (the tag is `vX.Y.Z`).

1. Verify that the checksum file was signed by the release workflow:

   ```sh
   cosign verify-blob --certificate checksums.txt.pem --signature checksums.txt.sig \
     --certificate-identity "https://github.com/DonSosiska/holealign/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt
   ```

2. Check the files you downloaded against it (`--ignore-missing` skips files you did not download):

   ```sh
   sha256sum -c checksums.txt --ignore-missing
   ```

3. Verify the server image (same exact identity; the image tag has no `v`):

   ```sh
   cosign verify ghcr.io/donsosiska/holealign-server:X.Y.Z \
     --certificate-identity "https://github.com/DonSosiska/holealign/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com
   ```

4. Verify the build provenance of an archive, `.deb` or `.rpm` (needs the [GitHub CLI](https://cli.github.com/)):

   ```sh
   gh attestation verify holealign-agent_X.Y.Z_linux_amd64.tar.gz --repo DonSosiska/holealign \
     --signer-workflow DonSosiska/holealign/.github/workflows/release.yml
   ```

`install.sh` does steps 1 and 2 for the agent archive itself. The release job runs in the `release`
environment (required reviewers) and refuses tags that are not on `main`: see
[security-model.md](security-model.md) and [development.md](development.md#release-process).

## Upgrading

Back up first ([operations.md](operations.md#backup-and-restore)). Database migrations run
automatically at server start; there is no downgrade path, so restore the backup to go back.

| What | How |
|---|---|
| Server, Compose | `git pull` (or change the image tag), `docker compose up -d --build` (or `pull`) |
| Server, package | install the new package; `/etc/holealign/server.yaml` is kept; `systemctl restart holealign-server` |
| Server, binary | replace `/usr/bin/holealign-server`, copy the new `rules/*.yaml`, restart |
| Agent, script | run `install.sh` again (optionally `--version X.Y.Z`). The existing config is kept; downgrades are refused unless `--allow-downgrade`. Use `--min-version` in automation. |
| Agent, package | install the new package; `agent.yaml` is kept |

The shipped rules are read at server start. After a rules update (new release), restart the server.
Rules edited or approved in the web UI live in the database and override same-ID shipped rules.

## Uninstalling

- **Agent, script:** `sudo sh install.sh --uninstall` removes the units and the binary and keeps the
  config and state; add `--force` to also remove `/etc/holealign/agent.yaml`, `ca.pem`,
  `/var/lib/holealign-agent` and the `holealign` user (only if it is a plain system account).
- **Agent, package:** `apt remove holealign-agent` / `dnf remove holealign-agent` (the services are
  stopped and disabled on removal).
- **Server, Compose:** `docker compose down` keeps the data volume; `docker compose down -v`
  deletes the database.
- **Server, package:** stop and disable the service, remove the package; `/var/lib/holealign` is
  left in place.
- On the server, remove a decommissioned host and its findings with
  `holealign-server host delete <id|hostname>`.

## Agentless mode

The server monitors its own host through a built-in local agent, without a separately installed
`holealign-agent` and without an enrollment token. It is off by default. The local agent runs the same
agent logic in the server process and feeds the same pipeline as a remote agent, so the host gets the
same facts, inventory, rules and alerts. In the web UI it is marked with a "local (built-in)" badge.
Every key is listed in [configuration.md](configuration.md#local-agent-agentless-mode).

```yaml
# /etc/holealign/server.yaml
local_agent:
  enabled: true
  source: collector       # collector | inprocess | auto (default auto)
  labels: [server]        # default
```

**Source choice.**

- `collector` (recommended for a host install): the server reads the host through the root collector's
  socket. The server then needs no root privileges, but it must run as the static user `holealign` (see
  below). It does not fall back: if the socket refuses the server, the local agent does not run.
- `inprocess`: the server collects the host itself with its own privileges. Without root, root-only data
  (for example `sshd -T`, `nginx -T`, `docker.sock`) is missing, and a WARN says so. Use it for dev or
  single-box setups.
- `auto` (default): uses `collector` when a real request to the socket succeeds, otherwise `inprocess`.
  The chosen source is logged at startup. Because `auto` falls back to `inprocess` without an error,
  check the logged source after the first start.

**Recommended setup (package or binary install with systemd):**

1. On the server host install the collector only: `sudo sh install.sh --collector-only`. It downloads and
   verifies the release like a normal install (or uses `--binary`), installs `/usr/bin/holealign-agent`,
   creates the system user and group `holealign`, writes a minimal `/etc/holealign/agent.yaml` (no sender,
   no token) and starts `holealign-collector.service` (root, no network). The socket is
   `/run/holealign/collector.sock`, `root:holealign 0660`.
2. Set `local_agent.enabled: true` and `local_agent.source: collector` (or `auto`) in `server.yaml`.
3. Run the server as the static user `holealign`. A systemd `DynamicUser` uid is rejected by the collector,
   and adding only `SupplementaryGroups=holealign` is **not enough**: the collector authorises the peer by
   its uid (`SO_PEERCRED`) and accepts only root and `collector_user` (default `holealign`). In the unit,
   the lines for this are commented out in `deploy/systemd/holealign-server.service`. Use a drop-in:

   ```ini
   # systemctl edit holealign-server
   [Service]
   DynamicUser=no
   User=holealign
   Group=holealign
   ```

   This is **unverified on a real host** (the unit comments say so; `PrivateUsers=yes` and
   `StateDirectory=` must be checked with a static user). Back up the database first, check that
   `data_dir` ends up owned by `holealign`, and check the first start in the logs.

4. `sudo systemctl restart holealign-server`, then check the log for `local agent source: collector`.

**Docker.** `source: inprocess` inside a container scans the container's own filesystem, not the Docker
host. To monitor the host, install the collector on the host (`--collector-only`), mount its socket
directory read-only, and run the container as the host's `holealign` user, as the commented example in
`deploy/docker-compose.yml` shows:

```yaml
services:
  holealign-server:
    user: "<holealign uid>:<holealign gid>"   # `id holealign` on the host
    group_add: ["<holealign gid>"]
    volumes:
      - /run/holealign:/run/holealign:ro
    environment:
      HOLEALIGN_LOCAL_AGENT_ENABLED: "true"
      HOLEALIGN_LOCAL_AGENT_SOURCE: collector
```

The data volume must be writable by that uid as well: the image owns `/var/lib/holealign` as uid 65532,
so change its ownership before you switch the user. With `source: auto` and no socket mounted, the
container falls back to scanning itself (the log says `inprocess`).

**Conflicts.** If a host with the same machine ID is already enrolled by a standalone agent (or an earlier
enrollment), the local agent does not take it over. It logs an ERROR, and the local agent does not start.
Either remove that host and uninstall the standalone agent, then restart the server:

```sh
holealign-server host list
holealign-server host delete <hostname>   # also deletes its findings
sudo systemctl restart holealign-server
```

or set `local_agent.enabled: false`. Details: [operations](troubleshooting.md#local-agent-agentless-mode).
