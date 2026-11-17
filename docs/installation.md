# Installation

How to install the Panoptes server (Docker Compose, `.deb`/`.rpm` packages, or a plain binary with
systemd), how to put TLS in front of it, how to install agents on monitored hosts (`install.sh`,
packages, or by hand), how to verify releases, how to upgrade and uninstall, and how to run
agentless mode. Every configuration key is listed in [configuration.md](configuration.md).

Contents: [Server](#server) - [TLS](#tls) - [First admin user](#first-admin-user) -
[Agents](#agents) - [Verifying releases](#verifying-releases) - [Upgrading](#upgrading) -
[Uninstalling](#uninstalling) - [Agentless mode](#agentless-mode)

## Server

Pick one. All three run the same `panoptes-server serve`. The server needs outbound HTTPS for the
vulnerability feed (Grype DB, about 100 MB on first start) and, if configured, Matrix, the LLM and
OSV (advisory text for drafting). Without outbound access see
[air-gapped feeds](operations.md#air-gapped-and-feed-updates).

### Docker Compose

```sh
git clone https://github.com/DonSosiska/panoptes.git
cd panoptes/deploy
cp server.env.example .env       # edit: PANOPTES_ADMIN_PASSWORD (12+ chars), PANOPTES_PUBLIC_URL, Matrix, LLM
docker compose up -d --build     # builds from source (deploy/Dockerfile.server.build)
docker compose logs -f panoptes-server
```

To use the signed prebuilt image instead of building, edit `deploy/docker-compose.yml`: remove the
`build:` block and set `image: ghcr.io/donsosiska/panoptes-server:X.Y.Z` (pin a version; verify the
image first, see [Verifying releases](#verifying-releases)).

What the shipped Compose file does:

| Setting | Value |
|---|---|
| Ports | `8080:8080` (agent API, all interfaces) and `127.0.0.1:8081:8081` (admin UI, host loopback only) |
| Container | read-only root filesystem, `/tmp` tmpfs, all capabilities dropped, `no-new-privileges`, 4 GiB memory limit, 512 pids |
| Data | named volume `panoptes-data` at `/var/lib/panoptes` (database and Grype DB) |
| Config | no `server.yaml`: defaults plus `PANOPTES_*` environment variables from `deploy/.env` |
| Admin listener | `PANOPTES_ADMIN_LISTEN=0.0.0.0:8081` inside the container; the published port restricts it to the host's loopback |
| Healthcheck | none (the image is distroless: no shell, no curl). Use `docker compose logs`, or `GET /healthz` on port 8080 |

To use a `server.yaml`, mount it and point `PANOPTES_CONFIG` at it:

```yaml
# deploy/docker-compose.override.yml
services:
  panoptes-server:
    environment:
      PANOPTES_CONFIG: /etc/panoptes/server.yaml
    volumes:
      - ./server.yaml:/etc/panoptes/server.yaml:ro
```

An explicitly named config file that does not exist is a startup error, so do not set
`PANOPTES_CONFIG` without mounting the file.

### Packages (.deb, .rpm)

Download `panoptes-server_X.Y.Z_<arch>.deb` or `.rpm` from the
[releases page](https://github.com/DonSosiska/panoptes/releases), verify it
([Verifying releases](#verifying-releases)), then:

```sh
sudo apt install ./panoptes-server_X.Y.Z_amd64.deb        # Debian, Ubuntu
sudo dnf install ./panoptes-server_X.Y.Z_<arch>.rpm       # RHEL family (use the file name of the release asset)
```

The package installs `/usr/bin/panoptes-server`, the unit `panoptes-server.service`,
`/etc/panoptes/server.yaml` (a copy of `deploy/server.yaml.example`, kept on upgrade) and the
shipped rules in `/usr/share/panoptes/rules/`. It does **not** enable or start the service and does
not create `server.env`. Create it (secrets, mode 0600), then start:

```sh
sudo install -m 0600 /dev/null /etc/panoptes/server.env
sudoedit /etc/panoptes/server.env        # PANOPTES_ADMIN_PASSWORD=..., PANOPTES_MATRIX_TOKEN=..., PANOPTES_LLM_API_KEY=...
sudoedit /etc/panoptes/server.yaml       # at least public_url, matrix, TLS or trusted_proxies
sudo systemctl enable --now panoptes-server
journalctl -u panoptes-server -f
```

The unit runs as a systemd dynamic user with full sandboxing; state is in `/var/lib/panoptes`
(`StateDirectory=panoptes`, which must match `data_dir`). See `deploy/systemd/panoptes-server.service`.

### Binary and systemd

```sh
V=X.Y.Z; A=amd64                         # or arm64
curl -fsSLO https://github.com/DonSosiska/panoptes/releases/download/v$V/panoptes-server_${V}_linux_${A}.tar.gz
curl -fsSLO https://github.com/DonSosiska/panoptes/releases/download/v$V/checksums.txt
curl -fsSLO https://github.com/DonSosiska/panoptes/releases/download/v$V/checksums.txt.sig
curl -fsSLO https://github.com/DonSosiska/panoptes/releases/download/v$V/checksums.txt.pem
# verify (see "Verifying releases"), then:
tar -xzf panoptes-server_${V}_linux_${A}.tar.gz panoptes-server
sudo install -m 0755 panoptes-server /usr/bin/panoptes-server
# from a checkout of the same tag:
sudo install -d /etc/panoptes /usr/share/panoptes/rules
sudo install -m 0644 deploy/server.yaml.example /etc/panoptes/server.yaml
sudo install -m 0644 rules/*.yaml /usr/share/panoptes/rules/
sudo install -m 0644 deploy/systemd/panoptes-server.service /etc/systemd/system/
sudo systemctl daemon-reload
```

Then create `/etc/panoptes/server.env` and start the service as in the package instructions. The
server also runs without systemd (`panoptes-server -config server.yaml serve`); then you provide the
sandboxing and the data directory yourself.

## TLS

Agents require `https://` (unless `allow_insecure_http` is set, for tests only) and always verify
the chain. The server logs a WARN when it is reachable without TLS (non-loopback `listen` with no
`tls_cert` and no `trusted_proxies`, or a non-loopback `admin_listen` without `admin_tls_cert`).
There are two supported setups.

### Native TLS

```yaml
# /etc/panoptes/server.yaml
tls_cert: /etc/panoptes/agent.crt       # agent API listener; TLS 1.2 minimum
tls_key:  /etc/panoptes/agent.key
admin_tls_cert: /etc/panoptes/admin.crt # admin UI listener (optional; keep it on loopback or a VPN anyway)
admin_tls_key:  /etc/panoptes/admin.key
public_url: https://panoptes-admin.example.com
```

Both files of a pair are required. Certificates are read at start: restart the server after
renewing them. With the packaged unit the service runs as a dynamic user that cannot read a
root-only key; hand the files to it with a drop-in (systemd 247 or newer):

```ini
# systemctl edit panoptes-server
[Service]
LoadCredential=agent.key:/etc/panoptes/agent.key
LoadCredential=agent.crt:/etc/panoptes/agent.crt
```

and set `tls_key: /run/credentials/panoptes-server.service/agent.key` and `tls_cert` likewise. In
Docker, mount the files read-only and set `PANOPTES_TLS_CERT` / `PANOPTES_TLS_KEY` to their paths
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
    server_name panoptes.example.com;
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
and set `PANOPTES_PUBLIC_URL`. Single-port mode (`admin_listen` empty or equal to `listen`)
exists for legacy setups and logs a WARN: every monitored host could then reach the login page.

## First admin user

On first start, when no web user exists, the server creates the user `admin` with the password from
`PANOPTES_ADMIN_PASSWORD` (the variable named by `admin.initial_password_env`), or from the file
named by `PANOPTES_ADMIN_PASSWORD_FILE`, which takes precedence and keeps the secret out of the
process environment and `docker inspect`. The password must have at least 12 characters, otherwise
the server refuses to start. After the first start the variable is unused: remove it from
`server.env` / `.env`.

With Compose, a file-based secret:

```yaml
# deploy/docker-compose.override.yml (the file must be readable by uid 65532)
services:
  panoptes-server:
    environment:
      PANOPTES_ADMIN_PASSWORD_FILE: /run/secrets/panoptes_admin
    secrets: [panoptes_admin]
secrets:
  panoptes_admin:
    file: ./admin_password.txt
```

If no password is configured the server starts without any user and logs a WARN. Create or change a
user later from the command line (password on stdin, 12+ characters):

```sh
docker compose exec -T panoptes-server panoptes-server user set-password admin <<< 'a-long-password'
```

For packages, start the service once first so the data directory exists, then run
`sudo panoptes-server user set-password admin` and type the password on stdin. More: [operations.md](operations.md#cli-reference).

## Agents

The agent is one binary with two services: `panoptes-collector` (root, no network) and
`panoptes-agent` (user `panoptes`). See [architecture.md](architecture.md#privilege-separation).
Create an enrollment token on the server first:

```sh
panoptes-server token create web-prod -labels prod,web -max-hosts 20 -expires 72h
```

Use short-lived tokens per group of hosts with labels and a `max_hosts` cap
([security-model.md](security-model.md#operator-hardening-checklist)). Labels are lowercase:
`^[a-z0-9][a-z0-9._-]{0,63}$`, at most 32.

### install.sh

```sh
curl --proto '=https' --tlsv1.2 -fsSLO https://raw.githubusercontent.com/DonSosiska/panoptes/main/deploy/install.sh
less install.sh
sudo sh install.sh --server https://panoptes.example.com --token-file /root/panoptes.token --labels prod,web
```

`install.sh` needs root, Linux, systemd, `curl`, `tar` and a SHA-256 tool (it installs missing
ones with the system package manager). It supports amd64 and arm64. It creates the system user
`panoptes` (it aborts if a `panoptes` user exists that is not a plain system account), downloads the
release for your architecture, verifies it, installs `/usr/bin/panoptes-agent`, writes the config,
installs both units, and runs `systemctl enable --now` for `panoptes-collector` and
`panoptes-agent`. The token is written only to the config file and never printed. It is removed from
the file after the first successful check-in.

| Flag | Meaning |
|---|---|
| `--server URL` | Server base URL: `https://`, no `user:password@`. Required when writing a config. |
| `--token-file PATH` | Read the enrollment token from this file. Preferred. |
| `--token TOKEN` | Token on the command line (visible in `ps` and shell history; a warning is printed). |
| *(env)* `PANOPTES_ENROLL_TOKEN` | Token from the environment. One of the three is required on first install. |
| `--labels a,b` | Comma-separated labels (letters, digits, `.`, `_`, `-`). Ignored by the server when the token itself has labels. |
| `--ca-file PATH` | PEM bundle of the CA(s) signing the server certificate. Copied to `/etc/panoptes/ca.pem`; when set, **only** these roots are trusted. |
| `--server-pin HEX` | Pin the server key: SHA-256 of the certificate's SubjectPublicKeyInfo (64 hex chars). Repeatable. Get it with `panoptes-agent -print-server-pin`. |
| `--allow-insecure-http` | Accept an `http://` `--server` (testing only; the agent key travels in cleartext). |
| `--version VER` | Release to install (`1.2.3` or `v1.2.3`); default: latest. The signature identity is pinned to exactly this tag. |
| `--min-version X.Y.Z` | Refuse to install an older release. |
| `--allow-downgrade` | Allow installing an older release than the installed one (refused by default). |
| `--binary PATH` | Install this local `panoptes-agent` binary instead of downloading (air-gapped). No signature check is done for it. |
| `--skip-signature-check` | Do not verify the release signature (not recommended). Without it the install aborts when cosign is missing. |
| `--collector-only` | For agentless mode: install the root collector (`panoptes-collector.service`), the `panoptes` user and group, and a minimal `agent.yaml`, but no sender (`panoptes-agent.service`). No `--server` or token. The release is still downloaded and verified (or use `--binary`). See [Agentless mode](#agentless-mode). |
| `--force` | Overwrite an existing `/etc/panoptes/agent.yaml`. With `--uninstall`: also remove the config and state. |
| `--uninstall` | Stop and remove the units and the binary. |
| `-h`, `--help` | Show the built-in help. |
| *(env)* `PANOPTES_REPO` | Download from another GitHub `owner/name` (default `DonSosiska/panoptes`). The signature identity then names that repository. |

Notes:

- With an existing `/etc/panoptes/agent.yaml` and no `--force`, the config is kept and `--server`,
  `--token` and `--labels` are not applied (a warning says so). Re-running the script is the
  upgrade path.
- Private CA example: `--ca-file ./ca.pem --server-pin "$(panoptes-agent -print-server-pin)"`.
  `-print-server-pin` validates the chain first, so it is a convenience, not trust on first use:
  compare the value out of band. List the next key too before rotating a certificate.
- Hosts without internet: download the archive on another machine, verify it, copy it over, and
  use `--binary`.

### Packages

```sh
sudo apt install ./panoptes-agent_X.Y.Z_amd64.deb      # or: sudo dnf install ./panoptes-agent_X.Y.Z_<arch>.rpm
sudoedit /etc/panoptes/agent.yaml                      # server_url, enroll_token, labels
sudo systemctl restart panoptes-collector panoptes-agent
```

The package creates the user `panoptes`, installs both units and `/etc/panoptes/agent.yaml`
(`root:panoptes`, 0640, kept on upgrade) and enables the services without starting them. Verify the
package as described in [Verifying releases](#verifying-releases). Packages are not signed with apt
or rpm keys.

### Manual install

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin panoptes
sudo install -m 0755 panoptes-agent /usr/bin/panoptes-agent
sudo install -d /etc/panoptes
sudo install -o root -g panoptes -m 0640 deploy/agent.yaml.example /etc/panoptes/agent.yaml   # then edit
sudo install -m 0644 deploy/systemd/panoptes-collector.service deploy/systemd/panoptes-agent.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now panoptes-collector panoptes-agent
```

For a one-off check on any host without services:

```sh
panoptes-agent -print-facts          # collected facts as JSON, no server needed
panoptes-agent -print-inventory      # SBOM payload as JSON
panoptes-agent -config agent.yaml -once   # one check-in and upload, then exit (-mode all)
```

All agent flags: `-config`, `-mode all|collector|sender`, `-once`, `-print-facts`,
`-print-inventory`, `-print-server-pin`, `-log-level debug|info|warn|error`, `-version`.
Config keys: [configuration.md](configuration.md#agent-configuration).

## Verifying releases

Each release contains `checksums.txt`, its keyless Sigstore signature (`checksums.txt.sig` and
`checksums.txt.pem`), SPDX SBOMs for the archives (`*.spdx.json`), and GitHub build provenance
attestations. Signatures are made by the release workflow of this repository, and the certificate
identity is an exact string, not a pattern: a signature from any other workflow or tag is rejected.
Replace `X.Y.Z` with the release version (the tag is `vX.Y.Z`).

1. Verify that the checksum file was signed by the release workflow:

   ```sh
   cosign verify-blob --certificate checksums.txt.pem --signature checksums.txt.sig \
     --certificate-identity "https://github.com/DonSosiska/panoptes/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt
   ```

2. Check the files you downloaded against it (`--ignore-missing` skips files you did not download):

   ```sh
   sha256sum -c checksums.txt --ignore-missing
   ```

3. Verify the server image (same exact identity; the image tag has no `v`):

   ```sh
   cosign verify ghcr.io/donsosiska/panoptes-server:X.Y.Z \
     --certificate-identity "https://github.com/DonSosiska/panoptes/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com
   ```

4. Verify the build provenance of an archive, `.deb` or `.rpm` (needs the [GitHub CLI](https://cli.github.com/)):

   ```sh
   gh attestation verify panoptes-agent_X.Y.Z_linux_amd64.tar.gz --repo DonSosiska/panoptes \
     --signer-workflow DonSosiska/panoptes/.github/workflows/release.yml
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
| Server, package | install the new package; `/etc/panoptes/server.yaml` is kept; `systemctl restart panoptes-server` |
| Server, binary | replace `/usr/bin/panoptes-server`, copy the new `rules/*.yaml`, restart |
| Agent, script | run `install.sh` again (optionally `--version X.Y.Z`). The existing config is kept; downgrades are refused unless `--allow-downgrade`. Use `--min-version` in automation. |
| Agent, package | install the new package; `agent.yaml` is kept |

The shipped rules are read at server start. After a rules update (new release), restart the server.
Rules edited or approved in the web UI live in the database and override same-ID shipped rules.

## Uninstalling

- **Agent, script:** `sudo sh install.sh --uninstall` removes the units and the binary and keeps the
  config and state; add `--force` to also remove `/etc/panoptes/agent.yaml`, `ca.pem`,
  `/var/lib/panoptes-agent` and the `panoptes` user (only if it is a plain system account).
- **Agent, package:** `apt remove panoptes-agent` / `dnf remove panoptes-agent` (the services are
  stopped and disabled on removal).
- **Server, Compose:** `docker compose down` keeps the data volume; `docker compose down -v`
  deletes the database.
- **Server, package:** stop and disable the service, remove the package; `/var/lib/panoptes` is
  left in place.
- On the server, remove a decommissioned host and its findings with
  `panoptes-server host delete <id|hostname>`.

## Agentless mode

The server monitors its own host through a built-in local agent, without a separately installed
`panoptes-agent` and without an enrollment token. It is off by default. The local agent runs the same
agent logic in the server process and feeds the same pipeline as a remote agent, so the host gets the
same facts, inventory, rules and alerts. In the web UI it is marked with a "local (built-in)" badge.
Every key is listed in [configuration.md](configuration.md#local-agent-agentless-mode).

```yaml
# /etc/panoptes/server.yaml
local_agent:
  enabled: true
  source: collector       # collector | inprocess | auto (default auto)
  labels: [server]        # default
```

**Source choice.**

- `collector` (recommended for a host install): the server reads the host through the root collector's
  socket. The server then needs no root privileges, but it must run as the static user `panoptes` (see
  below). It does not fall back: if the socket refuses the server, the local agent does not run.
- `inprocess`: the server collects the host itself with its own privileges. Without root, root-only data
  (for example `sshd -T`, `nginx -T`, `docker.sock`) is missing, and a WARN says so. Use it for dev or
  single-box setups.
- `auto` (default): uses `collector` when a real request to the socket succeeds, otherwise `inprocess`.
  The chosen source is logged at startup. Because `auto` falls back to `inprocess` without an error,
  check the logged source after the first start.

**Recommended setup (package or binary install with systemd):**

1. On the server host install the collector only: `sudo sh install.sh --collector-only`. It downloads and
   verifies the release like a normal install (or uses `--binary`), installs `/usr/bin/panoptes-agent`,
   creates the system user and group `panoptes`, writes a minimal `/etc/panoptes/agent.yaml` (no sender,
   no token) and starts `panoptes-collector.service` (root, no network). The socket is
   `/run/panoptes/collector.sock`, `root:panoptes 0660`.
2. Set `local_agent.enabled: true` and `local_agent.source: collector` (or `auto`) in `server.yaml`.
3. Run the server as the static user `panoptes`. A systemd `DynamicUser` uid is rejected by the collector,
   and adding only `SupplementaryGroups=panoptes` is **not enough**: the collector authorises the peer by
   its uid (`SO_PEERCRED`) and accepts only root and `collector_user` (default `panoptes`). In the unit,
   the lines for this are commented out in `deploy/systemd/panoptes-server.service`. Use a drop-in:

   ```ini
   # systemctl edit panoptes-server
   [Service]
   DynamicUser=no
   User=panoptes
   Group=panoptes
   ```

   This is **unverified on a real host** (the unit comments say so; `PrivateUsers=yes` and
   `StateDirectory=` must be checked with a static user). Back up the database first, check that
   `data_dir` ends up owned by `panoptes`, and check the first start in the logs.

4. `sudo systemctl restart panoptes-server`, then check the log for `local agent source: collector`.

**Docker.** `source: inprocess` inside a container scans the container's own filesystem, not the Docker
host. To monitor the host, install the collector on the host (`--collector-only`), mount its socket
directory read-only, and run the container as the host's `panoptes` user, as the commented example in
`deploy/docker-compose.yml` shows:

```yaml
services:
  panoptes-server:
    user: "<panoptes uid>:<panoptes gid>"   # `id panoptes` on the host
    group_add: ["<panoptes gid>"]
    volumes:
      - /run/panoptes:/run/panoptes:ro
    environment:
      PANOPTES_LOCAL_AGENT_ENABLED: "true"
      PANOPTES_LOCAL_AGENT_SOURCE: collector
```

The data volume must be writable by that uid as well: the image owns `/var/lib/panoptes` as uid 65532,
so change its ownership before you switch the user. With `source: auto` and no socket mounted, the
container falls back to scanning itself (the log says `inprocess`).

**Conflicts.** If a host with the same machine ID is already enrolled by a standalone agent (or an earlier
enrollment), the local agent does not take it over. It logs an ERROR, and the local agent does not start.
Either remove that host and uninstall the standalone agent, then restart the server:

```sh
panoptes-server host list
panoptes-server host delete <hostname>   # also deletes its findings
sudo systemctl restart panoptes-server
```

or set `local_agent.enabled: false`. Details: [operations](operations.md#troubleshooting).
