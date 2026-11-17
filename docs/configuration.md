# Configuration reference

Every key of the server configuration (`server.yaml`) and the agent configuration (`agent.yaml`),
with type, default, environment override and meaning. The tables follow the Go structs in
`internal/server/config/config.go` and `internal/agent/config/config.go`. Annotated examples are
`deploy/server.yaml.example`, `deploy/agent.yaml.example` and `deploy/server.env.example`.

Contents: [Server configuration](#server-configuration) -
[Environment variables](#environment-variables) - [Local agent (agentless mode)](#local-agent-agentless-mode) -
[Agent configuration](#agent-configuration) - [Example files](#example-files)

## Server configuration

The file is `/etc/panoptes/server.yaml`, or the path in `-config` or `PANOPTES_CONFIG`. An
explicitly named file must exist; with nothing named, the default path is read if it exists, and
otherwise built-in defaults apply (this is how the container image runs). Every key is optional.
**Unknown keys are an error** (a typo stops the server from starting). Secrets never go in this
file: they come from environment variables.

Value formats: durations are Go durations (`30m`, `6h`); `retention.*` also accepts days (`30d`,
`1d12h`) and a bare `0`. Lists are YAML lists in the file and comma-separated in environment
variables.

### Listeners and TLS

| Key | Type | Default | Environment | Description |
|---|---|---|---|---|
| `listen` | string | `:8080` | `PANOPTES_LISTEN` | Agent API listener: `/api/v1/*` and `/healthz` only; everything else is 404. |
| `admin_listen` | string | `127.0.0.1:8081` | `PANOPTES_ADMIN_LISTEN` | Admin web UI listener (and `/healthz`). Keep it on loopback. Empty or equal to `listen`: one shared port (legacy, logs a WARN, `admin_tls_*` ignored). |
| `public_url` | string | `http://localhost:8081` | `PANOPTES_PUBLIC_URL` | Base URL of the admin UI, used for links in alerts. An `https` URL makes the session cookie `Secure`. Trailing `/` is removed. |
| `tls_cert`, `tls_key` | string (path) | empty | `PANOPTES_TLS_CERT`, `PANOPTES_TLS_KEY` | Native TLS for the agent listener (TLS 1.2 minimum). Both or neither. |
| `admin_tls_cert`, `admin_tls_key` | string (path) | empty | `PANOPTES_ADMIN_TLS_CERT`, `PANOPTES_ADMIN_TLS_KEY` | Native TLS for the admin listener. Both or neither. |
| `trusted_proxies` | list of CIDR or IP | `[]` | `PANOPTES_TRUSTED_PROXIES` | Reverse proxies whose `X-Forwarded-For` is trusted for the client address (rate limits, audit log). Bare IPs are `/32` or `/128`. WARN for entries wider than `/16` (IPv4) or `/48` (IPv6). |

### Storage and rules

| Key | Type | Default | Environment | Description |
|---|---|---|---|---|
| `data_dir` | string (path) | `/var/lib/panoptes` | `PANOPTES_DATA_DIR` | SQLite database `panoptes.db` and Grype DB cache `grype-db/`. Must not be empty. Must match `StateDirectory` of the systemd unit. |
| `rules_dir` | string (path) | `/usr/share/panoptes/rules` | `PANOPTES_RULES_DIR` | Directory of shipped rule YAML files. |
| `retention.resolved_findings` | duration | `30d` | `PANOPTES_RETENTION_RESOLVED_FINDINGS` | Delete resolved findings older than this (daily and at start). `0` keeps them forever. |
| `retention.notifications` | duration | `90d` | `PANOPTES_RETENTION_NOTIFICATIONS` | Delete notification dedup rows older than this. Rows of still-open findings are kept. `0` keeps forever. |
| `limits.findings_per_host` | int | `20000` | `PANOPTES_LIMITS_FINDINGS_PER_HOST` | Open findings kept per host; the lowest severities are dropped first (WARN and a `pipeline_error` alert). `0` = unlimited. |
| `limits.match_seconds_per_host_hour` | int | `900` | `PANOPTES_LIMITS_MATCH_SECONDS_PER_HOST_HOUR` | Cumulative Grype time one host may use per rolling hour; runs over budget are deferred (WARN and `pipeline_error` alert). `0` = unlimited. |

### Feeds and alerts

| Key | Type | Default | Environment | Description |
|---|---|---|---|---|
| `feeds.interval` | duration | `6h` | `PANOPTES_FEEDS_INTERVAL` | Vulnerability data refresh period (Grype DB with KEV and EPSS). Must be positive. |
| `feeds.update` | bool | `true` | `PANOPTES_FEEDS_UPDATE` | `false` disables all network updates (air-gapped, tests). |
| `alerts.agent_silent_after` | duration | `30m` | `PANOPTES_ALERTS_AGENT_SILENT_AFTER` | Alert when a host has not checked in for this long. `0` disables `agent_silent` / `agent_back`. |
| `alerts.feed_stale_after` | duration | `48h` | `PANOPTES_ALERTS_FEED_STALE_AFTER` | Alert when the vulnerability DB is older than this or refreshing keeps failing. `0` disables `feed_stale` / `feed_ok`. |
| `alerts.ops_rooms` | list of room IDs | `[]` | `PANOPTES_ALERTS_OPS_ROOMS` | Matrix rooms for server-level events (feed, pipeline, mass silence). Empty: `matrix.default_rooms`. |

### Matrix

| Key | Type | Default | Environment | Description |
|---|---|---|---|---|
| `matrix.homeserver` | string (URL) | empty | `PANOPTES_MATRIX_HOMESERVER` | Homeserver base URL. Empty disables Matrix. |
| `matrix.access_token_env` | string | `PANOPTES_MATRIX_TOKEN` | `PANOPTES_MATRIX_ACCESS_TOKEN_ENV` | Name of the environment variable that holds the bot's access token. |
| `matrix.default_rooms` | list of room IDs | `[]` | `PANOPTES_MATRIX_DEFAULT_ROOMS` | Rooms used when no label route matches. Room IDs look like `!abc:example.com` (not aliases). |
| `matrix.routes` | list of `{label, rooms}` | `[]` | not overridable | Label to rooms. Merged with the routes edited in the web UI. |

### LLM

| Key | Type | Default | Environment | Description |
|---|---|---|---|---|
| `llm.provider` | string | `none` | `PANOPTES_LLM_PROVIDER` | `none`, `anthropic` or `openai-compatible`. |
| `llm.model` | string | `claude-sonnet-5-5` | `PANOPTES_LLM_MODEL` | Model name sent to the provider. |
| `llm.base_url` | string (URL) | empty | `PANOPTES_LLM_BASE_URL` | Required for `openai-compatible` (e.g. `http://ollama:11434/v1`); optional endpoint override for `anthropic`. |
| `llm.api_key_env` | string | `PANOPTES_LLM_API_KEY` | `PANOPTES_LLM_API_KEY_ENV` | Name of the environment variable that holds the API key. |
| `llm.daily_limit` | int | `50` | `PANOPTES_LLM_DAILY_LIMIT` | Maximum drafting calls per day. A value of `0` or less falls back to 50. |

### Admin

| Key | Type | Default | Environment | Description |
|---|---|---|---|---|
| `admin.initial_password_env` | string | `PANOPTES_ADMIN_PASSWORD` | `PANOPTES_ADMIN_INITIAL_PASSWORD_ENV` | Name of the environment variable holding the password for user `admin`; used only when no web user exists. `PANOPTES_ADMIN_PASSWORD_FILE` takes precedence. Minimum 12 characters. |

### Validation

The server refuses to start when:

- `feeds.interval` is not positive, `data_dir` is empty, or `alerts.*_after` is negative;
- only one of `tls_cert`/`tls_key` (or `admin_tls_cert`/`admin_tls_key`) is set, or `trusted_proxies`
  contains something that is not an IP or CIDR;
- a `*_env` name does not match `^PANOPTES_[A-Z0-9_]+$`, or `matrix.access_token_env`,
  `llm.api_key_env` and `admin.initial_password_env` are not pairwise different;
- `retention.*` or `limits.*` is negative;
- a configured certificate cannot be loaded, or the initial admin password is shorter than 12 characters.

Warnings logged at start (non-fatal): `http://` `public_url`, `matrix.homeserver` or `llm.base_url` on a
non-loopback host; broad `trusted_proxies`; a non-loopback `admin_listen` without admin TLS; a
non-loopback `listen` with neither `tls_cert` nor `trusted_proxies`; a single shared port.

## Environment variables

| Variable | Used by | Meaning |
|---|---|---|
| `PANOPTES_CONFIG` | server | Path to `server.yaml`. |
| `PANOPTES_<SECTION>_<KEY>` | server | Overrides any scalar or string-list key (table above). Empty values are ignored. Top-level keys: `PANOPTES_<KEY>`. |
| `PANOPTES_MATRIX_TOKEN` | server | Matrix access token (the variable named by `matrix.access_token_env`). |
| `PANOPTES_LLM_API_KEY` | server | LLM API key (the variable named by `llm.api_key_env`). |
| `PANOPTES_ADMIN_PASSWORD` | server | Initial password of `admin` (the variable named by `admin.initial_password_env`). |
| `PANOPTES_ADMIN_PASSWORD_FILE` | server | File holding the initial password; takes precedence over the variable. |
| `PANOPTES_AGENT_CONFIG` | agent | Path to `agent.yaml` (the `-config` flag wins). |
| `PANOPTES_ENROLL_TOKEN`, `PANOPTES_REPO` | `install.sh` | Enrollment token; GitHub `owner/name` to download from. |

The agent has no environment overrides for its keys.

## Local agent (agentless mode)

New. The `local_agent` section makes the server monitor its own host. It is not available in
releases before the one that adds agentless mode. Setup steps and caveats:
[installation.md](installation.md#agentless-mode).

| Key | Type | Default | Environment | Description |
|---|---|---|---|---|
| `local_agent.enabled` | bool | `false` | `PANOPTES_LOCAL_AGENT_ENABLED` | Enable the built-in local agent. |
| `local_agent.source` | string | see installation | `PANOPTES_LOCAL_AGENT_SOURCE` | `collector` (root collector socket), `inprocess` (collect inside the server process; in Docker this scans the container) or `auto` (collector socket if present, else in-process). |
| `local_agent.collector_socket` | string (path) | `/run/panoptes/collector.sock` | `PANOPTES_LOCAL_AGENT_COLLECTOR_SOCKET` | Collector socket. The server unit needs `SupplementaryGroups=panoptes` for `source: collector`. |
| `local_agent.labels` | list of strings | `[server]` | `PANOPTES_LOCAL_AGENT_LABELS` | Labels of the local host. Authoritative. |
| `local_agent.checkin_interval` | duration | as the agent | `PANOPTES_LOCAL_AGENT_CHECKIN_INTERVAL` | Like the agent key of the same name. |
| `local_agent.inventory_interval` | duration | as the agent | `PANOPTES_LOCAL_AGENT_INVENTORY_INTERVAL` | Like the agent key. |
| `local_agent.scan_language_packages` | bool | as the agent | `PANOPTES_LOCAL_AGENT_SCAN_LANGUAGE_PACKAGES` | Like the agent key. |
| `local_agent.exclude_paths` | list of globs | as the agent | `PANOPTES_LOCAL_AGENT_EXCLUDE_PATHS` | Like the agent key. |
| `local_agent.docker_socket` | string (path) | as the agent | `PANOPTES_LOCAL_AGENT_DOCKER_SOCKET` | Like the agent key. |

A host with the same machine ID that is already enrolled by a standalone agent makes the local
agent refuse to start.

## Agent configuration

The file is `/etc/panoptes/agent.yaml` (or `-config`, or `PANOPTES_AGENT_CONFIG`; the flag wins).
The systemd install makes it `root:panoptes 0640` because it holds the enrollment token until the
first successful check-in. Unlike the server file, unknown keys are ignored. Defaults apply for
every key not listed as required. Durations are Go durations.

| Key | Type | Default | Description |
|---|---|---|---|
| `server_url` | string | **required** | Server base URL. `https://` with a host and no `user:password@`; a trailing `/` is removed; redirects are never followed. TLS 1.2 or newer. |
| `allow_insecure_http` | bool | `false` | Permit an `http://` `server_url` (testing only; a WARN is logged). |
| `enroll_token` | string | empty | Token from `panoptes-server token create`. Used until enrolled; blanked in the file by the collector after the first successful check-in. A host that lost its credentials needs a fresh token here. |
| `labels` | list of strings | `[]` | Labels for alert routing. Lowercase `^[a-z0-9][a-z0-9._-]{0,63}$`, at most 32. Ignored by the server when the enrollment token has labels. |
| `state_dir` | string (path) | `/var/lib/panoptes-agent` | Where `agent_id` and `agent_key` are stored (0600). Must match `StateDirectory` of the unit. Must not be empty. |
| `checkin_interval` | duration | `5m` | How often the agent checks in. Must be positive. The server can suggest another value; the agent clamps it to 60 s - 1 h. |
| `inventory_interval` | duration | `6h` | Safety-net full rescan. Package database or image changes trigger an earlier scan. Must be positive. |
| `docker_socket` | string (path) | `/var/run/docker.sock` | Container images are scanned when the socket exists. |
| `scan_language_packages` | bool | `true` | Also scan language packages (pip, npm, gems, ...), not only OS packages. |
| `exclude_paths` | list of globs | `/proc`, `/sys`, `/dev`, `/run`, `/var/lib/docker`, `/var/lib/containerd`, `/snap`, `/mnt`, `/media`, `/var/lib/containers`, `/var/lib/kubelet`, `/var/lib/lxc`, `/var/lib/lxd`, `/home/*/.cache` | Paths skipped by the filesystem scan. Setting the key replaces the whole default list. |
| `host_scan_timeout` | duration | `10m` | Time limit for the host scan. A timeout or crash is reported as the `agent.inventory_error` fact. Must be positive. |
| `image_scan_timeout` | duration | `5m` | Time limit per image scan. Must be positive. |
| `ca_file` | string (path) | empty | PEM bundle. When set, **only** these roots are trusted (no system roots). Must contain a PEM certificate. |
| `server_cert_sha256` | list of strings | `[]` | Hex SHA-256 of the server leaf certificate's SPKI, 64 characters (colons and upper case accepted). The handshake must present a leaf with one of these hashes, in addition to normal chain validation. List the next key before rotating. |
| `client_cert`, `client_key` | string (path) | empty | Optional mTLS client certificate and key (PEM). Both or neither; must be readable by group `panoptes`. |
| `collector_socket` | string (path) | `/run/panoptes/collector.sock` | Unix socket of the collector (absolute path). Unused with `-mode all`. |
| `collector_user` | string | `panoptes` | User allowed on the socket besides root; its primary group owns the socket. |

Agent command-line flags: [installation.md](installation.md#manual-install).

## Example files

- [deploy/server.yaml.example](../deploy/server.yaml.example) - server configuration with the defaults.
- [deploy/server.env.example](../deploy/server.env.example) - secrets and common overrides.
- [deploy/agent.yaml.example](../deploy/agent.yaml.example) - agent configuration.
- [deploy/docker-compose.yml](../deploy/docker-compose.yml) - single-host server.
