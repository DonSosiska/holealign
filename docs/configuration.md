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
| `rules_dir` | string (path) | `/usr/share/panoptes/rules` | `PANOPTES_RULES_DIR` | Optional directory of rule YAML files. The eight shipped rules are embedded in the binary, so a missing directory is fine; files here add rules and replace embedded ones with the same `id`. |
| `retention.resolved_findings` | duration | `30d` | `PANOPTES_RETENTION_RESOLVED_FINDINGS` | Delete resolved findings older than this (daily and at start). `0` keeps them forever. |
| `retention.notifications` | duration | `90d` | `PANOPTES_RETENTION_NOTIFICATIONS` | Delete notification dedup rows older than this. Rows of still-open findings are kept. `0` keeps forever. |
| `limits.findings_per_host` | int | `20000` | `PANOPTES_LIMITS_FINDINGS_PER_HOST` | Open findings kept per host, applied after rule evaluation: exploitable findings are kept first, then `conditions_unknown`, then by KEV/severity/CVSS (WARN and a `pipeline_error` alert). Findings dropped by the cap are never reported as resolved. `0` = unlimited. |
| `limits.match_seconds_per_host_hour` | int | `900` | `PANOPTES_LIMITS_MATCH_SECONDS_PER_HOST_HOUR` | Cumulative Grype time one host may use per rolling hour; runs over budget are deferred (WARN and `pipeline_error` alert). `0` = unlimited. |
| `limits.inventory_attempts_per_minute` | int | `10` | `PANOPTES_LIMITS_INVENTORY_ATTEMPTS_PER_MINUTE` | Per-host refill rate of the bucket charged by every inventory request before its body is read (identical-hash uploads included); over it: 429 + `Retry-After`. `0` = default. |
| `limits.inventory_attempt_burst` | int | `6` | `PANOPTES_LIMITS_INVENTORY_ATTEMPT_BURST` | Burst size of that bucket. `0` = default. |
| `limits.inventory_concurrent_decodes` | int | `4` | `PANOPTES_LIMITS_INVENTORY_CONCURRENT_DECODES` | Inventory bodies decoded at once, server-wide (one per host); when all slots are busy: 503 + `Retry-After`. `0` = default. |

### Feeds and alerts

| Key | Type | Default | Environment | Description |
|---|---|---|---|---|
| `feeds.interval` | duration | `6h` | `PANOPTES_FEEDS_INTERVAL` | Vulnerability data refresh period (Grype DB with KEV and EPSS). Must be positive. |
| `feeds.update` | bool | `true` | `PANOPTES_FEEDS_UPDATE` | `false` disables all network updates (air-gapped, tests). |
| `alerts.agent_silent_after` | duration | `30m` | `PANOPTES_ALERTS_AGENT_SILENT_AFTER` | Alert when a host has not checked in for this long. `0` disables `agent_silent` / `agent_back`. |
| `alerts.feed_stale_after` | duration | `48h` | `PANOPTES_ALERTS_FEED_STALE_AFTER` | Alert when the vulnerability DB is older than this or refreshing keeps failing. `0` disables `feed_stale` / `feed_ok`. |
| `alerts.ops_rooms` | list of room IDs | `[]` | `PANOPTES_ALERTS_OPS_ROOMS` | Matrix rooms for server-level events (feed, pipeline, mass silence). Empty: `matrix.default_rooms`. |

### Rules feed

The signed central rules feed ([rules-feed.md](rules-feed.md)). Layers: built-in < feed < local (DB).

| Key | Type | Default | Environment | Description |
|---|---|---|---|---|
| `rules.feed.enabled` | bool | `false` | `PANOPTES_RULES_FEED_ENABLED` | Poll, verify and install signed rule bundles. Requires `rules.feed.trusted_keys`. |
| `rules.feed.url` | string | empty | `PANOPTES_RULES_FEED_URL` | URL of `latest.json`. `https://` is required; `file://` is accepted for tests, mirrors and air-gapped servers. Empty: no polling, only bundles installed with `panoptes-server rules import` are used. |
| `rules.feed.interval` | duration | `6h` | `PANOPTES_RULES_FEED_INTERVAL` | Poll period, at least `1m`. |
| `rules.feed.trusted_keys` | list of base64 | `[]` | `PANOPTES_RULES_FEED_TRUSTED_KEYS` (comma separated) | ed25519 public keys (`panoptes-server rules keygen` prints one). A bundle must be signed by one of them; list two keys while rotating. Enabled with an empty list is a configuration error. |
| `rules.feed.stale_after` | duration | `7d` | `PANOPTES_RULES_FEED_STALE_AFTER` | `feed_stale` alert ("rules feed ...") when no poll succeeded for this long or the last 3 polls failed. `0` disables; the check is also off when `url` is empty. |

### Triage

| Key | Type | Default | Environment | Description |
|---|---|---|---|---|
| `triage.epss_threshold` | float 0..1 | `0.1` | `PANOPTES_TRIAGE_EPSS_THRESHOLD` | A `conditions_unknown` finding with EPSS at or above this value goes to the web UI's "needs attention" tier (see [Reading the dashboard](rules.md#reading-the-dashboard-attention-vs-background)). Display only: alerts are not affected. |

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
- `rules.feed.enabled` is set without a valid `rules.feed.trusted_keys` entry, `rules.feed.url` is not `https://` or
  `file://`, or `rules.feed.interval` is below `1m`;
- `retention.*` or `limits.*` is negative, or `triage.epss_threshold` is outside 0..1;
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

The `local_agent` section makes the server monitor its own host without a separately installed
`panoptes-agent`. It is off by default. Setup steps and caveats:
[installation.md](installation.md#agentless-mode).

| Key | Type | Default | Environment | Description |
|---|---|---|---|---|
| `local_agent.enabled` | bool | `false` | `PANOPTES_LOCAL_AGENT_ENABLED` | Turn the built-in local agent on. |
| `local_agent.source` | string | `auto` | `PANOPTES_LOCAL_AGENT_SOURCE` | `collector`: read facts and inventory from the root collector's socket. `inprocess`: collect inside the server process with the server's privileges (one WARN when not root; in Docker this scans the container). `auto`: `collector` if a real request to the socket succeeds, otherwise `inprocess`; the choice is logged. Values other than these three fail at startup. |
| `local_agent.collector_socket` | string (absolute path) | `/run/panoptes/collector.sock` | `PANOPTES_LOCAL_AGENT_COLLECTOR_SOCKET` | Socket of the host's root collector. With `source: collector` the collector accepts only root and the uid of `collector_user` (`panoptes`), so the server must run as user `panoptes`; see [installation](installation.md#agentless-mode). |
| `local_agent.labels` | list of strings | `[server]` | `PANOPTES_LOCAL_AGENT_LABELS` (comma-separated) | Labels of the local host. Authoritative and locked, like enrollment-token labels. A change is applied at the next server start and rotates the local agent key. Each label must match `^[a-z0-9][a-z0-9._-]{0,63}$`; at most 32. |
| `local_agent.checkin_interval` | duration | `5m` | `PANOPTES_LOCAL_AGENT_CHECKIN_INTERVAL` | Check-in interval. Minimum `1m`. |
| `local_agent.inventory_interval` | duration | `6h` | `PANOPTES_LOCAL_AGENT_INVENTORY_INTERVAL` | Safety-net full inventory rescan; package changes trigger earlier scans. Minimum `1m`. |
| `local_agent.scan_language_packages` | bool | `true` | `PANOPTES_LOCAL_AGENT_SCAN_LANGUAGE_PACKAGES` | Also inventory language packages (as the agent key of the same name). |
| `local_agent.exclude_paths` | list of globs | empty (= agent defaults) | `PANOPTES_LOCAL_AGENT_EXCLUDE_PATHS` (comma-separated) | Paths excluded from the host scan. Empty uses the agent defaults (see [agent configuration](#agent-configuration)). `data_dir` is always excluded in addition, whatever this list says. |
| `local_agent.docker_socket` | string (absolute path, or empty) | `/var/run/docker.sock` | `PANOPTES_LOCAL_AGENT_DOCKER_SOCKET` | Docker socket; images are scanned when it exists and is readable. |

Notes:

- The `local_agent` values are validated at startup even when `enabled` is `false`.
- No enrollment token is used. The server creates the host record itself and stores the agent key in
  `<data_dir>/local-agent/credentials.json` (0600). The host shows a "local (built-in)" badge in the web UI.
- If a host with the same machine ID is already enrolled by a standalone agent, the local agent does not
  take it over. It logs an ERROR and does not start; see [operations](operations.md#troubleshooting).

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
