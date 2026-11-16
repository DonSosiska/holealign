# Panoptes contracts

Single source of truth for interfaces between components. Go types live in
`internal/model` and `internal/server/core`; this document explains their semantics.
If you change a contract, change both.

## 1. Agent ↔ server HTTP API (`/api/v1`)

All bodies are JSON. Agent requests after enrollment carry `Authorization: Bearer <agent_key>`.
Server stores only a SHA-256 hash of agent keys and enrollment tokens.

| Method & path | Body → Response | Notes |
|---|---|---|
| `POST /api/v1/enroll` | `EnrollRequest` → `EnrollResponse` | `machine_id` must match `^[0-9a-f]{32,64}$` (agents send a sha256 hex) else 400; labels ≤ 32 entries matching `^[a-z0-9][a-z0-9._-]{0,63}$` else 400; hostname truncated to 253 chars, control chars stripped. 401 on unknown/revoked/expired token; 403 when the token's `max_hosts` is reached. **409** `{"error":"host exists; previous key required (admin: panoptes-server host allow-reenroll <host>)"}` when the `machine_id` is already enrolled and the request carries neither `Authorization: Bearer <current agent key of that host>` nor an admin `allow-reenroll` flag (cleared on use). A permitted re-enroll reuses the host record and rotates the key. 429 beyond 10 requests/min per client IP. |
| `POST /api/v1/checkin` | `CheckinRequest` → `CheckinResponse` | Every 5 min (default); at most 1 per 20 s per host (else 429 + `Retry-After`). Updates labels, OS, facts, `last_checkin`. Labels sent here are ignored for hosts enrolled with a token that has labels. Facts after merge: ≤ 1000 keys, ≤ 1 MiB JSON, each value ≤ 64 KiB, else 413. |
| `POST /api/v1/inventory` | `InventoryPayload` (gzip, `Content-Encoding: gzip`) → `202` | Max body 64 MiB decompressed (413); ≤ 50 000 CycloneDX components per target SBOM (413). At most 1 per 5 min per host (429 + `Retry-After`; the agent retries later). An inventory whose `hash` equals the stored one is answered `202` without re-matching. Otherwise the server replaces all targets of the host and re-runs matching asynchronously. |
| `GET /healthz` | → `200 ok` | No auth. |

Any request failing Bearer authentication counts against a per-client-IP limit (30/min, then 429); valid agents are never throttled by it.

Enrollment tokens (`panoptes-server token create <name> [-max-hosts N] [-expires 72h] [-labels prod,web]`):
optional `max_hosts` (hosts that may enroll), `expires_at`, and `labels`. Token labels are **authoritative**:
hosts enrolled with such a token get exactly these labels (the token name is stored on the host) and
check-in labels are ignored, so alert routing cannot be steered by self-asserted labels.
Admin CLI: `host list`, `host allow-reenroll <id|hostname>` (one re-enroll without the old key), `host delete <id|hostname>`.

Error responses: `{"error": "<message>"}` with a 4xx/5xx status.
Agents retry 5xx, 429 (honouring `Retry-After`) and network errors with exponential backoff (max 5 min); 401 → re-enroll (sending the old key as Bearer) if an enroll token is still configured, else log and keep retrying hourly; 409 → log and wait for an admin `host allow-reenroll`.

`CheckinResponse.WantInventory` is true when the server has no inventory whose hash equals `CheckinRequest.InventoryHash`.

## 2. Agent configuration (`/etc/panoptes/agent.yaml`)

```yaml
server_url: https://panoptes.example.com
enroll_token: "pt_..."          # used only until enrolled
labels: [prod, web, team-a]
state_dir: /var/lib/panoptes-agent  # agent_id + agent_key stored here (0600)
checkin_interval: 5m
inventory_interval: 6h          # safety-net full rescan; changes trigger earlier
docker_socket: /var/run/docker.sock  # images are scanned if the socket exists
scan_language_packages: true
exclude_paths: [/proc, /sys, /dev, /run, /var/lib/docker, /var/lib/containerd, /snap]
```

Inventory is rescanned when any of these change (mtime): `/var/lib/dpkg/status`,
`/var/lib/rpm/` (or `/usr/lib/sysimage/rpm/`), `/lib/apk/db/installed`, or the set of Docker image IDs.

## 3. Fact catalog

Facts are a flat map `name → value`. Built-in facts are collected on every check-in;
parametrised facts only when requested. **Absent = unknown** (collector not applicable,
binary missing, command failed). A collector that determines software is not installed
sets `<x>.installed = false` and omits the other `<x>.*` facts.

| Fact | Type | Source |
|---|---|---|
| `os.id`, `os.version_id` | string | /etc/os-release |
| `os.libc` | string `glibc`\|`musl` | ldd --version / /lib/ld-musl-* |
| `os.libc_version` | string | ldd --version |
| `kernel.release` | string | uname -r |
| `kernel.modules` | list<string> | /proc/modules (names) |
| `kernel.sysctl` | map<string,string> | /proc/sys for an allowlist: `kernel.unprivileged_userns_clone`, `user.max_user_namespaces`, `kernel.unprivileged_bpf_disabled`, `kernel.kptr_restrict`, `kernel.yama.ptrace_scope`, `kernel.dmesg_restrict`, `net.ipv4.ip_forward`, `net.ipv6.conf.all.disable_ipv6`, `fs.protected_symlinks`, `fs.protected_hardlinks`, `vm.unprivileged_userfaultfd`, `kernel.io_uring_disabled`, `kernel.apparmor_restrict_unprivileged_userns` |
| `services.active` | list<string> | `systemctl list-units --type=service --state=running --no-legend` (unit names without `.service`). If systemctl is missing or fails: fallback to `/proc/<pid>/comm`, mapped through a table of well-known daemons (e.g. `sshd`→`ssh`,`sshd`; `apache2`/`httpd`→both), other names as-is (lowercase); kernel threads and shells/tools excluded; sorted, deduplicated |
| `services.source` | string `systemd`\|`proc` | origin of `services.active` (absent together with it) |
| `sockets.listening` | list<map{proto,addr,port(int),process}> | /proc/net/{tcp,tcp6,udp,udp6} + /proc/*/fd inode mapping |
| `sockets.ports` | list<int> | distinct listening ports |
| `sshd.installed` | bool | `sshd` binary exists |
| `sshd.version` | string | `sshd -V` / `ssh -V` |
| `sshd.config` | map<string,string> | `sshd -T` (keys lowercased, first value) |
| `nginx.installed`, `nginx.version` | bool, string | `nginx -v` |
| `nginx.modules` | list<string> | `nginx -V` configure args (`--with-*` names, e.g. `http_v2_module`) |
| `nginx.directives` | map<string,list<string>> | `nginx -T`, directive name → all values seen (comments stripped) |
| `nginx.http2` | bool | `http2 on` directive or `listen ... http2` |
| `apache.installed`, `apache.version` | bool, string | `apachectl -v` / `httpd -v` |
| `apache.modules` | list<string> | `apachectl -M` (e.g. `proxy_module`) |
| `apache.http2` | bool | `http2_module` loaded and `Protocols` contains `h2` or `h2c` |
| `php.installed`, `php.version` | bool, string | `php -v` |
| `php.sapi` | list<string> | php-fpm / apache2handler / cli present |
| `php.ini` | map<string,string> | `php -i` for: `allow_url_include`, `allow_url_fopen`, `disable_functions`, `expose_php`, `open_basedir`, `cgi.fix_pathinfo` |
| `openssl.version` | string | `openssl version` |
| `docker.installed`, `docker.version` | bool, string | Docker API `/version` |
| `docker.containers` | list<map{name,image,image_id,ports(list<string>),privileged(bool)}> | Docker API `/containers/json` + inspect |
| `runc.version` | string | `runc --version` |
| `sudo.version` | string | `sudo -V` |
| `file.match:<id>` | list<string> | **parametrised**, see below |

Command execution rules for collectors: fixed argv (no shell), 10 s timeout, stdout capped at 4 MiB,
`LC_ALL=C`. All commands are hard-coded in the agent.

### `file.match` collector

`FactRequest{Name:"file.match:<id>", Collector:"file.match", Params:{path, pattern}}`

- `path` is a glob; after `filepath.Clean` and symlink resolution it must be under an allowed
  root: `/etc/`, `/opt/*/conf/`, `/opt/*/etc/`, `/usr/local/etc/`. Otherwise the request is ignored (logged).
- `pattern` is RE2 (Go `regexp`), max 512 chars. Max 50 files, 1 MiB per file, 200 matched lines total.
- Value: matched lines, trimmed, prefixed with `<file>:`.
- Secret masking: in returned lines, values after keys matching
  `(?i)(pass(word)?|secret|token|key|credential|auth)\s*[:=]` are replaced with `***`.
- Max 100 active parametrised requests; extra ones are ignored.

## 4. Rules

YAML files in `rules/` (shipped, `status: reviewed`) plus rules in the DB (LLM drafts, user edits).
DB rules with the same `id` override files.

```yaml
id: CVE-2024-6387
vulns: [CVE-2024-6387]
title: "OpenSSH regreSSHion: unauthenticated RCE via SIGALRM race"
packages:
  - {name: openssh-server, type: deb}
  - {name: openssh-server, type: rpm}
  - {name: openssh, type: apk}
facts: [os.libc, sshd.config]
exploitable_if: >
  facts["os.libc"] == "glibc" &&
  facts["sshd.config"]["logingracetime"] != "0"
explanation: "Exploitable only on glibc systems while LoginGraceTime is non-zero."
fix:
  upgrade: "Upgrade OpenSSH to a patched package."
  mitigation: "Set 'LoginGraceTime 0' in /etc/ssh/sshd_config and reload sshd (risk: connection-slot DoS)."
status: reviewed
source: builtin
references: [https://www.qualys.com/2024/07/01/cve-2024-6387/regresshion.txt]
```

### Matching a rule to a finding
A rule applies when `finding.vuln_id` or any of `finding.aliases` is in `rule.vulns`, AND a
`packages` selector matches (`name` matches as a `path.Match` glob, e.g. `nginx*`, `linux-image-*`;
`type` equal or empty). `status: rejected` rules are ignored. Several rules may cover the same CVE for
different packages (e.g. `CVE-2023-44487-nginx` and `CVE-2023-44487-apache`); if more than one applies,
the DB one wins over the file one, then the first by ID.

### CEL environment
Variables:
- `facts` — `map(string, dyn)` (host facts)
- `pkg` — `map(string, dyn)`: `name`, `version`, `type`, `purl`, `fixed_versions` (list), `target`, `target_kind`
- `host` — `map(string, dyn)`: `hostname`, `labels` (list), `os_id`, `os_version_id`, `kernel`, `arch`

Custom functions:
- `version_lt(a string, b string) bool`, `version_ge(a, b)` — loose version comparison
  (numeric segments compared numerically, e.g. `"6.1.10" < "6.10.0"`).
- `has_module(list, name)` — sugar for `name in list`.

CEL optional types are enabled (`cel.OptionalTypes()`), so rules can write
`facts["kernel.sysctl"][?"user.max_user_namespaces"].orValue("1")` for map keys that may be missing.
Expressions must return bool. Evaluation cost limit 10 000; timeout 50 ms.

### Verdict algorithm (per finding)
1. Find the applicable rule (DB overrides file). None → `conditions_unknown`, reason "no rule".
2. Any fact in `rule.facts` (or requested `file.match:*` name) absent → `conditions_unknown`, reason lists missing facts.
3. `not_affected_if` set and true → `affected_not_exploitable`.
4. `exploitable_if` true → `exploitable`, else `affected_not_exploitable`.
5. Expression error → `conditions_unknown`, reason contains the error.
6. Ungrounded-draft guard (applied to the result of steps 3–4). A rule is *ungrounded* when
   `status` is `draft` and its `facts` + `fact_requests` are empty or all of the form `<x>.installed`
   (no host evidence). For an ungrounded draft: `exploitable` → `conditions_unknown`, reason
   `LLM draft (unreviewed, no host evidence): likely exploitable — <explanation[:200]>`;
   `affected_not_exploitable` stays, reason prefixed `LLM draft (unreviewed): `, except for KEV
   findings, which become `conditions_unknown`. `reviewed` rules are never affected.
   `Evaluation.Rule`/`RuleStatus` remain set.

`Evaluation.Reason` is short, human readable, mentions the deciding facts and their values
(e.g. `os.libc=glibc, sshd.config.logingracetime=120`).

## 5. Pipeline and events

After inventory upload, after a fact change on check-in, after a vuln-DB update, and after a
rule changes, the server (re)computes findings for affected hosts:

1. Grype matches every target SBOM → candidate findings.
2. Each finding gets `Evaluation` from `core.RuleEvaluator`.
3. Upsert into the DB keyed by `(host_id, target, package_name, package_version, vuln_id)`;
   findings no longer present become `resolved`.
4. Findings with no rule and (`severity` ∈ {High, Critical} or `kev`) → `core.RuleDrafter.Enqueue`.
5. Events (`core.Notifier.Notify`), comparing with the previously stored verdict:
   - `EventExploitable` — finding is new or verdict changed *to* `exploitable`.
   - `EventUnknownCritical` — new finding with `conditions_unknown` and (`kev` or severity Critical).
     Not re-sent when only the reason changes.
   - `EventResolved` — previously notified finding became `resolved`, `affected_not_exploitable` or `not_affected`.
   Dedup key `(host_id, target, package_name, vuln_id, kind)`; never send the same key twice in a row.
   Delivery is per event: `Notifier.Notify` may return a `*notify.DeliveryError{Failed []int}` (indexes into the
   events passed in); the pipeline records every other event as delivered and retries only the failed ones.
   A permanent 4xx from Matrix (other than 429) is logged at ERROR and recorded as delivered (not retried forever).
   Message text: every untrusted field is cut to 300 characters with control characters removed, the body is
   capped at 8 KiB; for draft (unreviewed LLM) rules only a warning and the server-generated fix command are shown.
   Each pipeline run has a 10 min timeout; a panic in any background goroutine is logged and recovered, and a
   target whose matching panicked is flagged (`kv poison.<host>.<target-hash>`) and skipped until a new inventory arrives.

## 6. Server configuration (`/etc/panoptes/server.yaml`, all keys optional)

```yaml
listen: ":8080"
public_url: "http://localhost:8080"   # used for links in notifications
data_dir: /var/lib/panoptes           # SQLite DB + Grype DB cache
feeds:
  interval: 6h                        # vuln DB / KEV / EPSS refresh
rules_dir: /usr/share/panoptes/rules  # shipped YAML rules
matrix:
  homeserver: https://matrix.example.com
  access_token_env: PANOPTES_MATRIX_TOKEN
  default_rooms: ["!abc:example.com"]   # used when no label route matches
  routes:                               # label -> rooms; web UI edits are stored in DB and merged
    - {label: prod, rooms: ["!prod:example.com"]}
llm:
  provider: none                      # none | anthropic | openai-compatible
  model: claude-sonnet-5-5
  base_url: ""                        # openai-compatible only, e.g. http://ollama:11434/v1
  api_key_env: PANOPTES_LLM_API_KEY
  daily_limit: 50                     # max drafting calls per day
admin:
  initial_password_env: PANOPTES_ADMIN_PASSWORD  # creates user "admin" on first start
```

Validation: `*_env` names must match `^PANOPTES_[A-Z0-9_]+$` and must not equal the admin password variable.
The initial admin password needs ≥ 12 characters and may come from the file named by
`PANOPTES_ADMIN_PASSWORD_FILE`. Startup logs a WARN when `public_url`, `matrix.homeserver` or `llm.base_url`
use `http://` for a non-loopback host, and when the Grype DB is older than 5 days. The server runs with
`umask 077` and a 0600 database file; HTTP limits: header ≤ 64 KiB, read timeout 5 min, write timeout 2 min.

Environment variable `PANOPTES_CONFIG` points to the file; every scalar can be overridden by
`PANOPTES_<SECTION>_<KEY>` (e.g. `PANOPTES_MATRIX_HOMESERVER`).

## 7. Build constraints

- SQLite drivers: the **server** uses `github.com/glebarez/go-sqlite` (Grype already links it and it registers
  the driver name `sqlite`); importing `modernc.org/sqlite` directly in any server package panics at start-up
  ("Register called twice"). The **agent** does not link Grype and imports `modernc.org/sqlite` for Syft's RPM
  cataloger. Never import agent packages from the server or vice versa (except `internal/model`).
- Grype DB v6 provides KEV and EPSS; there are no separate CISA/FIRST fetchers.
