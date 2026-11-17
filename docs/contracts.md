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
server_url: https://panoptes.example.com   # https required; no userinfo; redirects are never followed
allow_insecure_http: false      # true permits an http:// server_url (WARN logged; testing only)
enroll_token: "pt_..."          # used only until enrolled
labels: [prod, web, team-a]
state_dir: /var/lib/panoptes-agent  # agent_id + agent_key stored here (0600)
checkin_interval: 5m
inventory_interval: 6h          # safety-net full rescan; changes trigger earlier
docker_socket: /var/run/docker.sock  # images are scanned if the socket exists
scan_language_packages: true
exclude_paths: [/proc, /sys, /dev, /run, /var/lib/docker, /var/lib/containerd, /snap,
                /mnt, /media, /var/lib/containers, /var/lib/kubelet, /var/lib/lxc, /var/lib/lxd, /home/*/.cache]
host_scan_timeout: 10m          # per scan; a panic or timeout is an error, not a crash
image_scan_timeout: 5m
ca_file: /etc/panoptes/ca.pem   # optional PEM bundle; when set ONLY these roots are trusted (no system roots)
server_cert_sha256: ["<64 hex>"] # optional; leaf SubjectPublicKeyInfo SHA-256 pins, checked in addition to chain validation
client_cert: /etc/panoptes/client.pem  # optional mTLS client certificate; client_key must be set with it
client_key: /etc/panoptes/client.key
collector_socket: /run/panoptes/collector.sock  # privilege separation (below); unused in -mode all
collector_user: panoptes        # uid allowed on the socket besides root; its group owns the socket
```

### Process modes and the collector socket

One binary, `-mode` flag: `all` (default; one process doing everything, used by `-once`, containers and e2e),
`collector` and `sender`. The process that parses untrusted local files as root has no network, and the process
that talks to the network is not root.

- **collector** (root, `panoptes-collector.service`, `PrivateNetwork=yes`, `IPAddressDeny=any`,
  `RestrictAddressFamilies=AF_UNIX`): listens on `collector_socket` (`/run/panoptes/collector.sock`; directory
  `0750 root:panoptes`, socket `0660 root:panoptes`). It applies every collection policy itself (file.match allow/deny
  lists and budgets, binary trust checks, scan timeouts) and runs at most one inventory scan per 10 minutes whoever
  asks (later requests get the previous result). Its code lives in packages that do not import the HTTP transport
  (`go list -deps` test). In a private network namespace `/proc/net` is empty, so `-mode collector` reads
  `sockets.listening` from `/proc/1/net/*` (the host namespace of PID 1); if that is unreadable the sockets facts are
  omitted (unknown), never reported empty.
- **sender** (user `panoptes`, `panoptes-agent.service`, empty capability set, `NoNewPrivileges`): the whole runner
  (enroll, check-in loop, clamping, backoff, credentials in `state_dir` owned by `panoptes`), but facts, inventory,
  OS info and change detection come from the collector. `/etc/panoptes/agent.yaml` is `root:panoptes 0640`.
- Socket protocol: one request per connection, one JSON line of at most 64 KiB, answered by one JSON document
  (gzip-compressed for `inventory`; errors are plain JSON). `SO_PEERCRED` uid must be 0 or the `collector_user`'s uid.

| Request | Response |
|---|---|
| `{"op":"facts","fact_requests":[...]}` | `{"ok":true,"facts":{...}}` |
| `{"op":"inventory","gzip":true}` | `{"ok":true,"inventory":<InventoryPayload>}` |
| `{"op":"osinfo"}` | `{"ok":true,"os":<OSInfo>,"machine_id":"<sha256 hex>"}` |
| `{"op":"changed"}` | `{"ok":true,"changed":<bool>}` |
| anything else / too large / bad JSON | `{"ok":false,"error":"..."}` |

`panoptes-agent -print-facts` / `-print-inventory` / `-once` always run in-process.

Server identity: TLS 1.2+, chain and host name are always verified (`InsecureSkipVerify` is never set). With `ca_file`
only that bundle is trusted. With `server_cert_sha256` the presented leaf's SPKI SHA-256 must be in the list (colons
and upper case are accepted); if `ca_file` is absent the chain is still validated against the system roots. A mismatch
fails the handshake and logs the presented hash so an operator can pin it. Config validation rejects non-hex or
wrong-length pins, an unreadable or certificate-less `ca_file`, and `client_cert` without `client_key`.
`panoptes-agent -print-server-pin` connects to `server_url`, validates the chain normally and prints the leaf SPKI
hash; it is a convenience, not trust-on-first-use. `deploy/install.sh` takes `--ca-file PATH` and `--server-pin HEX`
(repeatable) and verifies the release with cosign (`checksums.txt.sig`/`.pem`) before trusting any checksum.

Agent hardening rules (not trusting the server): `next_checkin_seconds` is clamped to 60 s – 1 h;
`want_inventory` is honoured at most once per 10 min; after a failed scan the next attempt is delayed
(check-in interval doubled per consecutive failure, max 6 h) and the error is reported as
`agent.inventory_error`. On enrollment the agent sends a stored previous `agent_key` as
`Authorization: Bearer`; on `409 Conflict` it logs an ERROR (operator: `panoptes-server host allow-reenroll
<hostname>`) and retries hourly. `machine_id` is `hex(sha256("panoptes-machine-id:" + /etc/machine-id))`.
A `429` is not retried inside the transport backoff loop: it surfaces as `*transport.RateLimitedError`
(`Retry-After` seconds or HTTP date, default 30 s, clamped to 5 s - 15 min). The run loop logs it at INFO, does not treat
it as a check-in or scan failure, keeps a scanned-but-rejected inventory pending (the same payload/hash is re-sent next
cycle, no rescan) and schedules the next cycle at `max(normal next, Retry-After)`. With `-once`, a `Retry-After` of at
most 60 s is waited out once; a longer one exits non-zero with a clear message.
Helper binaries are looked up in `/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin` and only run
when file and directory are root-owned and not group/world-writable.

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
| `nginx.directives` | map<string,list<string>> | `nginx -T`, directive name → all values seen (comments stripped; secret-looking values masked as `***`, values capped at 256 bytes) |
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
| `agent.inventory_error` | string | last inventory scan error (truncated to 200 chars); absent when the last scan succeeded |
| `agent.skipped` | list<string> | tools not run because their config tree is not trustworthy, e.g. `nginx: /etc/nginx/conf.d writable by gid 33`. Before `nginx -V/-T`, `php -i` and `sshd -T` the agent verifies that `/etc/nginx` (+ `/usr/local/etc/nginx`, `/usr/local/nginx/conf`), `/etc/php/*/cli` (+ `/etc/php.ini`, `/etc/php.d`, `/usr/local/etc/php`) and `/etc/ssh/sshd_config{,.d}` and their parents are root-owned and not group/world-writable (≤ 2000 entries walked); otherwise the command is skipped and its facts omitted |
| `file.match:<id>` | list<string> | **parametrised**, see below |

Command execution rules for collectors: fixed argv (no shell), 10 s timeout, stdout capped at 4 MiB,
`LC_ALL=C`. All commands are hard-coded in the agent.

### `file.match` collector

`FactRequest{Name:"file.match:<id>", Collector:"file.match", Params:{path, pattern}}`

- `path` is a glob (bounded walk, at most 50 matches); after `filepath.Clean` and symlink resolution it must be
  under an allowed root: `/etc/`, `/opt/*/conf/`, `/opt/*/etc/`, `/usr/local/etc/`. Otherwise the request is
  ignored (logged).
- Hard denylist on the resolved physical (and logical) path, any component, case-insensitive: `shadow*`,
  `gshadow*`, `passwd-`, `sudoers*`, `ssh/ssh_host_*`, `ssl/private`, `letsencrypt`, `pki`, `panoptes`,
  `krb5.keytab`, `*.key`, `*.pem`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore`, `.htpasswd`, `*secret*`,
  `*credential*`, `*token*`, `NetworkManager`, `wireguard`, `openvpn`, `ppp`, `security`, `polkit-1`,
  `ipsec*`, `strongswan*`, `cloud`, `mysql/debian.cnf`, `*.env`. The server enforces the same list.
- Only regular, world-readable (`mode & 0o004`) files are read; files are opened with
  `O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC` (Linux: `openat2` `RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH`, fallback to an
  `openat` component walk), the mode is checked on the open fd. Files with a NUL byte or `-----BEGIN ` in the
  first 64 KiB are skipped; crypt-hash lines (`^[^:]+:\$id\$`) are dropped.
- `pattern` is RE2 (Go `regexp`), max 512 chars. Per file max 1 MiB.
- Value: matched lines, trimmed, prefixed with `<file>:`; each line truncated to 512 bytes.
- Secret masking: values after keys matching
  `(?i)(["']?)(pass(wd|word|phrase)?|pwd|psk|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth(orization)?|requirepass|masterauth)\1\s*[:=\s]\s*\S.*`
  are replaced with `***` (the key is kept; a bare `pass` needs `:`/`=`); URL userinfo becomes `://***@`;
  tokens of 32+ chars from `[A-Za-z0-9+/=_-]` mixing letters and digits/cases become `***`.
- Budgets: per check-in at most 20 requests (deduplicated by name and by (path, pattern)), 2 MiB read in total,
  500 lines in total (200 per request), 5 s wall time. Requests beyond a budget yield no fact.

## 4. Rules

YAML files in `rules/` (shipped, `status: reviewed`) plus rules in the DB (LLM drafts, user edits).
A DB rule with the same `id` as a file rule overrides it, except a DB `draft`, which never replaces a
file rule (the file rule is kept and a problem is reported). Rule ids match `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`.

`fact_requests` policy (enforced by `Validate`): at most 5 per rule; name `file.match:<ruleID-sanitized>.<id>`
(`[a-z0-9._-]`, at most 64 chars after the prefix; ruleID lowercased, other characters become `-`); `path` absolute,
clean, under `/etc/`, `/opt/*/conf/`, `/opt/*/etc/` or `/usr/local/etc/`, without `[`, `]`, `\`, and unable to match
a denylist of secret locations (`shadow*`, `sudoers*`, `ssh/ssh_host_*`, `ssl/private`, `*.key`, `*.pem`, `*secret*`,
`*credential*`, `*token*`, `panoptes`, ...; see `rules.FileMatchPathAllowed`); `pattern` at most 256 chars, valid RE2,
not match-all (must not match the empty string nor almost any single character). Only `reviewed` rules'
fact requests are sent to agents; drafts are inert. Evaluation reasons never contain `file.match` values, only
`file.match:<id>=<N> matching lines`.

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
the winner is chosen by status (`reviewed` over `draft`), then DB over file, then the first by ID.

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
The legacy spelling `m.?["k"]` is rejected by `Validate` (use `m[?"key"]`). Facts must be read as `facts["literal"]`. Expressions must return bool. Evaluation cost limit 10 000; timeout 50 ms.

### Verdict algorithm (per finding)
1. Find the applicable rule (DB overrides file). None → `conditions_unknown`, reason "no rule".
2. Any fact in `rule.facts` (or requested `file.match:*` name) absent → `conditions_unknown`, reason lists missing facts.
3. `not_affected_if` set and true → `affected_not_exploitable`.
4. `exploitable_if` true → `exploitable`, else `affected_not_exploitable`.
5. Expression error → `conditions_unknown`, reason contains the error.
6. Draft guard (applied to the result of steps 3–4; only when `status` is `draft` and the verdict is
   `exploitable` or `affected_not_exploitable`). Referenced facts are determined from the checked CEL AST
   (`facts["literal"]` index/select); names in string literals or only listed in `facts` do not count. A draft is
   *grounded* only if its expressions reference at least one fact that is not `<x>.installed`.
   - Ungrounded draft: always `conditions_unknown`, reason `LLM draft suggests <verdict>: <explanation[:200]>`.
   - Grounded draft: `exploitable` is allowed (reason prefixed `LLM draft (unreviewed): `);
     `affected_not_exploitable` is allowed only if the finding is not KEV and its severity is not Critical;
     otherwise `conditions_unknown`, reason `LLM draft suggests not exploitable (unreviewed; KEV/Critical need review): <explanation[:200]>`.
   `reviewed` rules are never affected. `Evaluation.Rule`/`RuleStatus` remain set.

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
