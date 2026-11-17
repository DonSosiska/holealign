# Panoptes contracts

Single source of truth for interfaces between components. Go types live in
`internal/model` and `internal/server/core`; this document explains their semantics.
If you change a contract, change both.

## 1. Agent ↔ server HTTP API (`/api/v1`)

All bodies are JSON. Agent requests after enrollment carry `Authorization: Bearer <agent_key>`.
Server stores only a SHA-256 hash of agent keys and enrollment tokens.

| Method & path | Body → Response | Notes |
|---|---|---|
| `POST /api/v1/enroll` | `EnrollRequest` → `EnrollResponse` | `machine_id` must match `^[0-9a-f]{32,64}$` (agents send a sha256 hex) else 400; labels ≤ 32 entries matching `^[a-z0-9][a-z0-9._-]{0,63}$` else 400; hostname truncated to 253 chars, control chars stripped. 401 on unknown/revoked/expired token; 403 when the token's `max_hosts` is reached. **409** `{"error":"host exists; previous key required (admin: panoptes-server host allow-reenroll <host>)"}` when the `machine_id` is already enrolled and the request carries neither `Authorization: Bearer <current agent key of that host>` nor an admin `allow-reenroll` flag (cleared on use). A permitted re-enroll reuses the host record and rotates the key; it keeps the host's `token_name`, labels and `labels_locked` unless the new token itself carries labels (then the token's labels apply, its `max_hosts` is checked and the host moves to it). The admin permission (`reenroll_allowed_until`) expires (default 1 h). 429 only for **invalid** requests (unknown token, bad body/machine_id/labels): 10/min per client, where a client is an IPv4 address or an IPv6 /64; requests with a valid token are never counted against it (separate cap of 600/min per client). Bodies declaring `Content-Length` > 1 MiB get 413 before reading. |
| `POST /api/v1/checkin` | `CheckinRequest` → `CheckinResponse` | Every 5 min (default); per host a token bucket: burst 3, one token refilled per 20 s (else 429 + `Retry-After`). Updates labels, OS, facts, `last_checkin`. Labels sent here are ignored for hosts enrolled with a token that has labels. Facts after merge: ≤ 1000 keys, ≤ 1 MiB JSON, each value ≤ 64 KiB, else 413. |
| `POST /api/v1/inventory` | `InventoryPayload` (gzip, `Content-Encoding: gzip`) → `202` | Max body 64 MiB decompressed (413; a `Content-Length` above it is refused before reading). Every target SBOM must be a CycloneDX JSON document: top-level `"bomFormat":"CycloneDX"` (exact, case-sensitive); keys that equal `components`/`bomFormat` only case-insensitively anywhere in the document are rejected; ≤ 50 000 components (nested ones counted); the matcher enforces the same package cap after decoding. Targets are validated **one by one**: a target that is invalid (unknown kind, empty name, `name` > 512 bytes, `image_id` > 128, > 200 containers or a container name > 256, not CycloneDX, duplicate) or oversized is **skipped**, the valid targets are stored and the response is `202 {"status":"accepted","skipped":[{"kind","name","reason"}]}` (`skipped` omitted when empty; repeated for an identical re-upload). Only payload-level errors (no/oversized `hash`, > 1000 targets, bad JSON/gzip) are 400/413, and `415` (with the `skipped` list) when no target is a CycloneDX document. The previous findings of a skipped target are kept (not resolved) and the skip is reported to the health loop (`pipeline_error`). A host whose uploads keep failing validation gets 429 (6 invalid uploads/min, checked before the body is read). Per host a token bucket: burst 3, one token refilled per 5 min (429 + `Retry-After` = seconds until the next token; the agent retries later). An inventory whose `hash` equals the stored one is answered `202` before the limiter, spends no token and does not re-match. Otherwise the server replaces all targets of the host and re-runs matching asynchronously. |
| `GET /healthz` | → `200 ok` | No auth. |

Any request failing Bearer authentication counts against a per-client limit (30/min, then 429); valid agents are never throttled by it. The per-client limiter maps (IPv4 address / IPv6 /64) are bounded LRUs: under key pressure the oldest idle entry is evicted, a new client is never denied for lack of space.

Enrollment tokens (`panoptes-server token create <name> [-max-hosts N] [-expires 72h] [-labels prod,web]`):
optional `max_hosts` (hosts that may enroll), `expires_at`, and `labels`. Token labels are **authoritative**:
hosts enrolled with such a token get exactly these labels (the token name is stored on the host) and
check-in labels are ignored, so alert routing cannot be steered by self-asserted labels.
Token names match `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`.
Admin CLI: `host list`, `host allow-reenroll <id|hostname> [-ttl 1h]` (one re-enroll without the old key, valid for the TTL, max 168 h), `host delete <id|hostname>` (also removes the host's findings, notification dedup rows and kv state such as `poison.*`). `token`/`host`/`user` run as root drop to the uid/gid owning the data directory (or DB) before touching it, so no root-owned files appear; if that is impossible they refuse and suggest `sudo -u <service-user>`.

Error responses: `{"error": "<message>"}` with a 4xx/5xx status.
Agents retry 5xx, 429 (honouring `Retry-After`) and network errors with exponential backoff (max 5 min); 401 → re-enroll (sending the old key as Bearer) if an enroll token is still configured, else log and keep retrying hourly; 409 → log and wait for an admin `host allow-reenroll`.

`CheckinResponse.WantInventory` is true when the server has no inventory whose hash equals `CheckinRequest.InventoryHash`.

## 2. Agent configuration (`/etc/panoptes/agent.yaml`)

```yaml
server_url: https://panoptes.example.com   # https required; no userinfo; redirects are never followed
allow_insecure_http: false      # true permits an http:// server_url (WARN logged; testing only)
enroll_token: "pt_..."          # used only until enrolled; blanked in this file after the first successful check-in (below)
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
  asks (later requests get the previous result). A package change reported by `changed` stays pending (and keeps
  being reported) until a real scan has run: while it is pending the cached inventory is bypassed, but never more
  than one real scan per 2 minutes. `facts` results are cached for 30 s per identical request set; at most 2 facts
  collections and 1 inventory scan run concurrently, further requests fail immediately with `busy` instead of queueing. Its code lives in packages that do not import the HTTP transport
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
| `{"op":"forget_enroll_token"}` | `{"ok":true}`; the root collector atomically rewrites the config file with `enroll_token: ""` |
| anything else / too large / bad JSON | `{"ok":false,"error":"..."}` |

`forget_enroll_token`: the enrollment token would otherwise stay readable by group `panoptes` in `agent.yaml` forever.
After a successful enrollment and the first successful check-in the sender asks the collector once; the collector
rewrites the file (temp file in `/etc/panoptes/`, `fsync`, `rename`; other content, mode and owner/group are kept)
replacing only the top-level `enroll_token` value with `""`. It refuses any path that is not a regular file (not a
symlink) directly in `/etc/panoptes/`, and the unit grants it `ReadWritePaths=-/etc/panoptes`. In `-mode all` the
process does the same itself when it runs as root (otherwise it logs a WARN and leaves the file; remove the token by
hand). Consequence: after the token is gone the agent cannot re-enroll by itself (a 401 is retried hourly); a host
that lost its credentials needs a fresh token in `agent.yaml`. At start the agent logs a WARN when `agent.yaml` or
`client_key` is readable beyond mode 0640, or the credentials file beyond 0600.

Sender hardening against a malicious server: `fact_requests` from a check-in response are filtered before they are
stored (only `file.match` with name `file.match:<id>` of at most 128 bytes, absolute `path` of at most 512,
`pattern` of at most 512, at most 20, unique names; the rest is dropped with one WARN). If the collector rejects the
request (`request too large` / `bad request`) the stored requests are cleared and the call is retried once without
them. A collector that answers with an error does not stop the check-in: it is sent with the facts still known
plus `agent.collector_error`; only an unreachable socket skips the cycle.

`panoptes-agent -print-facts` / `-print-inventory` / `-once` always run in-process.

Agentless mode: the server can run this same runner in-process for its own host (`local_agent`, §6); there the
"sender" is the server process, the transport is an in-memory `RoundTripper` to the agent API, and the data source
is either the collector socket above or `hostdata.Local`. `panoptes-agent -mode collector` on such a host still reads
`/etc/panoptes/agent.yaml` (which requires a `server_url`; `deploy/install.sh --collector-only` writes a placeholder).

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
| `agent.collector_error` | string | last error the root collector answered with (truncated to 200 chars); the check-in carried the previously known facts; absent when the collector answered normally |
| `agent.skipped` | list<string> | tools not run because their config tree is not trustworthy, e.g. `nginx: /etc/nginx/conf.d writable by gid 33`. Before `nginx -V/-T`, `php -i`, `sshd -T`, `apachectl/httpd -v/-M` and `sudo -V` the agent verifies that `/etc/nginx` (+ `/usr/local/etc/nginx`, `/usr/local/nginx/conf`), `/etc/php/*/cli` (+ `/etc/php.ini`, `/etc/php.d`, `/usr/local/etc/php`), `/etc/ssh/sshd_config{,.d}`, `/etc/apache2` (+ `/etc/httpd`, `/usr/local/apache2/conf`, `/usr/local/etc/apache24`; includes `envvars`) and `/etc/sudo.conf` and their parents are root-owned and not group/world-writable (≤ 2000 entries walked); otherwise the command is skipped and its facts omitted. Before `nginx -T` the `include`/`load_module` directives of the verified tree are scanned (≤ 200 files of ≤ 1 MiB); every location outside the verified roots is verified the same way, else `nginx -T` is skipped. Helper binaries must have EVERY ancestor directory up to `/` root-owned and not group/world-writable |
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
  `ipsec*`, `strongswan*`, `cloud`, `mysql/debian.cnf`, `*.env`. The server policy for rule `fact_requests` is
  stricter than the agent's (see section 4); the agent never relies on it and re-checks its own denylist on the
  resolved physical paths.
- Only regular, world-readable (`mode & 0o004`) files are read; files are opened with
  `O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC` (Linux: `openat2` `RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH`, fallback to an
  `openat` component walk), the mode is checked on the open fd, and every ancestor directory of the physical path
  must have the "other" execute bit (a 0644 file below a 0700/0750 directory is not readable by an unprivileged
  user and is skipped). Files with a NUL byte or `-----BEGIN ` anywhere in what is read (≤ 1 MiB) are skipped;
  crypt-hash lines (`^[^:]+:\$id\$`) are dropped.
- `pattern` is RE2 (Go `regexp`), max 512 chars, repeat counts ≤ 100 and a compiled program of ≤ 2000
  instructions (larger patterns are rejected). Per file max 1 MiB.
- Order per line: cut to 4 KiB, drop crypt-hash lines, **mask secrets, then match the pattern against the masked
  text** (so a pattern cannot probe secret values character by character), return the masked text.
- Value: matched lines, trimmed, prefixed with `<file>:`; each line truncated to 512 bytes.
- Secret masking: the value (rest of the line) after a key that contains `key`, `secret`, `token`, `pass`, `pw`,
  `psk`, `credential`, `auth` or `community` anywhere (case-insensitive; optional quotes; separator `:`, `=` or
  whitespace) is replaced with `***`, the key is kept. Not masked: booleans (`on/off/yes/no/true/false/enabled/
  disabled`), numbers (for keys that contain only `key`/`auth`, or end in a tuning suffix such as `_size`,
  `_timeout`, `_max`), system paths (`/etc/...`, `/var/...`), and `proxy_pass`-style/`auth_basic`/`passenger*`
  directives. `Bearer <anything>` anywhere on a line is masked; URL userinfo becomes `://***@`; tokens of 32+ chars
  from `[A-Za-z0-9+/=_-]` mixing letters and digits/cases become `***`.
- Budgets: per check-in at most 20 requests (deduplicated by name and by (path, pattern)), 2 MiB read in total,
  500 lines in total (200 per request), 5 s wall time. Requests beyond a budget yield no fact.

## 4. Rules

Rules come from three layers, lowest precedence first (details: [rules-feed.md](rules-feed.md)):

1. **built-in**: the YAML files of `rules/` (shipped, `status: reviewed`), embedded in the binary with
   `go:embed`; `rules_dir`, when it exists, adds rules and replaces embedded ones with the same `id`;
2. **feed**: the verified bundle of the signed central rules feed (only when `rules.feed.enabled`);
3. **DB**: LLM drafts and user edits.

A rule from a higher layer with the same `id` overrides the lower one, except a DB `draft`, which never
replaces a rule from a lower layer (the lower rule is kept and a problem is reported). The engine exposes
each rule's source (`builtin`, `feed:<seq>`, `db`; `Engine.Sources()`). Rule ids match
`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`.

**Rule tests.** `tests/<rule-id>.yaml` is a YAML list of cases
`{name, finding: {vuln, package, source, type, version, severity, kev}, facts: {...}, host: {os_id, os_version_id, arch, labels}, want: <verdict>}`;
`rules.RunTests(rules, tests)` evaluates them with the real Engine (the rule under test must be the one that
matches). The shipped rules' tests live in `rules-tests/`.

**Rules feed bundle** (`rules-<seq>.tar.gz`, `.sig`, `latest.json`; full description in
[rules-feed.md](rules-feed.md)):
- `rules-<seq>.tar.gz` holds `index.json`, `rules/<id>.yaml`, `tests/<id>.yaml` and nothing else.
  `index.json` = `{format: 1, seq: <uint64>, created_at, min_server_version?, catalog: [fact names used],
  rules: [{id, file, sha256}], tests: [{id, file, sha256}]}`. Every rule is `status: reviewed`.
- `rules-<seq>.tar.gz.sig` = `{alg: "ed25519", key_id: <first 16 hex of sha256(pubkey)>,
  sig: base64(ed25519.Sign(priv, sha256(tarball)))}`.
- `latest.json` = `{seq, url (relative or absolute), sha256, sig: <the sig object>}`; servers poll it.
- Acceptance (atomic, any failure rejects the whole bundle, the installed bundle stays): pointer <= 64 KiB,
  https (or file://), no redirects; `seq` greater than the installed one (lower is logged and ignored);
  tarball <= 10 MiB with the pointer's sha256; signature by a key in `rules.feed.trusted_keys`; strict in-memory
  extraction (only the three name patterns, regular files, <= 5000 entries of <= 256 KiB, every file listed with
  a matching sha256, nothing unlisted, `index.json` `seq` equal to the pointer's); every rule parses, passes
  `Validate` and is `reviewed`; the bundle's tests pass. The accepted bundle is persisted in
  `data_dir/rules-feed/` and re-verified at start. kv keys: `rulesfeed.seq`, `rulesfeed.updated_at`,
  `rulesfeed.checked_at`, `rulesfeed.last_error`, `rulesfeed.failures`.

`fact_requests` policy (enforced by `Validate`): at most 5 per rule; name `file.match:<ruleID-sanitized>.<id>`
(`[a-z0-9._-]`, at most 64 chars after the prefix; ruleID lowercased, other characters become `-`).
- `path` (`rules.FileMatchPathAllowed`): absolute, clean, under `/etc/`, `/opt/<app>/conf/`, `/opt/<app>/etc/` or
  `/usr/local/etc/`, without `[`, `]`, `\`. Wildcards (`*`, `?`) are allowed **only in the final component**, which
  must have a literal prefix or suffix of at least 3 characters. Every directory component is literal and is checked
  exactly against the agent's denylist; the literal parts of the final component are checked against it as
  substrings, and a final component containing `key`, `secret`, `token`, `shadow`, `passwd`, `credential`, `.pem`,
  `.p12`, `.pfx`, `.jks`, `.env`, `htpasswd` (also `keystore`, `sudoers`, `keytab`) is rejected. In addition the
  server rejects an explicit list of credential-bearing locations (`/etc/kubernetes`, `/etc/rancher`, `/etc/fstab`,
  `/etc/exim4/passwd.client`, `/etc/postfix/sasl_passwd*`, `/etc/samba/smbpasswd`, `/etc/pgbouncer`,
  `/etc/wpa_supplicant`, `/etc/environment`, `/etc/default`, `/etc/sysconfig`, `/etc/aws`, `/etc/gcloud`,
  `/etc/vault*`, `/etc/consul*`, `/etc/nomad*`, `/etc/ansible`, `/etc/ldap`, `/etc/dovecot`, `/etc/docker`,
  `/etc/cron*`, `/etc/redis`, `/etc/mysql`, `/etc/postgresql`, `/etc/krb5*`, `/etc/letsencrypt`, `/etc/ssl`,
  `/etc/pki`, ... see `rules/filematch.go`). The server policy is stricter than the agent's; the agent re-checks its
  own denylist on resolved paths and does not rely on the server.
- `pattern` (at most 256 chars, valid RE2, repeat counts at most 100): must contain a **mandatory literal** of at
  least 4 characters (a literal every match must contain: parts under `?`/`*` quantifiers do not count; in an
  alternation every branch must have one; case-insensitive literals are fine), must not match the empty string, and
  must match at most 3 of ~45 diverse probe lines (words, digits, punctuation, typical config lines).
- Only `reviewed` rules' fact requests are sent to agents; drafts are inert. Evaluation reasons never contain
  `file.match` values, only `file.match:<id>=<N> matching lines`.

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
`packages` selector matches (`type` equal or empty, and exactly one of `name`, a `path.Match` glob over the
binary package name, e.g. `nginx*`, `linux-image-*`, or `source`, an exact match on the source package: the
PURL `upstream` qualifier without version, else the package name; for rpm the source RPM file name reduced to
its package name). `status: rejected` rules are ignored. Several rules may cover the same CVE for
different packages (e.g. `CVE-2023-44487-nginx` and `CVE-2023-44487-apache`); if more than one applies,
the winner is chosen by status (`reviewed` over `draft`), then layer (DB over feed over built-in), then the first by ID.

### CEL environment
Variables:
- `facts` — `map(string, dyn)` (host facts)
- `pkg` — `map(string, dyn)`: `name` (binary package), `source` (source package), `version`, `type`, `purl`, `fixed_versions` (list), `target`, `target_kind`
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
6. Draft guard (applied to the result of steps 3-4; only when `status` is `draft`). A draft never lowers a verdict:
   - Any outcome other than `exploitable` (that is `affected_not_exploitable`, from `not_affected_if` or
     `exploitable_if` false) becomes `conditions_unknown`, at every severity, reason
     `LLM draft suggests not exploitable (unreviewed): <explanation[:200]>`. Only `reviewed` rules can yield
     `affected_not_exploitable`.
   - `exploitable` is kept (reason prefixed `LLM draft (unreviewed): `) only if the draft is *grounded*, otherwise it
     becomes `conditions_unknown`, reason `LLM draft: condition does not depend on host facts`. Grounded means
     (a) syntactically, the checked CEL AST of `exploitable_if`/`not_affected_if` references at least one fact that is
     not `<x>.installed` (names in string literals or only listed in `facts` do not count), and (b) semantically,
     `exploitable_if` is fact-dependent: at compile time the expression is evaluated (at most 256 evaluations, the
     usual cost limit) against synthetic activations in which every referenced fact is varied over type-appropriate
     values (missing, empty, typical, the literals it is compared with, +-1 for numbers; maps and lists with the
     referenced keys/elements present and absent) while `pkg` (taken from the rule's package selectors) and `host`
     are held constant. If the result never takes both values true and false (errors are ignored), e.g.
     `facts["os.id"] == facts["os.id"]`, `x != "" || true`, `size(l) >= 0`, `true || ...`, `c ? true : true`, the rule
     is fact-independent. The result is computed once per compiled rule.
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
   A permanent 4xx from Matrix (other than 429) is logged at ERROR; for `resolved`, `agent_back`, `feed_ok` and
   `pipeline_error` events it is recorded as delivered (not retried forever). For `exploitable`, `unknown_critical`,
   `agent_silent` and `feed_stale` events a permanent failure is reported as failed (retried on later runs) and
   surfaced through `notify.Config.OnDeliveryProblem(room, status, kind, permanent)` (wired to kv `health.notify_errors`,
   the last 20 distinct problems, shown as a dashboard banner). "No room resolved for an event" is an error reported the
   same way (not a silent success). A given (room, status) is logged / reported at most once per 10 min, and a retried
   event is not posted again to rooms it already reached.
   Message text: every untrusted field is cut to 300 characters with control characters removed and a zero-width space
   after every `@` (no `@room` pings); every message carries `"m.mentions": {}`. At most 50 events are rendered per
   group and 5 fixed versions per package ("+N more"); plain and formatted body are each capped at 8 KiB after HTML
   escaping; for draft (unreviewed LLM) rules only a warning and the server-generated fix command are shown.
   Each pipeline run has a 10 min timeout; a panic in any background goroutine is logged and recovered, and a
   target whose matching panicked is flagged (`kv poison.<host>.<target-hash>`) and skipped until a new inventory arrives.
   A target whose matching fails or exceeds its own 5 min timeout is isolated the same way (previous findings carried over,
   error recorded, `Options.OnProblem` -> health `pipeline_error`) and the other targets are still processed; the run fails
   only when no target could be matched at all. A missing vulnerability DB (`match.ErrNoDB`, e.g. right after start) is
   not a target problem: the run changes nothing, does not poison the target, does not count as a failed run and raises
   no `pipeline_error`; the host is remembered and re-run when the DB is loaded (`feeds.Updater.OnUpdated` fires after the
   initial load as well, with `feeds.update` true or false). The built-in local agent waits for the DB (max 2 min) before
   its first upload. A run that completes with no skipped/failed/poisoned target clears the host's entry in
   `health.pipeline_errors`. Wording: "matching failed" for ordinary errors, "crashed" only for recovered panics. At most 2 hosts match concurrently, slots are granted FIFO, so a host that
   just finished queues behind hosts already waiting. Per host: matcher time is budgeted per rolling hour
   (`limits.match_seconds_per_host_hour`; over budget -> runs deferred, WARN + hook) and open findings are capped
   (`limits.findings_per_host`; lowest severity dropped first, WARN + hook).
   Retention: a daily job (and one at start) deletes resolved findings older than `retention.resolved_findings` and
   `notifications_sent` rows older than `retention.notifications` (rows of still-open findings are kept so alerts are not repeated).

### Health events (silence alerts)

`model.Event` additionally carries `Detail` (human text) for events without a finding. Kinds, evaluated by
`internal/server/health` every minute (dedup via `notifications_sent` keys `host|<id>|<kind>` and `server|feed|<kind>`):

- `agent_silent` — a host that has checked in at least once has not checked in for `alerts.agent_silent_after`.
  Routed by the host's labels. When more than max(5, 30% of the fleet) hosts go silent in one pass (mass silence), the
  hosts are still announced where their owners look: one event without a host (`Host.ID == ""`, "N agents silent —
  server/network problem?", the first 50 hosts by last check-in, newest first, with IDs, and a link to the hosts page)
  goes to the ops rooms, and for every label one event (`Host.ID == "group:<label>"`, `Host.Labels == [label]`) lists
  up to 50 silent hosts carrying that label to that label's rooms (unlabelled hosts go to the default rooms). A host's
  silence is recorded as notified only when a delivered message names it; unnamed hosts are announced on the next pass.
  Held back for 2 x check-in interval after server start.
- `agent_back` — a silent host checked in again (clears the silent record so a later silence alerts again).
- `feed_stale` / `feed_ok` — the vulnerability DB (kv `feeds.grype.updated_at` or the loaded DB build time, whichever is
  newer) is older than `alerts.feed_stale_after`, or `feeds.grype.last_error` stayed set for more than 2 consecutive
  checks; ok on recovery. Ops rooms.
- `pipeline_error` — 3 consecutive failed pipeline runs for a host, or a poisoned target; once per host per 24 h
  (kv `health.pipeline_alert.<host>`); more than 5 hosts at once are aggregated. Ops rooms.

`Event.ServerLevel()` marks events routed to `alerts.ops_rooms`. Health events are never grouped with each other or
with findings and are exempt from burst summarising. The web dashboard shows active feed/pipeline problems from kv
`health.feed_stale`, `health.pipeline_errors` and `health.notify_errors`.

## 6. Server configuration (`/etc/panoptes/server.yaml`, all keys optional)

```yaml
listen: ":8080"                       # agent API: /api/v1/* and /healthz only
admin_listen: "127.0.0.1:8081"        # web UI (+ /healthz); empty or == listen: one shared port (legacy, WARN)
public_url: "http://localhost:8081"   # base URL of the admin UI, used for links in notifications
# tls_cert / tls_key (agent listener) and admin_tls_cert / admin_tls_key (admin listener): native TLS, min 1.2
trusted_proxies: []                   # CIDRs; X-Forwarded-For is honoured only when the peer is in this list
alerts:
  agent_silent_after: 30m             # 0 disables agent_silent / agent_back
  feed_stale_after: 48h               # 0 disables feed_stale / feed_ok
  ops_rooms: []                       # Matrix rooms for server-level events; empty: matrix.default_rooms
triage:
  epss_threshold: 0.1                 # 0..1; web UI tier: conditions_unknown with EPSS >= this needs attention
data_dir: /var/lib/panoptes           # SQLite DB + Grype DB cache
feeds:
  interval: 6h                        # vuln DB / KEV / EPSS refresh
rules_dir: /usr/share/panoptes/rules  # optional: adds to / overrides the rules embedded in the binary
rules:
  feed:                               # signed central rules feed (docs/rules-feed.md); off by default
    enabled: false                    # env PANOPTES_RULES_FEED_ENABLED
    url: ""                           # latest.json, https:// (file:// for mirrors); empty = import only
    interval: 6h                      # >= 1m
    trusted_keys: []                  # base64 ed25519 public keys; required when enabled (list two while rotating)
    stale_after: 7d                   # feed_stale ("rules feed") when no poll succeeded for this long or 3 polls failed
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
retention:                            # 0 = keep forever; accepts "30d" and Go durations
  resolved_findings: 30d              # delete resolved findings after this age
  notifications: 90d                  # delete notification dedup rows after this age
limits:                               # 0 = unlimited
  findings_per_host: 20000            # open findings per host; excess dropped by lowest severity
  match_seconds_per_host_hour: 900    # matcher time per host per rolling hour; over budget -> runs deferred
local_agent:                          # agentless mode: the server monitors its own host (see below)
  enabled: false                      # env PANOPTES_LOCAL_AGENT_ENABLED
  source: auto                        # collector | inprocess | auto
  collector_socket: /run/panoptes/collector.sock
  labels: [server]                    # authoritative (locked) labels of the local host
  checkin_interval: 5m                # >= 1m
  inventory_interval: 6h              # >= 1m
  scan_language_packages: true
  exclude_paths: []                   # empty = agent defaults (§2)
  docker_socket: /var/run/docker.sock
```

Validation: with `rules.feed.enabled`, `rules.feed.trusted_keys` must hold at least one valid key and `rules.feed.url`
must be `https://` or `file://`; `rules.feed.interval` is at least 1m. `*_env` names must match `^PANOPTES_[A-Z0-9_]+$` and `matrix.access_token_env`, `llm.api_key_env`,
`admin.initial_password_env` must be pairwise different; retention/limits must not be negative.
The initial admin password needs ≥ 12 characters and may come from the file named by
`PANOPTES_ADMIN_PASSWORD_FILE`. Startup logs a WARN when `public_url`, `matrix.homeserver` or `llm.base_url`
use `http://` for a non-loopback host, when the Grype DB is older than 5 days, when `trusted_proxies` has an entry wider
than /16 (IPv4) or /48 (IPv6) or `0.0.0.0/0`/`::/0`, when `admin_listen` is non-loopback without admin TLS, and when
the agent listener is non-loopback without `tls_cert` and without `trusted_proxies` (public-facing, no TLS-terminating proxy). The server runs with
`umask 077` and a 0600 database file; HTTP limits: header ≤ 64 KiB, read timeout 5 min, write timeout 2 min.

Listeners: the agent listener serves only `/api/v1/*` and `/healthz` (everything else is 404); the admin listener
serves the web UI and `/healthz` and not the agent API. With `admin_listen` empty or equal to `listen` both share one
port. `trusted_proxies`: only when the TCP peer is in the list is the client IP taken from the right-most
`X-Forwarded-For` entry that is not itself a trusted proxy (used for rate limits and the audit log); a malformed or
zoned (`fe80::1%eth0`) entry makes the peer address the client.
`panoptes-server user set-password` needs at least 12 characters.

### Agentless mode (`local_agent`)

With `local_agent.enabled: true` the installed `panoptes-server` monitors **its own host** without a separately
installed `panoptes-agent`; the host appears like any other host (findings, rules, Matrix alerts, silence alerts).
`internal/server/localagent` runs the normal agent runner (§2) in the server process and gives it an `http.Client`
whose `RoundTripper` calls the agent API handler (the mux the agent listener serves) directly in memory (base URL
`https://panoptes.local`, `RemoteAddr` `127.0.0.1:0`, nothing touches the network). Every server-side validation,
limit, authentication and pipeline path therefore applies exactly as for a remote agent; gzip request bodies work.

- **Data source** (`local_agent.source`): `collector` connects to the root collector's unix socket
  (`collector_socket`; recommended: the server stays unprivileged, the host runs only `panoptes-collector.service`);
  `inprocess` collects in the server process with the server's privileges (`hostdata.Local`; one WARN that facts may
  be incomplete when euid != 0; meant for dev and single-box setups; inside a container it scans the container, not
  the host); `auto` (default) uses `collector` when a probe request on the socket succeeds, otherwise `inprocess`,
  and logs the choice. The collector accepts only root and `collector_user` (SO_PEERCRED), so with `collector` the
  server must run as that user (`panoptes`), not as a systemd `DynamicUser`.
- **data_dir is never scanned**: the in-process scanner always excludes `data_dir` (on top of `exclude_paths`).
  Closing any file descriptor of a file drops the process's POSIX locks on it, so a scanner that merely opens
  the server's own SQLite files would corrupt the database that the store holds open (observed in the e2e run).
- **Enrollment without tokens**: at start the server provisions the host itself (direct store call, not an enroll
  token; the host's token name is `local-agent`). `machine_id` is the same hashed machine id an agent computes
  (`hostinfo.MachineID`, from the collector when `source` is `collector`), hostname the OS hostname, labels
  `local_agent.labels` (authoritative and locked like enrollment-token labels; a change of the setting is applied
  at the next start and rotates the key). The plain agent key is stored only in
  `data_dir/local-agent/credentials.json` (0600); the DB holds its hash. A restart reuses it. The host id is kept
  in kv `local_host`, which makes the web UI show a "local (built-in)" badge on the hosts list and the host page.
- **Conflict rule**: if a host with the same machine id already exists that these credentials do not
  authenticate (e.g. a standalone agent was installed on this box first), the local agent does NOT take it over:
  it logs one ERROR (`panoptes-server host delete <hostname>` and uninstall the agent, or disable `local_agent`)
  and does not start. A host this server provisioned itself is recovered after a crash mid-rotation.
- **Lifecycle**: started after the pipeline and both listeners are up, stopped on shutdown; a panic or error is
  logged and the agent restarts with backoff (5 s doubling to 5 min); it never takes the server down. The local host
  is subject to the normal health logic: a stalled local agent raises `agent_silent`. A `host delete` of the local
  host while the server runs is only noticed after a restart (the in-process agent retries unauthorised calls
  hourly).

Environment variable `PANOPTES_CONFIG` points to the file; every scalar can be overridden by
`PANOPTES_<SECTION>_<KEY>` (e.g. `PANOPTES_MATRIX_HOMESERVER`).

## 7. Build constraints

- SQLite drivers: both SQLite drivers register the `database/sql` name `sqlite`, and a second registration panics
  at start-up ("Register called twice"). The **server** links `github.com/glebarez/go-sqlite` (Grype and the
  store); it also links the agent's inventory scanner (Syft) for the built-in local agent (§6), and Syft's RPM
  cataloger then uses that same driver. `modernc.org/sqlite` is therefore imported **only** by the agent binary,
  in `cmd/panoptes-agent/sqlite_driver.go` (never in `internal/agent/inventory` or any other library package).
  `cmd/panoptes-server/sqlite_driver_test.go` asserts that the server's dependency graph does not contain
  `modernc.org/sqlite`, that the agent's does, and that `sql.Drivers()` lists `sqlite` exactly once.
- Package boundaries: the server and the agent share only `internal/model`, with one exception: the built-in
  local agent, `internal/server/localagent` (imports `agent/{config,hostdata,runner,transport}`).
- Grype DB v6 provides KEV and EPSS; there are no separate CISA/FIRST fetchers.
