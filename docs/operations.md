# Operations

Day-to-day running of Holealign: the `holealign-server` command line, backup and restore, retention and
limits, health alerts, running without internet access, monitoring and logs, key and token rotation,
re-enrolling a host and scaling. Symptoms and fixes are in [troubleshooting.md](troubleshooting.md). Installation is in [installation.md](installation.md), every setting in
[configuration.md](configuration.md).

Contents: [CLI reference](#cli-reference) - [Backup and restore](#backup-and-restore) -
[Upgrades](#upgrades) - [Retention and limits](#retention-and-limits) - [Health alerts](#health-alerts) -
[Air-gapped and feed updates](#air-gapped-and-feed-updates) - [Monitoring and logs](#monitoring-and-logs) -
[Troubleshooting](#troubleshooting) - [Key and token rotation](#key-and-token-rotation) - [Re-enrolling a host](#re-enrolling-a-host) -
[Scaling notes](#scaling-notes)

## CLI reference

```
holealign-server [-config FILE] [serve]
holealign-server [-config FILE] token create <name> [-max-hosts N] [-expires 72h] [-labels a,b]
holealign-server [-config FILE] token list
holealign-server [-config FILE] token revoke <name>
holealign-server [-config FILE] host list
holealign-server [-config FILE] host allow-reenroll <id|hostname> [-ttl 1h]
holealign-server [-config FILE] host delete <id|hostname>
holealign-server [-config FILE] user set-password <user>          # password on stdin
holealign-server rules keygen|build|sign|verify|import|status|candidates|draft   # rules feed tooling, see rules-feed.md
holealign-server -version
```

The config file is `-config`, else `$HOLEALIGN_CONFIG`, else `/etc/holealign/server.yaml` if it exists.
`-config` may also come after the subcommand. The commands open the same SQLite database as the
running server (`data_dir`), so they use the same configuration.

| Command | What it does |
|---|---|
| `serve` | Run the server (the default). |
| `token create <name>` | Create an enrollment token. The secret `pt_...` is printed **once** on stdout (a note goes to stderr). `-max-hosts N`: how many hosts may enroll with it (0 = unlimited). `-expires 72h`: lifetime as a Go duration (`h`, `m`; no `d` here; 0 = never). `-labels a,b`: **authoritative** labels for hosts enrolled with it. Names match `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`. |
| `token list` | Name, created, last used, status (`active`, `revoked`, `expired`, `exhausted`), hosts used/max, expiry, labels. |
| `token revoke <name>` | Stop the token from enrolling more hosts. Agents already enrolled keep working. |
| `host list` | ID, hostname, labels, last check-in, token name, and whether a re-enroll is currently allowed. |
| `host allow-reenroll <host> [-ttl 1h]` | Allow **one** re-enrollment of that host without its old key, for the TTL (default 1 h, maximum 168 h). See [Re-enrolling a host](#re-enrolling-a-host). |
| `host delete <host>` | Delete the host and its findings, notification dedup records and state. `<host>` is the ID or the hostname; an ambiguous hostname needs the ID. |
| `user set-password <user>` | Set the password of a web user, or create the user. The password (12 or more characters) is read from the first line of stdin, so it stays out of the process list. |
| `rules keygen`, `build`, `sign`, `verify` | Build and sign rule bundles for the central rules feed; they need no configuration or database. `rules import <tarball>` installs a signed bundle on an air-gapped server and `rules status` shows the installed bundle. See [rules-feed.md](rules-feed.md). |

Tokens and users can also be managed in the web UI (Settings); every sensitive action there asks for
your current password.

**Where to run it.**

- Docker: `docker compose exec holealign-server holealign-server token list` (add `-T` and a here-string
  when piping a password).
- systemd: run as root (`sudo holealign-server host list`). When started as root while the data
  directory belongs to the service user (the packaged unit uses a dynamic user), the command drops to
  that uid/gid first, so no root-owned database files appear and the service is not locked out. If
  it cannot drop privileges it refuses and tells you to run as the owning user.
- Start the service once before using the CLI, so `data_dir` exists with the right owner.

```sh
read -rs -p 'New password: ' PW; echo
printf '%s\n' "$PW" | sudo holealign-server user set-password admin; unset PW
```

## Backup and restore

All server state is in `data_dir` (default `/var/lib/holealign`):

| Path | Content | Back up? |
|---|---|---|
| `holealign.db` (+ `-wal`, `-shm` while running) | SQLite, WAL mode: everything below | yes |
| `grype-db/` | Grype vulnerability DB cache | no, downloaded again (about 100 MB) |
| `rules-feed/` | the accepted rules bundle | no, downloaded again at the next poll (air-gapped: keep the tarball you imported) |
| `local-agent/credentials.json` | key of the built-in local agent (agentless mode), 0600 | optional; without it the local agent provisions a new key at start |

The server holds no private keys of its own: agent keys and enrollment tokens are stored only as
SHA-256 hashes, and passwords as bcrypt hashes. Back up the database and your configuration:

| What | Where | Needed for |
|---|---|---|
| `holealign.db` | `<data_dir>` | hosts and agent key hashes, findings, user and LLM rules, tokens, users, Matrix routes edited in the UI, notification dedup state |
| `server.yaml`, `server.env` | `/etc/holealign/` (or `deploy/.env`) | settings and secrets |
| TLS certificate and key, CA file | wherever you keep them | agent API and admin listeners; agents need the CA file or pins |
| agent hosts | nothing | agents keep their key in `state_dir`; they can be reinstalled |

Consistent copy, online (needs the `sqlite3` CLI):

```sh
sudo sqlite3 /var/lib/holealign/holealign.db ".backup '/backups/holealign-$(date +%F).db'"
```

Or stop the server and copy the files:

```sh
sudo systemctl stop holealign-server
sudo cp -a /var/lib/holealign/holealign.db* /backups/        # the -wal and -shm files belong with it
sudo systemctl start holealign-server
```

Docker volume (stop the container first; find the volume name with `docker volume ls`):

```sh
docker compose stop holealign-server
docker run --rm -v deploy_holealign-data:/data -v "$PWD":/backup busybox \
  tar czf /backup/holealign-data.tgz --exclude=grype-db -C /data .
docker compose start holealign-server
```

**Restore.** Stop the server, put `holealign.db` back in `data_dir` (remove stale `-wal` and `-shm`
files), give it to the service user (for the packaged unit: `sudo chown -R "$(stat -c %u:%g
/var/lib/private/holealign)" /var/lib/private/holealign`; in Docker the user is uid 65532), mode
0600, start the server. It runs any missing migrations itself. Schema migrations are one-way: to go
back to an older version, restore a backup taken with it.

If the database is lost entirely, agents get `401` (their key hash is gone). Their enrollment token
was blanked after the first check-in, so each host needs a fresh enrollment token in
`agent.yaml`; see [Re-enrolling a host](#re-enrolling-a-host).

Test a backup: restore it on another machine with the same version and open the UI. A backup is
sensitive: it holds hostnames, package inventories, findings and password hashes.

## Upgrades

1. Read [CHANGELOG.md](../CHANGELOG.md) for the new version.
2. Back up (above). Migrations are one-way.
3. Upgrade the server ([installation.md](installation.md#upgrading)); migrations run at start. Check
   `journalctl -u holealign-server` for `holealign-server listening`.
4. Restart after a rules update: shipped rules are read at start. Signed feed rules and web-edited
   rules reload on their own.
5. Upgrade agents at your pace: old agents keep working within the same API version
   ([contracts.md](contracts.md)). Re-run `install.sh --version X.Y.Z --min-version X.Y.Z` per host or
   use your configuration management.

Roll back by restoring the backup and installing the old version.

## Retention and limits

| Key | Default | Effect |
|---|---|---|
| `retention.resolved_findings` | `30d` | A daily job (and one at start) deletes resolved findings older than this. `0` keeps them. |
| `retention.notifications` | `90d` | Deletes notification dedup rows older than this; rows of still-open findings are kept so alerts are not repeated. |
| `limits.findings_per_host` | `20000` | Open findings kept per host, ranked after rule evaluation (exploitable, then conditions unknown, then KEV, severity, CVSS). Findings over the cap keep their previous state and never turn into `resolved`. WARN and a `pipeline_error` alert. |
| `limits.match_seconds_per_host_hour` | `900` | Grype time per host per rolling hour; over budget, runs are deferred (WARN and alert). |
| `limits.inventory_attempts_per_minute` | `10` | Inventory uploads per host per minute, charged before the body is read (identical re-uploads too); over it: 429 with `Retry-After`. |
| `limits.inventory_attempt_burst` | `6` | Burst of the bucket above. |
| `limits.inventory_concurrent_decodes` | `4` | Inventory bodies decoded at once, server-wide; one at a time per host. Over it: 503 (server) or 429 (same host) with `Retry-After`. |

Rate limits per client address or host that are not configurable: check-ins burst 3 then 1 per 20 s,
inventories burst 3 then 1 per 5 min, invalid enrollments 10/min, failed bearer authentications 30/min,
invalid inventories 6/min per host. Behind a proxy without `trusted_proxies` all clients share one
address and these per-client limits.

Other built-in bounds (not configurable): at most 2 hosts are matched at once, each run has a 10
minute timeout and each target 5 minutes; an inventory is capped at 64 MiB decompressed, 50 000
components per SBOM and 1000 targets; facts at 1000 keys and 1 MiB. Details:
[contracts.md section 1 and 5](contracts.md#1-agent--server-http-api-apiv1).

## Health alerts

The server checks itself every minute and reports to Matrix ([notifications.md](notifications.md)):

| Alert | Trigger | Switch off |
|---|---|---|
| Agent silent / back | no check-in for `alerts.agent_silent_after` (30 m) | `0` |
| Feed stale / OK | vulnerability DB older than `alerts.feed_stale_after` (48 h), or refresh failing | `0` |
| Feed stale / OK (rules feed) | with `rules.feed.enabled` and a `url`: no successful poll for `rules.feed.stale_after` (7 d), or the last 3 polls failed; detail starts with "rules feed" | `0` |
| Pipeline error | 3 failed runs for a host, a skipped (poisoned or invalid) target, or a host limit hit | n/a |

The dashboard also shows active feed, pipeline and Matrix-delivery problems as banners. Silence
alerts need hosts that have checked in at least once, and are held back for twice the check-in
interval after a server start.

## Air-gapped and feed updates

Vulnerability data (Grype DB v6, including KEV and EPSS) is refreshed every `feeds.interval` (6 h).
To run without it reaching the internet:

1. Set `feeds.update: false` (`HOLEALIGN_FEEDS_UPDATE=false`). The log then says
   `feed updates disabled (feeds.update=false)`.
2. Provide a Grype DB in `<data_dir>/grype-db/`: the directory that contains `6/vulnerability.db`.
   On a connected machine with the Grype CLI, `GRYPE_DB_CACHE_DIR=/tmp/grype-db grype db update`
   produces it; copy that directory to the server (the end-to-end test does the same with
   `GRYPE_DB_CACHE`). Repeat on your own schedule and restart the server afterwards, so that it is
   certain to load the new database.
3. Avoid false `FEED STALE` alerts: raise `alerts.feed_stale_after` to your refresh cadence plus
   margin, or set it to `0`. At start the server warns when the DB is older than 5 days.
4. Leave `llm.provider` at `none` (drafting also contacts `api.osv.dev`), or use a local
   OpenAI-compatible endpoint. Matrix can be an internal homeserver.

Agents never need the internet: they only reach `server_url`.

## Monitoring and logs

Logs are structured text (`key=value`) on stderr.

| What | Command |
|---|---|
| Server (systemd) | `journalctl -u holealign-server -f` |
| Server (Compose) | `docker compose logs -f holealign-server` |
| Agent | `journalctl -u holealign-agent -u holealign-collector -f` |
| Audit trail | `journalctl -u holealign-server \| grep 'msg=audit'`: login, logout, rule approve/reject/edit, token create/revoke, user add/delete/password change, Matrix route changes, with actor and client IP |
| Warnings about the setup | `journalctl -u holealign-server \| grep 'insecure configuration'` |

`GET /healthz` returns `200 ok` on both listeners, with no authentication; use it for load balancer
or uptime checks (the distroless image has no shell, so there is no Compose healthcheck). There
is no metrics endpoint: watch `/healthz` and the Matrix ops alerts. The agent has `-log-level debug`
for more detail; `holealign-agent -print-facts` and `-print-inventory` show what it would send.

## Troubleshooting

Symptom, cause and fix tables live in [troubleshooting.md](troubleshooting.md).

## Key and token rotation

| Secret | How to rotate |
|---|---|
| Enrollment token | `token create` a new one, then `token revoke` the old. Revoking stops new enrollments only; enrolled agents keep working. Use short `-expires` and `-max-hosts`. |
| Agent key | Re-enroll the host ([below](#re-enrolling-a-host)): the new key replaces the old one. |
| Web password | Settings, Users (asks your current password), or `user set-password <user>`. |
| Matrix token, LLM key, admin password variable | Change `server.env` (or `.env`) and restart the server. |
| Server TLS certificate | Renew the files and restart the server. Agents with `server_cert_sha256` need the new key's pin: list old and new pins first, rotate the certificate, remove the old pin later. A renewal with the same key keeps the pin valid. |
| Rules feed signing key | Add the new public key next to the old one in `rules.feed.trusted_keys`, publish bundles signed with the new key, then remove the old one ([rules-feed.md](rules-feed.md)). |
| Local agent key | Changing `local_agent.labels` rotates it at the next server start; no other action is needed. |

## Re-enrolling a host

A host keeps working with its agent key. Re-enrolling is needed when it lost the key (wiped
`state_dir`, reinstalled OS, cloned machine) or the server lost its record.

An enrolled host cannot be re-enrolled by anyone holding only an enrollment token: the server answers
`409` unless the request carries the current agent key, or an administrator allowed it.

1. On the server allow one re-enrollment (default 1 h, maximum 168 h):

   ```sh
   holealign-server host allow-reenroll web-01 -ttl 2h
   holealign-server host list            # REENROLL column shows "allowed until ..."
   ```

2. On the host put a **fresh** enrollment token into `/etc/holealign/agent.yaml`
   (`holealign-server token create web-01-again -max-hosts 1 -expires 2h`), then
   `systemctl restart holealign-agent`.
3. The agent enrolls, receives a new key (the old one stops working), and the permission is used up.
   The host record is kept: its labels (or the new token's labels, if it has any), findings and
   history stay. After the first check-in the token is removed from the file again.

If you do not need the history, `host delete <host>` followed by a normal enrollment is simpler.

## Scaling notes

- One server process and one SQLite file. There is no clustering and no external database; run one
  server per data directory. Measured capacity figures are not published: size by watching your own
  fleet.
- Work that scales with hosts: Grype matching (at most 2 hosts at once, 10 minute run timeout,
  `limits.match_seconds_per_host_hour` per host), inventory decoding (`limits.inventory_concurrent_decodes`)
  and rule evaluation after each inventory or rules change. The shipped Compose file and unit allot 4 GiB of memory; watch
  the server's memory on your fleet before you lower it.
- Each agent checks in every 5 minutes (a small JSON request) and uploads an inventory only when
  packages changed or every `inventory_interval` (6 h). Raise `checkin_interval` for very large fleets
  (the server may suggest a value; agents clamp it to 60 s to 1 h).
- Behind one NAT or proxy, set `trusted_proxies` so per-client limits see real addresses.
- Keep `data_dir` on local disk (SQLite WAL does not work well on network filesystems) with room for
  the Grype DB (about 100 MB download) and a second copy while it updates.
- A host with a huge SBOM is bounded by `limits.findings_per_host`; a `pipeline_error` alert tells you.
