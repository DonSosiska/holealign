# Operations

Day-to-day running of Panoptes: the `panoptes-server` command line, backup and restore, retention and
limits, health alerts, running without internet access, logs, a troubleshooting table, and how to
re-enroll a host. Installation is in [installation.md](installation.md), every setting in
[configuration.md](configuration.md).

Contents: [CLI reference](#cli-reference) - [Backup and restore](#backup-and-restore) -
[Retention and limits](#retention-and-limits) - [Health alerts](#health-alerts) -
[Air-gapped and feed updates](#air-gapped-and-feed-updates) -
[Monitoring and logs](#monitoring-and-logs) - [Troubleshooting](#troubleshooting) -
[Re-enrolling a host](#re-enrolling-a-host)

## CLI reference

```
panoptes-server [-config FILE] [serve]
panoptes-server [-config FILE] token create <name> [-max-hosts N] [-expires 72h] [-labels a,b]
panoptes-server [-config FILE] token list
panoptes-server [-config FILE] token revoke <name>
panoptes-server [-config FILE] host list
panoptes-server [-config FILE] host allow-reenroll <id|hostname> [-ttl 1h]
panoptes-server [-config FILE] host delete <id|hostname>
panoptes-server [-config FILE] user set-password <user>          # password on stdin
panoptes-server -version
```

The config file is `-config`, else `$PANOPTES_CONFIG`, else `/etc/panoptes/server.yaml` if it exists.
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

Tokens and users can also be managed in the web UI (Settings); every sensitive action there asks for
your current password.

**Where to run it.**

- Docker: `docker compose exec panoptes-server panoptes-server token list` (add `-T` and a here-string
  when piping a password).
- systemd: run as root (`sudo panoptes-server host list`). When started as root while the data
  directory belongs to the service user (the packaged unit uses a dynamic user), the command drops to
  that uid/gid first, so no root-owned database files appear and the service is not locked out. If
  it cannot drop privileges it refuses and tells you to run as the owning user.
- Start the service once before using the CLI, so `data_dir` exists with the right owner.

```sh
read -rs -p 'New password: ' PW; echo
printf '%s\n' "$PW" | sudo panoptes-server user set-password admin; unset PW
```

## Backup and restore

All server state is in `data_dir` (default `/var/lib/panoptes`): `panoptes.db` (SQLite, WAL mode,
with `panoptes.db-wal` and `panoptes.db-shm` while running) and `grype-db/`. The Grype DB is a
cache and is downloaded again; back up the database and your configuration:

| What | Where | Needed for |
|---|---|---|
| `panoptes.db` | `<data_dir>` | hosts and agent key hashes, findings, user and LLM rules, tokens, users, Matrix routes edited in the UI, notification dedup state |
| `server.yaml`, `server.env` | `/etc/panoptes/` (or `deploy/.env`) | settings and secrets |
| agent hosts | nothing | agents keep their key in `state_dir`; they can be reinstalled |

Consistent copy, online (needs the `sqlite3` CLI):

```sh
sudo sqlite3 /var/lib/panoptes/panoptes.db ".backup '/backups/panoptes-$(date +%F).db'"
```

Or stop the server and copy the files:

```sh
sudo systemctl stop panoptes-server
sudo cp -a /var/lib/panoptes/panoptes.db* /backups/        # the -wal and -shm files belong with it
sudo systemctl start panoptes-server
```

Docker volume (stop the container first; find the volume name with `docker volume ls`):

```sh
docker compose stop panoptes-server
docker run --rm -v deploy_panoptes-data:/data -v "$PWD":/backup busybox \
  tar czf /backup/panoptes-data.tgz --exclude=grype-db -C /data .
docker compose start panoptes-server
```

**Restore.** Stop the server, put `panoptes.db` back in `data_dir` (remove stale `-wal` and `-shm`
files), give it to the service user (for the packaged unit: `sudo chown -R "$(stat -c %u:%g
/var/lib/private/panoptes)" /var/lib/private/panoptes`; in Docker the user is uid 65532), mode
0600, start the server. It runs any missing migrations itself. Schema migrations are one-way: to go
back to an older version, restore a backup taken with it.

If the database is lost entirely, agents get `401` (their key hash is gone). Their enrollment token
was blanked after the first check-in, so each host needs a fresh enrollment token in
`agent.yaml`; see [Re-enrolling a host](#re-enrolling-a-host).

## Retention and limits

| Key | Default | Effect |
|---|---|---|
| `retention.resolved_findings` | `30d` | A daily job (and one at start) deletes resolved findings older than this. `0` keeps them. |
| `retention.notifications` | `90d` | Deletes notification dedup rows older than this; rows of still-open findings are kept so alerts are not repeated. |
| `limits.findings_per_host` | `20000` | Open findings kept per host; the lowest severities are dropped first, with a WARN and a `pipeline_error` alert. |
| `limits.match_seconds_per_host_hour` | `900` | Grype time per host per rolling hour; over budget, runs are deferred (WARN and alert). |

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
| Pipeline error | 3 failed runs for a host, a skipped (poisoned or invalid) target, or a host limit hit | n/a |

The dashboard also shows active feed, pipeline and Matrix-delivery problems as banners. Silence
alerts need hosts that have checked in at least once, and are held back for twice the check-in
interval after a server start.

## Air-gapped and feed updates

Vulnerability data (Grype DB v6, including KEV and EPSS) is refreshed every `feeds.interval` (6 h).
To run without it reaching the internet:

1. Set `feeds.update: false` (`PANOPTES_FEEDS_UPDATE=false`). The log then says
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
| Server (systemd) | `journalctl -u panoptes-server -f` |
| Server (Compose) | `docker compose logs -f panoptes-server` |
| Agent | `journalctl -u panoptes-agent -u panoptes-collector -f` |
| Audit trail | `journalctl -u panoptes-server \| grep 'msg=audit'`: login, logout, rule approve/reject/edit, token create/revoke, user add/delete/password change, Matrix route changes, with actor and client IP |
| Warnings about the setup | `journalctl -u panoptes-server \| grep 'insecure configuration'` |

`GET /healthz` returns `200 ok` on both listeners, with no authentication; use it for load balancer
or uptime checks (the distroless image has no shell, so there is no Compose healthcheck). There
is no metrics endpoint: watch `/healthz` and the Matrix ops alerts. The agent has `-log-level debug`
for more detail; `panoptes-agent -print-facts` and `-print-inventory` show what it would send.

## Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| Agent log `unauthorized and cannot re-enroll; retrying later` (HTTP 401) | The server does not know the agent key: host deleted, database restored from an older backup, or token revoked before enrollment. `enroll_token` was blanked, so put a **fresh** token in `/etc/panoptes/agent.yaml`, `systemctl restart panoptes-agent`. If the host still exists on the server, run `host allow-reenroll` first. |
| 401 at enroll | Token unknown, revoked or expired: `token list`, create a new one. |
| 403 at enroll | The token's `max-hosts` is used up: create another token. |
| Agent log `server refused enrollment: host already exists` (HTTP 409) | The machine ID is already enrolled and the agent has no valid old key (state lost, cloned VM image). On the server: `host allow-reenroll <hostname>`; the agent retries hourly, or restart it. Cloned VMs need a unique `/etc/machine-id`. |
| HTTP 429 `rate limited by server` | Normal back-pressure: check-ins allow a burst of 3 then 1 per 20 s, inventories a burst of 3 then 1 per 5 min; invalid enrolls 10/min per client. The agent honours `Retry-After`. If **all** agents are limited, the server sees one client address: behind a reverse proxy set `trusted_proxies` so it reads `X-Forwarded-For`. |
| HTTP 413 | Facts above 1 MiB or an inventory above 64 MiB decompressed. Exclude paths (`exclude_paths`) or shrink what is scanned. |
| HTTP 415 on inventory | No target was a CycloneDX document (an old or modified agent). |
| Host in the UI but no findings | No inventory uploaded yet (first scan takes minutes; `journalctl -u panoptes-agent` shows `inventory uploaded`), the SBOM was skipped (see `pipeline_error` alerts and the server log), or the Grype DB is not loaded yet (`no local grype db yet` in the log). |
| Agent TLS error, `x509`, or the log shows a presented hash after a handshake failure | Certificate not trusted: use `--ca-file`, or the pin no longer matches (`server_cert_sha256`): get the new one with `panoptes-agent -print-server-pin` and compare it out of band. |
| Sender cannot reach `/run/panoptes/collector.sock` (permission denied, no such file) | The collector is not running (`systemctl status panoptes-collector`), the user `panoptes` is missing, or `collector_user` / the socket group is wrong. Expected: directory `root:panoptes 0750`, socket `root:panoptes 0660`. Start order: the collector first (the agent unit requires it). |
| Fact `agent.skipped` lists entries such as `nginx: /etc/nginx/conf.d writable by gid 33` | The collector refuses to run `nginx -T`, `php -i`, `sshd -T`, `apachectl` or `sudo -V` when their config tree or a parent directory is not root-owned and not group- or world-writable. Fix the permissions; rules needing those facts stay `conditions_unknown` until then. |
| Fact `agent.collector_error` | The collector answered with an error (`busy`, request too large, a failing collector); the check-in carries the previously known facts. Check `journalctl -u panoptes-collector`. |
| Fact `agent.inventory_error` | The last scan failed or timed out. Raise `host_scan_timeout` / `image_scan_timeout`, add `exclude_paths`; after failures the next try is delayed (up to 6 h). |
| Local agent (`local_agent`): `local agent stopped; restarting` with a host-info error, or `collector socket not usable, falling back` in the server log; collector log `rejecting connection from unauthorised uid` (`journalctl -u panoptes-collector`) | Collector permission denied or uid rejected. The collector accepts only root and `collector_user` (`panoptes`), checked with `SO_PEERCRED`. A systemd `DynamicUser` server (the shipped default) is rejected, and `SupplementaryGroups=panoptes` alone does not help. Run the server as the static user `panoptes` (see [installation](installation.md#agentless-mode)), then restart it. With `source: auto` the local agent uses `inprocess` until then; the startup log names the source it chose. Also check `systemctl status panoptes-collector` and that the socket is `root:panoptes 0660`. |
| Local agent: `local agent NOT started: a host with this machine's id already exists ...` (ERROR) | A standalone `panoptes-agent` (or an earlier enrollment) already owns this machine, and the local agent does not take it over. Either run `panoptes-server host delete <hostname>` (this also deletes its findings), stop and uninstall the standalone agent, and restart the server; or set `local_agent.enabled: false`. After deleting the local host while the server runs, restart the server: the local agent only notices on its next start. |
| Local agent: `local agent stopped; restarting` with a `retry_in` value, `panic recovered in local agent`, or `local agent did not stop in time` at shutdown | The local agent crashed or failed (for example the collector is down, or the inventory failed). It restarts with backoff (5 s, doubling, max 5 min) and never stops the server. Read the `err` field. With `source: collector`, check `journalctl -u panoptes-collector`. The host raises `agent_silent` if the local agent keeps failing. A `local agent did not stop in time` WARN at shutdown means the local agent was still running 30 s after shutdown began; the server exits anyway. |
| Local agent: server fails to start with `local_agent.*` errors (`source ... must be collector, inprocess or auto`, `collector_socket must be an absolute path`, `checkin_interval must be at least 1m`, `labels: invalid label`, `labels: too many labels (max 32)`) | The `local_agent` section is validated even when `enabled: false`. Fix the value in `server.yaml` or `PANOPTES_LOCAL_AGENT_*` ([configuration](configuration.md#local-agent-agentless-mode)). |
| Local agent: `local_agent.labels changed` in the log, and the host gets a new key | Expected: labels are authoritative and changing them rotates the local agent key at the next server start. Nothing else needs doing. |
| `FEED STALE` alert, `grype db update failed; keeping previous db` | The server cannot download the DB (egress, proxy, DNS), or `feeds.update` is false. Check connectivity from the server; see [air-gapped](#air-gapped-and-feed-updates). |
| No Matrix messages | Look for `matrix notifier enabled` in the log; check the dashboard banner and the status (401/403 token or bot not in the room, 404 wrong room ID). Remember that `affected_not_exploitable` is silent, `CHECK` is delayed 2 h when an LLM is on, and already-sent alerts are not repeated. See [notifications.md](notifications.md#delivery-problems). |
| Web login fails or is slow | After several wrong passwords attempts for a name are delayed (never locked out), and an address with many failures is blocked for a few minutes. Reset a password with `user set-password`. |
| Server will not start: `initial admin password must be at least 12 characters` | Fix `PANOPTES_ADMIN_PASSWORD` / the file named by `PANOPTES_ADMIN_PASSWORD_FILE`. |
| Server will not start: `parse ...: field ... not found` | An unknown or misspelled key in `server.yaml` (the server file is strict). |
| `invalid rule skipped` in the log | A rule failed validation; the message names the rule and the problem ([rules.md](rules.md#testing-a-rule-locally)). |

## Re-enrolling a host

A host keeps working with its agent key. Re-enrolling is needed when it lost the key (wiped
`state_dir`, reinstalled OS, cloned machine) or the server lost its record.

An enrolled host cannot be re-enrolled by anyone holding only an enrollment token: the server answers
`409` unless the request carries the current agent key, or an administrator allowed it.

1. On the server allow one re-enrollment (default 1 h, maximum 168 h):

   ```sh
   panoptes-server host allow-reenroll web-01 -ttl 2h
   panoptes-server host list            # REENROLL column shows "allowed until ..."
   ```

2. On the host put a **fresh** enrollment token into `/etc/panoptes/agent.yaml`
   (`panoptes-server token create web-01-again -max-hosts 1 -expires 2h`), then
   `systemctl restart panoptes-agent`.
3. The agent enrolls, receives a new key (the old one stops working), and the permission is used up.
   The host record is kept: its labels (or the new token's labels, if it has any), findings and
   history stay. After the first check-in the token is removed from the file again.

If you do not need the history, `host delete <host>` followed by a normal enrollment is simpler.
