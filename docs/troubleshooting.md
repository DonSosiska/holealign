# Troubleshooting

Symptom, cause, fix. Messages are quoted as the code logs them. Logs: `journalctl -u holealign-server`
(or `docker compose logs holealign-server`) on the server, `journalctl -u holealign-agent -u
holealign-collector` on a host; see [operations.md](operations.md#monitoring-and-logs).

Contents: [Server will not start](#server-will-not-start) - [Enrollment and agents](#enrollment-and-agents) -
[HTTP status codes](#http-status-codes) - [TLS](#tls) - [Collector and facts](#collector-and-facts) -
[No findings or wrong verdicts](#no-findings-or-wrong-verdicts) - [Feeds](#feeds) -
[Matrix](#matrix) - [Web login](#web-login) - [LLM](#llm) -
[Local agent (agentless mode)](#local-agent-agentless-mode)

## Server will not start

| Symptom | Cause and fix |
|---|---|
| `initial admin password must be at least 12 characters` | Fix `HOLEALIGN_ADMIN_PASSWORD` or the file named by `HOLEALIGN_ADMIN_PASSWORD_FILE`. |
| `parse ...: field ... not found` | An unknown or misspelled key in `server.yaml`. The server file is strict; compare with [configuration.md](configuration.md). |
| `read config: ... no such file` | `-config` or `HOLEALIGN_CONFIG` names a file that does not exist. With the Compose file, do not set `HOLEALIGN_CONFIG` without mounting the file. |
| `... must match ^HOLEALIGN_[A-Z0-9_]+$` or `must name different environment variables` | `matrix.access_token_env`, `llm.api_key_env` and `admin.initial_password_env` must be valid and pairwise different. |
| `tls_cert and tls_key must be set together` (or the admin pair) | Set both files of a pair or neither. |
| Certificate cannot be read (permission denied) | The packaged unit runs as a dynamic user. Use `LoadCredential=` ([installation.md](installation.md#native-tls)). |
| `rules.feed.enabled requires at least one entry in rules.feed.trusted_keys` | Add the public key ([configuration.md](configuration.md#rules-feed)). |
| `local_agent.*` errors | The section is validated even when `enabled: false`; see [below](#local-agent-agentless-mode). |
| Server runs but starts with no web user and logs a WARN | No admin password was configured. Run `holealign-server user set-password admin`. |
| `insecure configuration` warnings | Not errors. `http://` URLs to non-loopback hosts, broad `trusted_proxies`, a non-loopback listener without TLS: fix as the message says. |
| Agents cannot reach the server | `listen` binds `:8080` but a firewall blocks it, or you published only the admin port. `curl -k https://host/healthz` should print `ok`. |

## Enrollment and agents

| Symptom | Cause and fix |
|---|---|
| Agent log `unauthorized and cannot re-enroll; retrying later` (401) | The server does not know the agent key: host deleted, database restored from an older backup, or the key was replaced. `enroll_token` was blanked after the first check-in, so put a **fresh** token in `/etc/holealign/agent.yaml` and restart `holealign-agent`. If the host still exists on the server, run `host allow-reenroll` first ([operations.md](operations.md#re-enrolling-a-host)). The agent retries hourly. |
| 401 at enroll | Token unknown, revoked or expired: `holealign-server token list`, create a new one. |
| 403 at enroll (`enrollment token exhausted`) | The token's `-max-hosts` is used up: create another token. |
| `server refused enrollment: host already exists` (409) | The machine ID is already enrolled and the agent has no valid old key (state lost, reinstalled, cloned VM). On the server: `host allow-reenroll <hostname>`. The agent retries hourly or on restart. Cloned VMs need a unique `/etc/machine-id`. |
| `credentials unreadable, enrolling again` | The agent's state file is damaged; it enrolls again. That needs a token in the config and, if the host exists, `allow-reenroll`. |
| Host never appears in the UI | Check the agent log for the reason; check `server_url` (https, reachable from the host, not a trailing path), the token, and that the server's agent port is published. |
| Host appears with the wrong labels | Labels on the token are authoritative and override `labels` in `agent.yaml`. Create a token with the labels you want and re-enroll, or fix the token. |
| Host shown as stale / `AGENT SILENT` | No check-in for `alerts.agent_silent_after` (30 m). Check `systemctl status holealign-agent holealign-collector`, the network path, and `journalctl`. A stopped agent is the usual cause. |
| `config: server_url must use https://` | Use an `https://` URL, or set `allow_insecure_http: true` for tests (the agent key then travels in cleartext). |
| A setting has no effect | The agent file ignores unknown keys silently: a typo means the default applies. Compare with [configuration.md](configuration.md#agent-configuration). |

## HTTP status codes

| Code | Meaning and fix |
|---|---|
| 429 `rate limited by server` | Back-pressure. Check-ins: burst 3 then 1 per 20 s. Inventories: burst 3 then 1 per 5 min. Invalid enrollments 10/min, failed authentications 30/min per client. The agent honours `Retry-After`. If **all** agents are limited, the server sees one client address: behind a reverse proxy set `trusted_proxies` so it reads `X-Forwarded-For`. |
| 429 `inventory upload attempts too frequent` | The per-host bucket `limits.inventory_attempts_per_minute` (10) and `limits.inventory_attempt_burst` (6) is empty. Something re-uploads in a loop. Check for a cloned `state_dir` shared by hosts. |
| 429 `an inventory upload from this host is already being processed` | Only one inventory per host is decoded at a time; retry after `Retry-After` (5 s). |
| 503 `server busy decoding inventories; retry later` | All `limits.inventory_concurrent_decodes` (4) slots are in use by other hosts. The agent retries after `Retry-After`. Raise the limit if the server has memory to spare. |
| 413 | Facts above 1 MiB or an inventory above 64 MiB decompressed. Add `exclude_paths`, or shrink what is scanned. |
| 415 on inventory | No target was a CycloneDX document (an old or modified agent). |
| 400 `invalid inventory` / `invalid gzip body` | A proxy modified the body (for example decompressed it) or the agent is modified. Allow `client_max_body_size 64m` and pass the body unchanged. |

## TLS

| Symptom | Cause and fix |
|---|---|
| Agent log `x509: certificate signed by unknown authority` | The server certificate is not trusted: use a public CA, or give the agent `ca_file` (`install.sh --ca-file`). With `ca_file` set only that file is trusted, so include the whole chain's root. |
| `server certificate pin mismatch: presented SPKI sha256 ... matches none of the N configured server_cert_sha256 pins` | The server certificate's key changed (renewal with a new key). The log prints the presented hash. Verify it out of band (`holealign-agent -print-server-pin`, which validates the chain first), then add it to `server_cert_sha256`. List old and new pins before rotating. |
| `config: ca_file ... contains no PEM certificate` | The file is not a PEM bundle. |
| `config: client_cert and client_key must be set together` | Set both. |
| TLS errors only through a proxy | The proxy must forward HTTPS correctly; set `proxy_read_timeout` for inventory uploads (300 s in the example) and `client_max_body_size 64m`. Agents never follow redirects: a proxy redirecting `http` to `https` breaks an `http://` `server_url`. |

## Collector and facts

| Symptom | Cause and fix |
|---|---|
| Sender cannot reach `/run/holealign/collector.sock` (permission denied, no such file) | The collector is not running (`systemctl status holealign-collector`), the user `holealign` is missing, or `collector_user` or the socket group is wrong. Expected: directory `root:holealign 0750`, socket `root:holealign 0660`. The agent unit requires the collector. |
| Collector log `rejecting connection from unauthorised uid` | A process that is neither root nor `collector_user` connected. For the sender, check the unit's `User=`. For a server local agent, see [below](#local-agent-agentless-mode). |
| `collector group not found; socket stays root-only` | The group `holealign` does not exist. Create it (the installer and packages do). |
| Facts missing, so findings are `conditions_unknown` | A rule needs a fact the host did not report. Run `holealign-agent -print-facts` on the host: the fact is absent when the tool is not installed, not applicable, failed, or was skipped. Open the finding: the reason lists the missing facts. |
| Fact `agent.skipped` lists `nginx: /etc/nginx/conf.d writable by gid 33` | The collector refuses to run `nginx -T`, `php -i`, `sshd -T`, `apachectl` or `sudo -V` when their config tree or a parent directory is not root-owned, or is group- or world-writable. Fix the permissions; the rules that need those facts stay `conditions_unknown` until then. |
| Fact `agent.collector_error` | The collector answered with an error (`busy`, request too large, a failing collector). The check-in carries the previously known facts. Read `journalctl -u holealign-collector`. |
| Fact `agent.inventory_error` | The last scan failed or timed out. Raise `host_scan_timeout` or `image_scan_timeout`, add `exclude_paths`. After failures the next try is delayed (up to 6 h). |
| `collector rejected the stored fact requests; dropping them and retrying once` | The server asked for a `file.match` fact the collector refuses. The request is dropped; look at the rule's `fact_requests` ([rules.md](rules.md#filematch-policy)). |

## No findings or wrong verdicts

| Symptom | Cause and fix |
|---|---|
| Host in the UI, no findings | No inventory yet (the first scan takes minutes; the agent log shows `inventory uploaded`), the SBOM was skipped (look for `pipeline_error` alerts and the server log), or the Grype DB is not loaded (next row). |
| Server log `no local grype db yet` | The first download of the Grype DB (about 100 MB) has not finished or failed. Matching waits for it; hosts are matched once it loads. Check egress to the DB host, or install a DB by hand ([air-gapped](operations.md#air-gapped-and-feed-updates)). `feeds.update: false` without a DB on disk keeps this state forever. |
| `grype db is stale; vulnerability data may be outdated` | The DB on disk is older than 5 days at start. Check connectivity; see [Feeds](#feeds). |
| Everything is `conditions_unknown` | Expected for CVEs without a rule: the verdict means "cannot tell", not "safe". Triage with the attention tier ([user-guide.md](user-guide.md#triage-tiers)); cover important CVEs with a rule ([rules.md](rules.md)). |
| A finding I expected to be `affected_not_exploitable` is `exploitable` | Read the verdict reason (it names the facts) and compare with `holealign-agent -print-facts`. Rules can be overridden locally ([user-guide.md](user-guide.md#rules)). |
| `invalid rule skipped` in the log | A rule failed validation; the message names the rule and the problem ([rules.md](rules.md#testing-a-rule-locally)). |
| `pipeline_error` alert or banner | Matching failed 3 runs in a row, a target was skipped (invalid or poisoned SBOM), or a host limit was hit (`findings_per_host`, `match_seconds_per_host_hour`). The message names the host and cause; see [operations.md](operations.md#retention-and-limits). |

## Feeds

| Symptom | Cause and fix |
|---|---|
| `FEED STALE` alert; `grype db update failed; keeping previous db` | The server cannot download the DB (egress, proxy, DNS), or `feeds.update` is false. Check connectivity from the server. The previous DB keeps serving. Air-gapped: raise or disable `alerts.feed_stale_after`. |
| Rules feed: dashboard banner "Rules feed stale" or `FEED STALE` with "rules feed" | No successful poll for `rules.feed.stale_after` (7 d) or the last 3 polls failed. Read the "Last error" on the dashboard. |
| `signature key "..." is not a trusted key` | The bundle was signed with a key that is not in `rules.feed.trusted_keys`. Compare `key_id` with the one you trust (public feed: `75eef42e119d4dda`). |
| `signature does not match the bundle` | The bundle or its signature was corrupted or tampered with. The installed bundle is kept. Retry later; if it persists, do not add keys to "fix" it. |
| `no trusted keys configured` / `rules.feed.url is not set` | Configuration, see [configuration.md](configuration.md#rules-feed). |
| `bundle needs holealign-server X or newer` / `uses fact ... that this server does not know; upgrade holealign-server` | The feed is newer than this server. Upgrade the server. The installed bundle stays in use. |
| `unsupported bundle format N` | Same: upgrade the server. |
| `ignoring a pointer to an older bundle (rollback attempt or publisher mistake)` | `latest.json` points to a lower `seq` than installed. Ignored on purpose. |
| `latest.json: bundle url host ... differs from the pointer's` | The pointer must name a bundle on the same host and scheme. Publisher problem. |
| `HTTP 404` or `redirects are not followed` | Wrong `rules.feed.url`, or the URL redirects; use the final URL. |

Details of the feed and its CLI: [rules-feed.md](rules-feed.md).

## Matrix

| Symptom | Cause and fix |
|---|---|
| No alerts at all | Look for `matrix channel enabled`, `slack channel enabled` or `telegram channel enabled` in the log (`... channel disabled` names the reason). Without `matrix.homeserver` Matrix is off; Slack and Telegram need `slack.token_env` or `telegram.bot_token_env` and the variable set. Check the dashboard banner "Alert delivery problems" for the status. |
| Status 401 / 403 | Token invalid, or the bot has not joined the room or cannot send. |
| Status 404 | Wrong room ID (use `!id:server`, not an alias) or the room was deleted. |
| Status 429 | Homeserver rate limit; retried with its `retry_after`. |
| Status 0 | The homeserver is unreachable from the server. |
| A finding was not announced | `affected_not_exploitable` is silent. `CHECK` (unknown and KEV or Critical) is delayed 2 h when an LLM is configured. Alerts already sent are not repeated (dedup). No label route and no `notify.default`: it is reported as a delivery problem. |
| Alerts go to the wrong room | A host goes to the union of the rooms of **all** its labels; see [notifications.md](notifications.md#routing). |

More: [notifications.md](notifications.md#delivery-problems).

## Web login

| Symptom | Cause and fix |
|---|---|
| "Invalid username or password." | Wrong credentials. Reset with `holealign-server user set-password <user>`. |
| "Too many failed attempts. Try again in a few minutes." (429) | Limits: 5 failures per (address, user) in 5 minutes, 20 per address in 5 minutes. A correct password still works for a user whose name is merely slowed (the per-name delay grows to 5 s, never a lock-out), but the address limit blocks until the window passes. |
| Everyone is blocked together | Behind a reverse proxy without `trusted_proxies`, all clients share the proxy's address and one login limit. The log shows a one-time WARN `X-Forwarded-For received from a peer that is not in trusted_proxies`. Set `trusted_proxies` to the proxy's address. |
| Why a known user still gets in while others are blocked | A browser that logged in before holds a known-device cookie (`holealign_device`, 30 days, up to 10 devices per user). Such a browser skips the per-address limits; its password is still checked. The device list is kept in server memory, so a server restart forgets it and the next login from that browser is rate limited like a new one. |
| Login works, then you are logged out | Sessions end after 1 hour idle or 12 hours in total. |
| Login loops back to the login page on `https` | `public_url` is `https` so the cookie is `Secure`: open the UI over `https` (or via the tunnel with the right URL), not `http`. |
| "Your current password is required and was missing or incorrect. Nothing was changed." | Sensitive actions ask for your password. Five failures in an hour log the session out. |

## LLM

| Symptom | Cause and fix |
|---|---|
| `llm: daily limit reached, dropping drafts` | `llm.daily_limit` (default 50 calls per UTC day) is used up; drafting resumes the next UTC day. Raise it, knowing each call costs money with a hosted provider. A value of 0 or less means 50. |
| No drafts ever appear | `llm.provider` is `none`, or the API key variable is empty. Look for `LLM drafter enabled` in the log. Settings shows the provider read-only. |
| `llm.base_url` WARN about cleartext | A plain `http://` URL to a non-loopback host. Use `https`. |

Details: [llm.md](llm.md).

## Local agent (agentless mode)

| Symptom | Cause and fix |
|---|---|
| `collector socket not usable, falling back`; collector log `rejecting connection from unauthorised uid`; permission denied | The collector accepts only root and `collector_user` (`holealign`), checked by uid. A systemd `DynamicUser` server (the shipped default) is rejected, and `SupplementaryGroups=holealign` alone does not help. Run the server as the static user `holealign` ([installation.md](installation.md#agentless-mode)), then restart. With `source: auto` the local agent uses `inprocess` meanwhile; the startup log names the source it chose. |
| `local agent NOT started: a host with this machine's id already exists ...` (ERROR) | A standalone agent (or an earlier enrollment) already owns this machine. Run `holealign-server host delete <hostname>` (also deletes its findings), uninstall the standalone agent and restart the server, or set `local_agent.enabled: false`. |
| `local agent stopped; restarting` with `retry_in`, `panic recovered in local agent`, or `local agent did not stop in time` | The local agent failed (for example the collector is down) and restarts with backoff (5 s doubling to 5 min). It never stops the server. Read the `err` field. If it keeps failing, `agent_silent` fires. |
| Server fails to start with `local_agent.*` errors | Fix the value: `source` is `collector`, `inprocess` or `auto`; `collector_socket` absolute; intervals at least 1m; labels match `^[a-z0-9][a-z0-9._-]{0,63}$`, at most 32. |
| `local agent collects inside the server process without root privileges` | `source: inprocess` without root sees fewer facts (`sshd -T`, `nginx -T`, Docker). Use `source: collector`. |
| In Docker, the findings are about the container | `inprocess` in a container scans the container. Mount the host collector socket ([installation.md](installation.md#agentless-mode)). |
| `waiting for the vulnerability DB before the first inventory upload` | Expected on first start while the Grype DB downloads. |
| `local_agent.labels changed` | Expected: the local host gets a new key. |
