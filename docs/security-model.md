# Security model

What Panoptes defends against, how, and what you must do yourself. The agent runs as root on every
monitored host, so the design assumes the network, the server and the LLM can all be hostile. This
page summarises the threat model and the mitigations, gives an operator hardening checklist, and
lists known limitations. To report a vulnerability, see [SECURITY.md](../SECURITY.md).

Contents: [Assets and trust](#assets-and-trust) - [Threats and mitigations](#threats-and-mitigations) -
[Operator hardening checklist](#operator-hardening-checklist) - [Known limitations](#known-limitations)

## Assets and trust

| Asset | Why it matters |
|---|---|
| Root on monitored hosts | The collector runs as root to read host state. |
| The agent key of each host | Lets someone act as that host towards the server. |
| Enrollment tokens | Let someone register a host. |
| The admin session and password | Approve rules, create tokens, edit routes. |
| Matrix token, LLM key | Reach external services as you. |
| Host facts and inventories | Reveal what is installed and how it is configured. |

Trust rules: the agent trusts nothing from the server beyond a narrow, validated request format;
the server trusts nothing from agents beyond size-limited, schema-checked data; nobody trusts the LLM
or advisory text. The architecture is in [architecture.md](architecture.md).

## Threats and mitigations

| Threat | Mitigation |
|---|---|
| A compromised or malicious **server** tries to run code on hosts | There is no remote command channel. Every command the agent runs is a hard-coded argv, with no shell, a 10 s timeout and capped output. The server can only request `file.match` facts, and those are filtered (name pattern, absolute path, at most 20) and re-checked by the collector's own policy. `next_checkin_seconds` is clamped to 60 s - 1 h; `want_inventory` is honoured at most once per 10 minutes. |
| A server or network attacker impersonates the **server** | TLS 1.2+ with chain and host name always verified (`InsecureSkipVerify` is never set). Optional `ca_file` makes your CA the only trust root, `server_cert_sha256` pins the leaf key in addition to chain validation, optional mTLS client certificate. Redirects are never followed. `http://` needs `allow_insecure_http` and logs a WARN. |
| A bug in a **parser** of untrusted local data (configs, package databases, images) | Privilege separation: the root collector has no network (`PrivateNetwork=yes`, `IPAddressDeny=any`, AF_UNIX only); the networked sender is unprivileged and never parses those files. The collector is also resource-limited (CPU, memory, I/O, scan timeouts, a limit on concurrent scans). |
| Local users plant files so a **root helper** runs attacker content (`nginx -T`, `sshd -T`, `php -i` read config trees) | Before running those tools the collector requires the config trees and every ancestor directory to be root-owned and not group- or world-writable; helper binaries must also have a trusted path. Otherwise the tool is skipped and reported as `agent.skipped`. |
| **Secret leakage** through `file.match` | Allowed roots only, denylist, strict server-side validation of patterns and paths, world-readable regular files only, symlink-safe open, masking of secret values before the pattern is applied, per-check-in budgets. Only reviewed rules' requests are ever sent to agents. See [rules.md](rules.md#filematch-policy). |
| **Credential theft** from the server database | Enrollment tokens, agent keys and session tokens are stored only as SHA-256 hashes; passwords as bcrypt. The database is mode 0600 and the server runs with `umask 077`. |
| A stolen **enrollment token** | Tokens can expire, have a host cap and carry authoritative labels. A token cannot take over an enrolled host: re-enrollment of an existing machine ID needs the host's current key or an administrator's `host allow-reenroll` (time-limited, single use). The agent blanks the token in its config after the first check-in. |
| **Label spoofing** to steer alerts | Labels of a token-enrolled host are authoritative on the server; labels sent by the agent are ignored in that case. |
| **Flooding** the server | Body size limits (1 MiB enroll, 64 MiB inventory), per-host token buckets for check-in and inventory (plus a per-host attempt bucket charged before an inventory body is read, one decode in flight per host and a server-wide bound on concurrent decodes), limits per client address (invalid enrollments, failed authentication, invalid uploads), per-host caps on findings and matcher time, bounded SBOMs (CycloneDX only, at most 50 000 components), agent-supplied hostname, version and OS fields length-capped and stripped of control/format/bidi characters (OS id and version_id also restricted to `[a-z0-9._-]`, else dropped), bounded internal maps. |
| **Spoofed client addresses** (`X-Forwarded-For`) | The header is honoured only when the TCP peer is in `trusted_proxies`; the right-most untrusted entry is used. Broad entries trigger a WARN. |
| **Admin UI** attack | Separate listener, loopback by default, never serves the agent API; the agent listener serves nothing but `/api/v1/*` and `/healthz`. Sessions have a 1 h idle and 12 h absolute lifetime, `HttpOnly` and `SameSite=Lax` cookies (`Secure` with an https `public_url`), CSRF tokens, login delays per user name and blocks per address (a correct password is never locked out), a re-authentication (current password) for approving or rejecting rules, editing rules, creating tokens, changing routes and managing users, and an audit log. |
| **Malicious LLM output** or advisory text | The LLM only drafts; a draft is validated, inert (its file requests are not sent, it cannot lower a verdict, it only yields `exploitable` if grounded in host facts) until a human approves with password re-entry on a versioned form. Untrusted inputs are normalised, de-tagged and delimited. See [llm.md](llm.md). |
| **Injection into Matrix messages** | Untrusted fields are length-capped and stripped of control characters, `@` gets a zero-width space, empty `m.mentions`, bodies capped at 8 KiB; draft text is not shown in alerts. |
| **Tampered releases** | Releases are made only by the release workflow after tests pass, in the `release` environment (reviewer approval), only for tags on `main`. Keyless cosign signature with an exact certificate identity (workflow path and tag), SPDX SBOMs, GitHub build provenance. `install.sh` verifies the signature and refuses downgrades. Actions and base images are pinned to digests. |
| Data stolen from **backups or logs** | Evaluation reasons never contain `file.match` values (only match counts); the audit log records actors and client addresses, not passwords. Protect backups like the database. |

## Operator hardening checklist

Do these in a real deployment.

**Transport**

- [ ] Terminate TLS for the agent API: native `tls_cert`/`tls_key` or a reverse proxy
  ([installation.md](installation.md#tls)). Never expose `:8080` over plain HTTP.
- [ ] Give agents the exact trust they need: `--ca-file` for a private CA, and **pin the server key**
  (`--server-pin`, from `panoptes-agent -print-server-pin`, compared out of band); list the next key before
  rotating certificates. Consider mTLS (`client_cert`/`client_key`).
- [ ] Keep the admin listener on loopback or a VPN (`admin_listen: 127.0.0.1:8081`), reached by SSH
  tunnel; if you proxy it, restrict by source network, use TLS and set `public_url` to the https URL.
  Do not enable the single-port legacy mode.
- [ ] Set `trusted_proxies` to your proxy's address only (and nothing broader than needed).

**Enrollment**

- [ ] Use **short-lived, per-group tokens** with labels and `max_hosts`:
  `token create web-prod -labels prod,web -max-hosts 20 -expires 72h`. Revoke or let them expire when
  the rollout is done. Do not bake a token into images.
- [ ] Pass tokens with `--token-file` or the environment, not on a command line.
- [ ] Review `host list` regularly; `host delete` hosts you retire.

**Accounts and secrets**

- [ ] Use a strong admin password (12+ characters is enforced), supplied via
  `PANOPTES_ADMIN_PASSWORD_FILE`; remove the variable after first start. Create one account per
  person ([operations.md](operations.md#cli-reference)).
- [ ] Keep `server.env` at mode 0600 and out of version control.
- [ ] Give the LLM key a **spend limit** at the provider and keep `llm.daily_limit` low; use a
  dedicated key.
- [ ] Use a dedicated Matrix bot account and a token you can revoke. Alerts contain host names and
  package versions: keep the rooms private. Panoptes does not do Matrix end-to-end encryption, so use
  unencrypted rooms and a homeserver you trust ([notifications.md](notifications.md#matrix-setup)).

**Operations**

- [ ] Review every LLM draft before approving; read the "Before you approve" file-read list.
- [ ] Back up `panoptes.db` and the configuration ([operations.md](operations.md#backup-and-restore)).
- [ ] Verify what you install ([installation.md](installation.md#verifying-releases)); pin
  image versions, and use `--min-version` in automation.
- [ ] Alert on silence: keep `alerts.agent_silent_after` and `alerts.feed_stale_after` enabled and
  route `alerts.ops_rooms` to a room somebody watches.
- [ ] Limit who can run commands on the server: `panoptes-server` CLI commands act as the service
  user on the database.

**If you maintain a fork or run the release workflow (GitHub repository settings)**

- [ ] Environment `release`: add required reviewers, and restrict deployment to protected tags (`v*`).
- [ ] Tag protection (or rulesets) for `v*`, and branch protection on `main` with required CI.
- [ ] Require reviews for workflow changes; keep Dependabot enabled.
- [ ] Turn on private vulnerability reporting (used by [SECURITY.md](../SECURITY.md)).

## Known limitations

- **No RBAC and no 2FA.** Every web user is an administrator; authentication is a password with
  rate-limiting and re-authentication for sensitive actions. Put the admin UI behind a VPN or an
  authenticating proxy.
- **The systemd units need verification on your hosts.** Their hardening (`ProtectSystem=strict`,
  `PrivateNetwork`, the system-call filter, and child tools such as `nginx -T`, `php -i`, `sshd -T`
  inheriting those limits) has not been verified on a real host by the project's tests, and the unit
  comments say so. Check `panoptes-agent -print-facts` under the unit's properties, and watch `agent.collector_error`
  and `agent.skipped`. The unit comments list the known risk: `nginx -T` may fail on a read-only file
  system.
- **Rules are only as good as their author.** A wrong `exploitable_if` produces false negatives
  (`affected_not_exploitable`). Missing facts and missing rules fail towards `conditions_unknown`,
  not towards "safe", and drafts cannot lower verdicts, but a reviewed rule can.
- **One known dependency advisory.** `govulncheck` reports GO-2026-6905, which has no fixed upstream
  release yet; it is tracked in [`.govulncheck-allow`](../.govulncheck-allow) until one exists.
- **Matrix, LLM and OSV are external services.** Matrix alerts are not end-to-end encrypted; LLM
  prompts include package names and versions from your hosts.
- **Agents run as root.** The collector is hardened and isolated, but anything that runs as root on
  every host is a high-value target: treat the server and the release pipeline accordingly.
- **Single server, SQLite.** No clustering or high availability; back up regularly.
- **The built-in local agent (agentless mode, off by default).** With `source: collector` the server
  process, running as the static user `panoptes`, can request the host's facts and inventory through the
  collector socket. The root collector still has no network, and the server stays unprivileged. With
  `source: inprocess` (or `auto` when the socket refuses the server) the server process itself reads
  untrusted local files with its own privileges, so the server host needs the same care as any monitored
  host. The local agent does not add a remote command channel: all API validation, limits and
  authentication apply to it as to any agent.
