# Security model

What Holealign defends against, how, and what you must do yourself. The agent runs as root on every
monitored host, so the design assumes the network, the server and the LLM can all be hostile. This
page summarises the threat model and the mitigations, gives an operator hardening checklist, and
lists known limitations. To report a vulnerability, see [SECURITY.md](../SECURITY.md).

Contents: [Assets and trust](#assets-and-trust) - [Threats and mitigations](#threats-and-mitigations) -
[The rules feed trust chain](#the-rules-feed-trust-chain) -
[Operator hardening checklist](#operator-hardening-checklist) - [Known limitations](#known-limitations)

## Assets and trust

| Asset | Why it matters |
|---|---|
| Root on monitored hosts | The collector runs as root to read host state. |
| The agent key of each host | Lets someone act as that host towards the server. |
| Enrollment tokens | Let someone register a host. |
| The admin session and password | Every web account is a full administrator: approve rules, create tokens and users, edit routes. |
| Matrix token, Slack bot token, Telegram bot token, Discord and Teams webhook URLs, webhook signing keys and headers, SMTP password, LLM key | Reach external services as you (post as your bot or into your channels, send mail from your address, forge signed webhook deliveries, spend your LLM budget). A Discord or Teams webhook URL is itself the credential. |
| The rules repository and its signing key | Whoever can publish a signed rules bundle can change verdicts and request configuration-file reads on every server that trusts the key. |
| Host facts and inventories | Reveal what is installed and how it is configured. |

Trust rules: the agent trusts nothing from the server beyond a narrow, validated request format;
the server trusts nothing from agents beyond size-limited, schema-checked data; nobody trusts the LLM
or advisory text; a server trusts rules from outside only when they are signed by a key the operator
listed ([feed trust chain](#the-rules-feed-trust-chain)). The architecture is in [architecture.md](architecture.md).

## Threats and mitigations

| Threat | Mitigation |
|---|---|
| A compromised or malicious **server** tries to run code on hosts | There is no remote command channel. Every command the agent runs is a hard-coded argv, with no shell, a 10 s timeout and capped output. The server can only request `file.match` facts, and those are filtered (name pattern, absolute path, at most 20) and re-checked by the collector's own policy. `next_checkin_seconds` is clamped to 60 s - 1 h; `want_inventory` is honoured at most once per 10 minutes. |
| A server or network attacker impersonates the **server** | TLS 1.2+ with chain and host name always verified (`InsecureSkipVerify` is never set). Optional `ca_file` makes your CA the only trust root, `server_cert_sha256` pins the leaf key in addition to chain validation, optional mTLS client certificate. Redirects are never followed. `http://` needs `allow_insecure_http` and logs a WARN. |
| A bug in a **parser** of untrusted local data (configs, package databases, images) | Privilege separation: the root collector has no network (`PrivateNetwork=yes`, `IPAddressDeny=any`, AF_UNIX only); the networked sender is unprivileged and never parses those files. The collector is also resource-limited (CPU, memory, I/O, scan timeouts, a limit on concurrent scans, a 2 minute deadline per facts request that is cancelled when the client disconnects, helper commands killed as a whole process group on timeout, `TasksMax=128`). |
| Local users plant files so a **root helper** runs attacker content (`nginx -T`, `sshd -T`, `php -i` read config trees) | Before running those tools the collector requires the config trees and every ancestor directory to be root-owned and not group- or world-writable; helper binaries must also have a trusted path. Symbolic links are followed and the files below a linked directory are checked too. Otherwise the tool is skipped and reported as `agent.skipped`. Config files are `stat`ed and opened with `O_NONBLOCK`, so a FIFO planted in a user-writable place cannot hang the collector. |
| **Secret leakage** through `file.match` | Allowed roots only, denylist, strict server-side validation of patterns and paths, world-readable regular files only, symlink-safe open, masking of secret values before the pattern is applied, per-check-in budgets. Only reviewed rules' requests are ever sent to agents. See [rules.md](rules.md#filematch-policy). |
| **Credential theft** from the server database | Enrollment tokens, agent keys and session tokens are stored only as SHA-256 hashes; passwords as bcrypt. The database is mode 0600 and the server runs with `umask 077`. |
| A stolen **enrollment token** | Tokens can expire, have a host cap and carry authoritative labels. A token cannot take over an enrolled host: re-enrollment of an existing machine ID needs the host's current key or an administrator's `host allow-reenroll` (time-limited, single use). The agent blanks the token in its config after the first check-in. |
| **Label spoofing** to steer alerts | Labels of a token-enrolled host are authoritative on the server; labels sent by the agent are ignored in that case. |
| **Flooding** the server | Body size limits (1 MiB enroll, 64 MiB inventory), per-host token buckets for check-in and inventory (plus a per-host attempt bucket charged before an inventory body is read, one decode in flight per host and a server-wide bound on concurrent decodes), limits per client address (invalid enrollments, failed authentication, invalid uploads), per-host caps on findings and matcher time, bounded SBOMs (CycloneDX only, at most 50 000 components), agent-supplied hostname, version and OS fields length-capped and stripped of control/format/bidi characters (OS id and version_id also restricted to `[a-z0-9._-]`, else dropped), bounded internal maps. |
| **Spoofed client addresses** (`X-Forwarded-For`) | The header is honoured only when the TCP peer is in `trusted_proxies`; the right-most untrusted entry is used. Broad entries trigger a WARN, and so does an `X-Forwarded-For` header arriving on the admin listener from a peer that is not in `trusted_proxies` (logged once; it hints at a proxy that is not configured). |
| **Admin UI** attack | Separate listener, loopback by default, never serves the agent API; the agent listener serves nothing but `/api/v1/*` and `/healthz`. Sessions have a 1 h idle and 12 h absolute lifetime, `HttpOnly` and `SameSite=Lax` cookies (`Secure` with an https `public_url`), CSRF tokens, login delays per user name and blocks per address (a browser holding a known-device cookie for the user bypasses the per-address blocks, so failures from a shared address never lock out the real user), approving a rule shows its expressions (`exploitable_if`, `not_affected_if`) and flags LLM-written text as unverified, a re-authentication (current password) for approving or rejecting rules, editing rules, creating tokens, changing routes and managing users, and an audit log. There are no roles: every account is a full administrator (see [Known limitations](#known-limitations)). |
| **Malicious LLM output** or advisory text | The LLM only drafts; a draft is validated, inert (its file requests are not sent, it cannot lower a verdict, it only yields `exploitable` if grounded in host facts) until a human approves with password re-entry on a versioned form. Untrusted inputs are normalised, de-tagged and delimited. See [llm.md](llm.md). |
| **Injection into chat messages** (Matrix, Slack, Telegram, Discord, Teams, email) | Untrusted fields are length-capped and stripped of control characters and `@` gets a zero-width space. Each channel then escapes for its own markup: Matrix HTML-escapes and sends empty `m.mentions` with bodies capped at 8 KiB; Slack escapes `&`, `<`, `>` (so `<!channel>`, `<@U...>`, `<url\|text>` stay inert), guards formatting characters, sets no `link_names` and disables unfurling; Telegram sends HTML restricted to `b`, `code`, `a` with every value escaped, link previews off, at most 3900 visible characters per message so no entity is split; Discord backslash-escapes every markdown character, puts a zero-width space after `@` and `<` (no `@everyone`, `<@id>`, `<@&id>`, `<#id>`), sends `allowed_mentions.parse: []`, suppresses embeds and cuts at 2000 characters on line boundaries; Teams sends an Adaptive Card whose TextBlocks have the markdown subset escaped, no mention entities and at most about 25 KB; email HTML-escapes the HTML part, strips CR, LF and every non-printable character from the subject (no header injection), MIME-encodes it, derives `Message-ID` from characters `[A-Za-z0-9._-]` only and caps each body at 8 KiB; the generic webhook sends structured JSON (fields are data, cleaned of control characters and length-capped, never markup); draft text is not shown in alerts: the evaluation reason of a draft is a fixed string and the notifier replaces any reason starting with `LLM draft` by one. |
| **SSRF or exfiltration through notification destinations** | Destinations of Discord, Teams and webhook are **names** that refer to entries in `server.yaml`; the URLs and secrets are in the config file and the environment, never in the web UI or the stored routes (a destination containing a URL is rejected). Discord URLs must be `https` on `discord.com` or `discordapp.com` with the `/api/webhooks/<id>/<token>` path; Teams URLs must be `https` on a Microsoft workflow host (`.logic.azure.com`, `.powerplatform.com`, `.environment.api.powerplatform.com`) unless `allow_any_host` is set (WARN); the generic webhook may point anywhere because it is set by the operator in the config file (https unless `allow_http`, WARN): what it may reach is the operator's decision. None of the three follows redirects, response bodies are capped at 64 KiB, and URLs and tokens are removed from errors and logs. Email destinations are one strict mailbox, and `email.allowed_domains` restricts which recipients an admin can route to, so the web UI cannot turn Holealign into a mail relay to arbitrary addresses. |
| **Eavesdropping or tampering with alert delivery** (email, webhook) | Email requires TLS (STARTTLS that must be offered, or implicit TLS), verifies the server certificate (TLS 1.2+) and sends the password only afterwards; there is no downgrade to plain text. Generic webhook deliveries are signed with HMAC-SHA256 over `<timestamp>.<body>` (`X-Holealign-Signature`) with a per-endpoint key; receivers verify in constant time and reject timestamps older than 5 minutes ([notifications.md](notifications.md#generic-signed-webhook)); `X-Holealign-Event-Id` is stable across retries for idempotency. |
| **Malicious or tampered rules** (a hijacked feed host, a man in the middle, a poisoned bundle, a replayed old bundle) | Bundles are verified with ed25519 against `rules.feed.trusted_keys` before anything is read; the pointer cannot redirect to another host; a lower or equal `seq` is never installed and `index.json` must carry the pointer's `seq`; extraction is strict and bounded; every rule must validate and pass its own tests; the accepted bundle is re-verified at every start. Details: [the feed trust chain](#the-rules-feed-trust-chain). |
| **Tampered releases** | Releases are made only by the release workflow after tests pass, in the `release` environment (reviewer approval), only for tags on `main`. Keyless cosign signature on `checksums.txt` with an exact certificate identity (workflow path and tag), SPDX SBOMs, GitHub build provenance. `install.sh` verifies the signature and refuses downgrades. Actions and base images are pinned to digests. The `.deb` and `.rpm` packages are **not** apt- or rpm-signed (see limitations): verify their checksums against the signed `checksums.txt`. |
| Data stolen from **backups or logs** | Evaluation reasons never contain `file.match` values (only match counts); the audit log records actors and client addresses, not passwords. Protect backups like the database. |

## The rules feed trust chain

The optional signed rules feed ([rules-feed.md](rules-feed.md)) is the only way rules reach a server from
outside. A bad rule is dangerous in two ways: it can say "not exploitable" about a real hole (a false
negative), and a `file.match` request makes every agent read configuration lines as root. So the chain is
short and explicit:

1. **The rules repository is the trust root.** [DonSosiska/holealign-rules](https://github.com/DonSosiska/holealign-rules)
   holds the rules and tests. Changes need a reviewed pull request from a code owner; the bot's drafts get
   the same review and are never merged unchecked. A merge is the review.
2. **A protected CI environment signs.** Publishing runs in the `rules-release` environment with a
   required reviewer, only from the tip of `main`; the build tool is pinned to a commit that must be an
   ancestor of holealign `main`; the private signing key is written to a file only for the signer step and
   is also kept offline.
3. **The signature is the gate.** Servers install a bundle only when it is signed by a key in
   `rules.feed.trusted_keys`. The public key lives in the rules repository
   (`keys/rules-public.key`) and is listed in [rules-feed.md](rules-feed.md#the-public-feed).
   Everything else (the pointer, the host, the transport) is untrusted and cross-checked.
4. **The server still validates.** Every rule passes the same validation as a local one (including the
   strict `file.match` policy), must be `reviewed`, and must pass its tests; one failure rejects the bundle.
   The agent re-checks every file request against its own policy and does not rely on the server.
5. **Rollback is refused**, and a removed key takes effect at the next start.

Key rotation overlaps two keys in `trusted_keys` and then retires the old one; a leaked key means removing it
from every server's `trusted_keys` immediately ([rules-feed.md](rules-feed.md#key-rotation)). Running your own
feed makes your repository and key the root instead.

What the chain does not give you: a reviewed, signed rule can still be wrong, and an operator-installed
`trusted_keys` entry is trusted completely. A local rule you save in the web UI overrides a feed rule on that
server, so it is the operator's responsibility.

## Operator hardening checklist

Do these in a real deployment.

**Transport**

- [ ] Terminate TLS for the agent API: native `tls_cert`/`tls_key` or a reverse proxy
  ([installation.md](installation.md#tls)). Never expose `:8080` over plain HTTP.
- [ ] Give agents the exact trust they need: `--ca-file` for a private CA, and **pin the server key**
  (`--server-pin`, from `holealign-agent -print-server-pin`, compared out of band); list the next key before
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
  `HOLEALIGN_ADMIN_PASSWORD_FILE`; remove the variable after first start. Create one account per
  person ([operations.md](operations.md#cli-reference)).
- [ ] Keep `server.env` at mode 0600 and out of version control.
- [ ] Give the LLM key a **spend limit** at the provider and keep `llm.daily_limit` low; use a
  dedicated key.
- [ ] Use a dedicated bot account or app per channel and a token you can revoke: the Matrix bot, a
  Slack app with only `chat:write`, a Telegram bot from @BotFather, one Discord/Teams webhook per channel,
  a mailbox used only for alerts. Each secret has its own environment variable (`HOLEALIGN_MATRIX_TOKEN`,
  `HOLEALIGN_SLACK_TOKEN`, `HOLEALIGN_TELEGRAM_TOKEN`, `HOLEALIGN_DISCORD_<NAME>_URL`,
  `HOLEALIGN_TEAMS_<NAME>_URL`, `HOLEALIGN_WEBHOOK_<NAME>_SECRET`, `HOLEALIGN_SMTP_PASSWORD`); the config
  rejects one variable name used for two secrets. A Discord or Teams webhook URL is a credential: treat it
  like a token and rotate it by deleting the webhook. Alerts contain host names and package versions: keep
  the rooms, channels and groups private. Holealign does not do Matrix end-to-end encryption, so use
  unencrypted rooms and a homeserver you trust ([notifications.md](notifications.md#matrix)).
- [ ] The Slack and Telegram API addresses are constants in the program. The web UI accepts no URL for a
  channel (a route is only `scheme:target`, with the target syntax-checked; Discord, Teams and webhook
  targets are names from `server.yaml`), so a UI edit cannot make the server call an arbitrary host (no
  SSRF surface). In `server.yaml` the Discord and Teams URLs are restricted to the services' hosts; only
  `webhook.endpoints.<name>.url` may point anywhere, and only the person who edits the config file can set it.
- [ ] Set `email.allowed_domains` when admins other than you can edit routes, and give the generic
  webhook a signing key of at least 32 random bytes; verify signatures and the timestamp in the receiver. The Telegram token
  is part of the request URL; the server never logs or returns request URLs.

**Rules feed**

- [ ] Enable the feed only with `trusted_keys` containing exactly the keys you trust (the public feed's key
  from the rules repository, compared with [rules-feed.md](rules-feed.md#the-public-feed), or your own).
  List two keys only while rotating.
- [ ] Watch for the "rules feed" `feed_stale` alert; leave `rules.feed.stale_after` enabled.
- [ ] For an air-gapped server use `holealign-server rules import` and leave `rules.feed.url` empty.

**Operations**

- [ ] Review every LLM draft before approving; read the "Before you approve" file-read list.
- [ ] Back up `holealign.db` and the configuration ([operations.md](operations.md#backup-and-restore)).
- [ ] Verify what you install ([installation.md](installation.md#verifying-releases)); pin
  image versions, and use `--min-version` in automation.
- [ ] Alert on silence: keep `alerts.agent_silent_after` and `alerts.feed_stale_after` enabled and
  route `notify.ops` to a room or channel somebody watches.
- [ ] Limit who can run commands on the server: `holealign-server` CLI commands act as the service
  user on the database.

**If you maintain a fork or run the release workflow (GitHub repository settings)**

- [ ] Environment `release`: add required reviewers, and restrict deployment to protected tags (`v*`).
- [ ] In a rules repository: environment `rules-release` with required reviewers, deployment restricted
  to `main`, the signing key only there (and backed up offline), branch protection on `main` with required
  validation and code-owner review.
- [ ] Tag protection (or rulesets) for `v*`, and branch protection on `main` with required CI.
- [ ] Require reviews for workflow changes; keep Dependabot enabled.
- [ ] Turn on private vulnerability reporting (used by [SECURITY.md](../SECURITY.md)).

## Known limitations

- **There are no roles.** Every account in the web UI is a full administrator: it can approve and edit
  rules, create and revoke enrollment tokens, edit notification routes and create, change or delete users. There
  is no read-only or observer role, no RBAC and no 2FA. Create an account only for someone you trust with
  all of that. Authentication is a password with rate-limiting and re-authentication for sensitive actions.
  Put the admin UI behind a VPN or an authenticating proxy.
- **Apache includes are not scanned.** Before `apachectl -M` the agent verifies the Apache config roots, but
  unlike nginx it does not follow `Include`/`IncludeOptional`/`LoadModule` to locations outside those roots.
  Config that includes files from outside `/etc/apache2`, `/etc/httpd` and the other verified roots is not
  checked. The nginx scan covers `include`, `load_module`, `*_by_lua_file`, `perl_modules`, `perl_require`,
  `js_import` and `js_path`; other nginx directives that load files (for example lua `*_by_lua_block`
  requiring modules from a search path) are not followed.
- **The `.deb` and `.rpm` packages are not apt- or rpm-signed.** Releases are signed through `checksums.txt`
  (cosign), so verify the package checksum against it before installing
  ([installation.md](installation.md#verifying-releases)). Installing with `apt install ./file.deb` or
  `rpm -i` does not check anything by itself.
- **AI-assisted drafts need human review.** A rule drafted by an LLM (on the server, or by the rules
  repository's bot) is validated and inert, never lowers a verdict, and needs a grounded condition to report
  `exploitable`. That does not make it correct: it can be wrong or too narrow. Read every draft against the
  advisory before approving it.
- **Rules are only as good as their author.** A wrong `exploitable_if` in a *reviewed* rule produces false
  negatives (`affected_not_exploitable`). Missing facts and missing rules fail towards `conditions_unknown`,
  not towards "safe", and drafts cannot lower verdicts, but a reviewed rule can. The feed moves that trust to
  the rules repository's maintainers.
- **The systemd units need verification on your hosts.** Their hardening (`ProtectSystem=strict`,
  `PrivateNetwork`, the system-call filter, and child tools such as `nginx -T`, `php -i`, `sshd -T` inheriting
  those limits) has not been verified on a real host by the project's tests, and the unit comments say so.
  Check `holealign-agent -print-facts` under the unit's properties, and watch `agent.collector_error` and
  `agent.skipped`. The unit comments list the known risk: `nginx -T` may fail on a read-only file system.
- **One known dependency advisory.** `govulncheck` reports GO-2026-6905 (the `ar` parser used by Syft's deb
  support) with no fixed upstream release yet; it is accepted per binary in
  [`.govulncheck-allow`](../.govulncheck-allow) until one exists.
- **Matrix, Slack, Telegram, Discord, Teams, email, the generic webhook, LLM and OSV are external services.** Matrix alerts are not end-to-end encrypted, and Slack, Telegram, Discord and Microsoft see the alert text in clear (host names, package versions, vulnerability IDs), as does every mail server on the path of an email (TLS protects each hop to the server you configured, not the message at rest); LLM prompts
  include package names and versions from your hosts.
- **Agents run as root.** The collector is hardened and isolated, but anything that runs as root on every
  host is a high-value target: treat the server and the release pipeline accordingly. Note two caveats on
  collector containment: (1) on Docker hosts, direct `AF_UNIX` access to `/var/run/docker.sock` is not
  read-only — a code-execution bug in a collector parser (such as Syft scanning a malicious image) could
  call Docker Engine APIs to spawn a host-networked privileged container outside `PrivateNetwork=yes` and
  `ProtectSystem=strict`; (2) `CAP_SYS_PTRACE` without PID/proc isolation (needed to read `/proc/1/net`
  and `/proc/*/fd`) permits writing to `/proc/<pid>/mem` of other processes on the host.
- **Vulnerability DB upstream trust.** While the central rules feed is ed25519-signed (both bundles and
  signed `latest.json` freshness pointers, with an anti-downgrade latch once a signed pointer has been seen
  and an optional `rules.feed.require_signed_pointer` setting), the Grype vulnerability database (which
  supplies CVE matches, KEV and EPSS) is fetched over HTTPS without independent upstream signature
  verification (only SHA-256 against `latest.json`), and `ValidateAge` is disabled so stale databases keep
  working offline. To reduce the blast radius of a corrupted or poisoned upstream DB, updates are downloaded
  into a staging directory and refused before activation if the database contains zero vulnerability records
  or drops by more than 50% compared to the active database; operators can also pin a mirrored distribution
  via `feeds.grype_url` and `feeds.grype_ca_file`. Still, a subtly modified upstream DB could suppress
  individual CVE matches without triggering the volume anomaly guard.
- **Single server, SQLite.** No clustering or high availability; back up regularly.
- **The built-in local agent (agentless mode, off by default).** With `source: collector` the server process,
  running as the static user `holealign`, can request the host's facts and inventory through the collector
  socket. The root collector still has no network, and the server stays unprivileged. With
  `source: inprocess` (or `auto` when the socket refuses the server) the server process itself reads
  untrusted local files with its own privileges, so the server host needs the same care as any monitored
  host. The local agent does not add a remote command channel: all API validation, limits and
  authentication apply to it as to any agent.
