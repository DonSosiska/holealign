# Notifications (Matrix, Slack, Telegram, Discord, Teams, webhook, email)

Holealign sends alerts to Matrix/Element rooms, Slack channels, Telegram chats, Discord and Microsoft
Teams channels, a signed generic webhook, and email.
Findings are routed by the labels of the affected host; server-level events (stale feed, failing
pipeline, mass silence) go to separate ops destinations. This page is a per-channel setup guide, the
routing rules, the message types, and the deduplication, grace and burst behaviour, including what you
see when delivery fails.

Contents: [Destinations](#destinations) - [Matrix](#matrix) - [Slack](#slack) - [Telegram](#telegram) -
[Discord](#discord) - [Microsoft Teams](#microsoft-teams) - [Generic signed webhook](#generic-signed-webhook) -
[Email](#email) - [Routing](#routing) - [Message types](#message-types) -
[Deduplication, grace and bursts](#deduplication-grace-and-bursts) -
[Delivery problems](#delivery-problems)

## Destinations

A destination is a string `scheme:target`. Everything that routes alerts (`notify.default`,
`notify.routes[].to`, `notify.ops` and the routes edited in the web UI) takes destinations, and the
channels can be mixed freely in one route.

| Channel | Destination | Example |
|---|---|---|
| Matrix | `!id:server` (room ID), a room version 12 ID `!<43-character hash>` (no server part), or `matrix:` before either; an alias `#alias:server` passes the syntax check | `!abc123:matrix.example.com` |
| Slack | `slack:<channel ID>`: `C...` public, `G...` private, `D...` direct message. IDs only, never names. | `slack:C0123456789` |
| Telegram | `telegram:<chat_id>` or `telegram:<chat_id>/<message_thread_id>` (a topic of a forum group) | `telegram:-1001234567890`, `telegram:-1001234567890/17` |
| Discord | `discord:<name>`: the name of a webhook in `discord.webhooks` | `discord:ops` |
| Microsoft Teams | `teams:<name>`: the name of a webhook in `teams.webhooks` | `teams:ops` |
| Webhook | `webhook:<name>`: the name of an endpoint in `webhook.endpoints` | `webhook:siem` |
| Email | `email:<address>`: one plain mailbox, no display name | `email:ops@example.com` |

A destination without a known scheme is a Matrix room, so configs and routes written before Slack and
Telegram existed keep working unchanged. Syntax is checked strictly when the config loads and when
routes are saved in the web UI: an unknown scheme (`signal:...`), a malformed target
(`slack:#general`, `telegram:@channel`, `discord:https://...`), a name that is not configured
(`teams:other`), a channel that is not configured (`slack:...` without `slack.token_env`) or an
email address outside `email.allowed_domains` stops the server from starting, or is shown as an
error in the form.

Discord, Teams and webhook destinations are **names**, never URLs: the URLs and secrets live in the
config file and the environment, so a route edit in the web UI cannot make the server call an
arbitrary address.

Each channel is enabled by its own config section and has its own secret in the environment:

| Channel | Enabled by | Secret (environment variable) |
|---|---|---|
| Matrix | `matrix.homeserver` | `HOLEALIGN_MATRIX_TOKEN` (name set by `matrix.access_token_env`) |
| Slack | `slack.token_env` | `HOLEALIGN_SLACK_TOKEN` |
| Telegram | `telegram.bot_token_env` | `HOLEALIGN_TELEGRAM_TOKEN` |
| Discord | one entry in `discord.webhooks` | the webhook URL: `HOLEALIGN_DISCORD_<NAME>_URL` (`url_env`) |
| Microsoft Teams | one entry in `teams.webhooks` | the workflow URL: `HOLEALIGN_TEAMS_<NAME>_URL` (`url_env`) |
| Webhook | one entry in `webhook.endpoints` | the signing key: `HOLEALIGN_WEBHOOK_<NAME>_SECRET` (`secret_env`) |
| Email | `email.smtp.host` | the SMTP password: `HOLEALIGN_SMTP_PASSWORD` (`email.smtp.password_env`) |

The Slack and Telegram API addresses (`https://slack.com/api`, `https://api.telegram.org`) are fixed in
the program; neither the config file nor the web UI can point the server at another host. Discord
and Teams URLs are validated against the services' hosts; the generic webhook may point anywhere, but
only from the config file.

```yaml
# server.yaml: all three channels, mixed routes
matrix:   {homeserver: "https://matrix.example.com"}
slack:    {token_env: HOLEALIGN_SLACK_TOKEN}
telegram: {bot_token_env: HOLEALIGN_TELEGRAM_TOKEN}
notify:
  default: ["!default:matrix.example.com"]            # no label route matched
  routes:
    - {label: prod,    to: ["!prod:matrix.example.com", "slack:C0123456789"]}
    - {label: staging, to: ["telegram:-1001234567890/17"]}
  ops: ["slack:C0987654321", "telegram:-1009876543210"]  # server-level events
```

## Matrix

1. **Create a bot user** on your homeserver, for example `@holealign:matrix.example.com`. A dedicated
   account keeps the token's reach small.
2. **Get an access token** for it. Do not sign in with Element and later sign that session out,
   because logging out invalidates the token. Request a separate login instead:

   ```sh
   curl -sS -X POST https://matrix.example.com/_matrix/client/v3/login \
     -H 'Content-Type: application/json' \
     -d '{"type":"m.login.password","identifier":{"type":"m.id.user","user":"holealign"},"password":"BOT_PASSWORD","initial_device_display_name":"holealign-server"}'
   ```

   The reply contains `access_token`. (In Element: Settings, Help & About, Advanced, Access Token,
   but that token belongs to your Element session.)
3. **Create the rooms** (for example `prod-alerts`, `staging-alerts`, `holealign-ops`), **invite the
   bot, and accept the invite as the bot** (sign in as the bot once, or accept through the API). The
   server does not join rooms by itself: it only sends messages, so the bot must already be a member
   and allowed to send.
4. **Find the room IDs.** Holealign needs the internal ID (`!abc123:matrix.example.com`), not an
   alias (`#prod-alerts:...`): the send API addresses rooms by ID, so an alias passes the syntax check
   but is rejected by the homeserver at delivery. In Element: Room settings, Advanced, "Internal room ID".
   Rooms created with room version 12 have IDs without a server part (`!` and a 43-character hash);
   use them as they are.
5. **Configure the server.** The token goes in the environment, the rest in `server.env`/`.env` or
   `server.yaml`:

   ```sh
   # server.env or deploy/.env
   HOLEALIGN_MATRIX_TOKEN=syt_...
   HOLEALIGN_MATRIX_HOMESERVER=https://matrix.example.com
   HOLEALIGN_NOTIFY_OPS=!ops:matrix.example.com
   ```

   ```yaml
   # server.yaml
   matrix:
     homeserver: https://matrix.example.com
   notify:
     default: ["!default:matrix.example.com"]   # used when no label route matches
     routes:
       - {label: prod,    to: ["!prod:matrix.example.com"]}
       - {label: staging, to: ["!staging:matrix.example.com"]}
     ops: ["!ops:matrix.example.com"]
   ```

   The older keys `matrix.default_rooms`, `matrix.routes[].rooms` and `alerts.ops_rooms` are still
   accepted as deprecated aliases: they are merged into `notify.default`, `notify.routes[].to` and
   `notify.ops`, and one warning at startup names the ones in use.

6. **Restart the server** and look for `matrix channel enabled` in the log
   (`matrix channel disabled` with a reason means the config is invalid). There is no "send test
   message" button; the first real alert, or the delivery-problem banner on the dashboard, tells
   you whether delivery works.

**Encryption.** Holealign does not implement Matrix end-to-end encryption. It posts plain
`m.room.message` events through the client API. Use unencrypted rooms for alerts; do not put the
bot in an encrypted room and expect confidential content. Alerts contain hostnames, package
versions and vulnerability IDs. The access token is a secret: keep `server.env` mode 0600.

Message format: plain body plus HTML (`org.matrix.custom.html`); informational messages (resolved,
agent back, feed OK) are `m.notice`; every message carries empty `m.mentions`.

## Slack

Holealign posts with `chat.postMessage` using a **bot token**. One token serves any number of channels.

1. **Create a Slack app** at <https://api.slack.com/apps> ("Create New App", "From scratch"), pick
   your workspace. A dedicated app named for what it does (for example "Holealign alerts") keeps the
   token's reach small.
2. **Add the scope.** Under "OAuth & Permissions", "Bot Token Scopes", add `chat:write`. Nothing else
   is needed: Holealign never reads channels, and `chat:write.public` is deliberately not required.
3. **Install the app** to the workspace ("Install to Workspace") and copy the **Bot User OAuth Token**
   (starts with `xoxb-`). Treat it like a password.
4. **Invite the bot to every channel it should post to**: in the channel, `/invite @Holealign alerts`
   (or Channel details, Integrations, Add apps). Without that, Slack answers `not_in_channel`.
5. **Find the channel ID.** Names are not accepted. In Slack: open the channel, click its name at the
   top, scroll to the bottom of the About tab: "Channel ID" (`C0123456789`). Private channels start
   with `G` or `C`, direct messages with `D`.
6. **Configure the server:**

   ```sh
   # server.env
   HOLEALIGN_SLACK_TOKEN=xoxb-...
   ```

   ```yaml
   slack: {token_env: HOLEALIGN_SLACK_TOKEN}
   notify:
     routes:
       - {label: prod, to: ["slack:C0123456789"]}
     ops: ["slack:C0987654321"]
   ```

7. **Restart** and look for `slack channel enabled`.

Format: Slack mrkdwn (bold header, inline code for fix commands, `<url|label>` links); links are not
unfurled. Every untrusted string has `&`, `<` and `>` escaped, which also defuses `<!channel>`,
`<!here>`, `<@U...>` and `<url|text>` injection; `@` gets a zero-width space, and `*`, `~`, backticks
and word-boundary `_` are separated by zero-width spaces so a host name cannot restyle the message.
A message stays well under Slack's 40,000 character limit (whole lines are dropped with a note).

## Telegram

1. **Create a bot** with [@BotFather](https://t.me/BotFather): send `/newbot`, choose a name and a
   username, and copy the **token** (`123456789:AA...`). Treat it like a password.
2. **Add the bot to the group** (or start a chat with it for a private destination). In a group the
   bot can post as soon as it is a member; for a channel, make it an administrator with "Post
   messages". Privacy mode does not matter: the bot only sends.
3. **Find the chat ID.** Send any message in the group, then open
   `https://api.telegram.org/bot<TOKEN>/getUpdates` in a browser (or `curl`) and read
   `message.chat.id`: a group or supergroup ID is negative (supergroups look like `-1001234567890`),
   a private chat ID is positive. Holealign accepts only numeric IDs, not `@usernames`. (The URL
   contains the token: delete it from your browser history.)
4. **Topics (optional).** In a group with topics enabled ("forum"), alerts can go to one topic. Its
   `message_thread_id` is the number in the topic's link (`https://t.me/c/1234567890/17`: topic `17`),
   or `message_thread_id` in `getUpdates` for a message sent inside the topic. Use
   `telegram:-1001234567890/17`. Without `/17` the message goes to the General topic.
5. **Configure the server:**

   ```sh
   # server.env
   HOLEALIGN_TELEGRAM_TOKEN=123456789:AA...
   ```

   ```yaml
   telegram: {bot_token_env: HOLEALIGN_TELEGRAM_TOKEN}
   notify:
     routes:
       - {label: prod, to: ["telegram:-1001234567890/17"]}
     ops: ["telegram:-1009876543210"]
   ```

6. **Restart** and look for `telegram channel enabled`.

Format: Telegram HTML limited to `<b>`, `<code>` and `<a href>`; every untrusted string is HTML-escaped,
`@` gets a zero-width space, link previews are disabled, and informational messages (resolved, agent
back, feed OK) are sent silently. A message is at most 3,900 visible characters (the API limit is
4,096): whole lines are dropped with a note and an over-long line is cut before any tag is built, so
a tag or entity is never split. The token is part of the request URL, so the server never logs
request URLs or puts them in error messages.

## Discord

Holealign posts to a **Discord webhook**. The destination is a **name** you choose (`discord:ops`);
the webhook URL, which is the secret, lives only in the server's environment, so nobody who can edit
routes in the web UI can make the server call a different URL.

1. **Create the webhook.** In Discord open the channel's settings, **Integrations**, **Webhooks**,
   **New Webhook**, pick the channel and **Copy Webhook URL**
   (`https://discord.com/api/webhooks/<id>/<token>`). Treat it like a password: anyone who has it can
   post to that channel.
2. **Configure the server.** The variable name is yours to choose; the default for a webhook called
   `ops` is `HOLEALIGN_DISCORD_OPS_URL`.

   ```sh
   # server.env
   HOLEALIGN_DISCORD_OPS_URL=https://discord.com/api/webhooks/123456789012345678/AbCd...
   ```

   ```yaml
   discord:
     webhooks:
       ops:  {url_env: HOLEALIGN_DISCORD_OPS_URL}
       prod: {url_env: HOLEALIGN_DISCORD_PROD_URL}   # one webhook per channel
   notify:
     routes:
       - {label: prod, to: ["discord:prod"]}
     ops: ["discord:ops"]
   ```

3. **Restart** and look for `discord channel enabled`.

Names are 1 to 32 characters of `a-z`, `0-9`, `_` and `-`. The URL is validated when the server starts:
`https`, host `discord.com` or `discordapp.com`, path `/api/webhooks/<id>/<token>`, no query, no port.
A malformed URL stops the server from starting (the message names the key and the variable, never
the URL).

Format: Discord markdown (bold header, inline code for fix commands, links as `<url>` without
embeds). The request sets `allowed_mentions.parse` to an empty list and the `SUPPRESS_EMBEDS` flag.
Untrusted text has every markdown character backslash-escaped (`\ * _ ~ ` | > # - [ ] ( )`) and `@`
and `<` followed by a zero-width space, so `@everyone`, `@here`, `<@id>`, `<@&id>` and `<#id>`
cannot form. A message is at most 2,000 characters; whole lines are dropped with a note. Rate limits
(429) are retried after the `retry_after` the API sends. 401, 403, 404 and other 4xx are permanent
(deleted webhook, wrong URL).

## Microsoft Teams

The classic "Incoming Webhook" connectors of Office 365 are retired. Holealign targets the **Workflows**
(Power Automate) trigger **When a Teams webhook request is received**, which accepts a message with
an Adaptive Card attachment. The destination is a name (`teams:ops`); the workflow URL, which carries
a signature and is the secret, lives in the environment.

1. **Create the workflow.** In Teams open the **Workflows** app (or the channel's **...** menu,
   **Workflows**) and choose the template **Post to a channel when a webhook request is received**.
   Pick the team and channel, finish, and copy the **HTTP POST URL** the last step shows (a long URL on
   `...logic.azure.com` or `...environment.api.powerplatform.com`).
2. **Configure the server:**

   ```sh
   # server.env
   HOLEALIGN_TEAMS_OPS_URL=https://prod-12.westeurope.logic.azure.com:443/workflows/...&sig=...
   ```

   ```yaml
   teams:
     webhooks:
       ops: {url_env: HOLEALIGN_TEAMS_OPS_URL}
   notify:
     ops: ["teams:ops"]
   ```

3. **Restart** and look for `teams channel enabled`.

The URL must be `https`, without user info, and its host must end with one of `.logic.azure.com`,
`.powerplatform.com` or `.environment.api.powerplatform.com`. Anything else is rejected at startup,
unless that webhook sets `allow_any_host: true` (for a proxy or a test endpoint); the server then logs
a warning at startup.

Format: one message with an Adaptive Card (schema 1.4), one `TextBlock` per line, the headline in
bold. TextBlocks render a markdown subset, so untrusted text has `\ * _ ` ~ [ ] ( ) < > # | ! - + &`
backslash-escaped and `@` neutralised; the message has no mention entities, so nothing can ping. The
card is kept below 25 KB (whole lines are dropped with a note). `202 Accepted` is success; 429 is
retried after `Retry-After`; 400, 401, 403, 404 and other 4xx are permanent. Note that Workflows
answer 202 before the post reaches the channel: a flow that later fails shows up in the workflow's run
history, not in Holealign.

## Generic signed webhook

For everything else (a SIEM, a ticket system, your own receiver): Holealign sends a signed JSON
document to a URL you configure. The destination is a name (`webhook:siem`).

```yaml
webhook:
  endpoints:
    siem:
      url: https://siem.example.com/holealign/ingest
      secret_env: HOLEALIGN_WEBHOOK_SIEM_SECRET     # signing key, at least 16 bytes
      headers: {Authorization: "Bearer ..."}        # optional extra headers (values live in the config file)
    lab:
      url: http://10.0.0.5:8080/hook
      allow_http: true                               # plain http needs this; logged as a warning
notify:
  routes:
    - {label: prod, to: ["webhook:siem"]}
```

```sh
# server.env
HOLEALIGN_WEBHOOK_SIEM_SECRET=$(openssl rand -hex 32)
```

The URL must be `https` unless `allow_http: true`, and may point to any host. It comes from the config
file only, which only the operator edits; deciding what the server may reach is the operator's
responsibility (the web UI can only pick a configured name). Redirects are not followed and at most
64 KiB of the response is read. `2xx` is success; `429` and `5xx` are retried (honouring `Retry-After`);
every other status is permanent. Extra `headers` cannot override `Content-Type`, `Host`, the framing
headers or `X-Holealign-*`.

**Request.** `POST` with `Content-Type: application/json` and:

| Header | Value |
|---|---|
| `X-Holealign-Signature` | `t=<unix seconds>,v1=<hex HMAC-SHA256(secret, "<t>.<raw body>")>` |
| `X-Holealign-Event-Id` | the message ID; the same value on every retry of one message, use it to deduplicate |

**Body (schema version 1).** Built from the events, not parsed from the rendered text. Fields are only
added within a version; a change that removes or redefines a field increments `version`.

```json
{
  "version": 1,
  "id": "holealign-1731950000000000000-1-0a1b2c3d4e5f",
  "kind": "exploitable",
  "sent_at": "2026-11-18T17:00:00Z",
  "title": "🔴 EXPLOITABLE: CVE-2024-1 on web01",
  "text": "🔴 EXPLOITABLE: CVE-2024-1 on web01\nPackage: openssl 3.0.1 → fixed in 3.0.2\n...",
  "events": [
    {
      "kind": "exploitable", "host": "web01", "labels": ["prod", "eu"],
      "vuln_id": "CVE-2024-1", "aliases": ["GHSA-xxxx-yyyy-zzzz"],
      "package": "openssl", "version": "3.0.1", "fixed_version": "3.0.2",
      "verdict": "exploitable", "severity": "High", "cvss": 7.5, "epss": 0.42, "kev": true,
      "reason": "reachable via nginx", "finding_url": "https://holealign.example/findings/9"
    }
  ]
}
```

`kind` is the kind of the first event (`exploitable`, `unknown_critical`, `resolved`, `agent_silent`,
`agent_back`, `feed_stale`, `feed_ok`, `pipeline_error`) or `summary` for a burst summary (then
`events` is empty and the list is in `text`). `events` has at most 50 entries per message.
`fixed_version` joins several fixed versions with `, ` (empty if none); for health events `reason`
carries the detail text. Strings are cleaned of control characters and cut to 300 characters, but
not escaped: they are data, never markup, and a receiver must not render them as HTML.

**Verifying a delivery.** Recompute the HMAC over the **raw** request body (not a re-serialised
copy), compare in constant time, and reject timestamps older (or newer) than 5 minutes.

```go
// Go
func verify(secret string, header string, body []byte, now time.Time) bool {
	var ts, sig string
	for _, p := range strings.Split(header, ",") {
		if k, v, ok := strings.Cut(strings.TrimSpace(p), "="); ok {
			switch k {
			case "t":
				ts = v
			case "v1":
				sig = v
			}
		}
	}
	t, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || math.Abs(now.Sub(time.Unix(t, 0)).Seconds()) > 300 {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	want := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(want), []byte(sig))
}
```

```python
# Python
import hashlib, hmac, time

def verify(secret: str, header: str, body: bytes) -> bool:
    parts = dict(p.strip().split("=", 1) for p in header.split(",") if "=" in p)
    try:
        t = int(parts["t"])
    except (KeyError, ValueError):
        return False
    if abs(time.time() - t) > 300:
        return False
    want = hmac.new(secret.encode(), f"{t}.".encode() + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, parts.get("v1", ""))
```

Test vector: secret `key`, timestamp `1700000000`, body `body` gives
`t=1700000000,v1=47b6ce0fca59474308e2921c247cb2493dce6b8101d90ac05bd0c6a37d0e046e`.

Retries repeat the same `X-Holealign-Event-Id` with a fresh timestamp and signature; a receiver that
must not process a message twice stores the IDs it has seen.

## Email

Holealign sends through an SMTP server you provide, as `multipart/alternative` (plain text and HTML).
The destination is a single address: `email:ops@example.com`.

```yaml
email:
  smtp:
    host: smtp.example.com
    port: 587                       # default 587
    username: alerts@example.com    # optional; without it no login is attempted
    password_env: HOLEALIGN_SMTP_PASSWORD
    tls: starttls                   # starttls (default, port 587) or implicit (port 465)
    from: "Holealign <alerts@example.com>"
  allowed_domains: [example.com]    # optional: only these recipient domains
notify:
  ops: ["email:secops@example.com"]
  routes:
    - {label: prod, to: ["email:oncall@example.com", "slack:C0123456789"]}
```

```sh
# server.env
HOLEALIGN_SMTP_PASSWORD=...
```

- **TLS is mandatory.** `starttls` connects in plain text only to issue STARTTLS and refuses to
  continue (permanent failure, nothing sent, no login) when the server does not offer it; `implicit`
  starts TLS immediately. There is no plain-text mode and no downgrade. The server certificate is
  verified against the system roots (TLS 1.2 or newer) and must match `host`. The password is sent
  (PLAIN) only after TLS is up.
- **Recipients.** The address syntax is strict: one `local@domain` with a local part of letters,
  digits and `. _ % + -`, a domain with at least two labels; no display names, quotes, comments, lists
  or address literals. `allowed_domains` (exact, lower case, subdomains are not included) limits which
  addresses can be configured or routed in the web UI, and is checked again before sending.
- **Message.** The subject is the first line of the alert with control characters and line breaks
  removed (no header injection), cut to 150 characters and MIME-encoded; `Message-ID` is derived from
  the message ID, `Date` is set, `Auto-Submitted: auto-generated` marks it as automatic. Bodies are
  quoted-printable, at most 8 KiB each, with every untrusted value HTML-escaped.
- **Errors.** SMTP 4xx replies and network errors are retried with backoff; 5xx replies (rejected
  recipient, authentication failure, policy) and certificate errors are permanent. The server
  never includes the password in logs or error messages. One SMTP connection is used per message.
- **Restart** and look for `email channel enabled`.

Gmail, Microsoft 365 and similar services need an app password or an SMTP relay account: use
`smtp.gmail.com` / `smtp.office365.com`, port 587, `starttls`.

## Routing

- A finding event goes to the **union of the destinations** of all labels of its host
  (`notify.routes` plus the routes edited in the web UI, deduplicated; `!a:b` and `matrix:!a:b` are the
  same destination). If no label of the host has a route, the event goes to `notify.default`.
- **Server-level events** (feed stale/ok, pipeline error, and aggregated silence with no single host)
  go to `notify.ops`; if empty, to `notify.default`.
- If no destination can be resolved for an event, that is reported as a delivery problem, not dropped
  silently. The same holds for a destination whose channel is not configured on the running server
  (for example a route saved in the web UI for Slack after the Slack token was removed).
- Host labels come from the enrollment token (authoritative when the token has labels) or from the
  agent's `labels`. See [installation.md](installation.md#agents).

**Editing routes in the web UI.** Settings, "Notification routes": one line per label, destinations
of any configured channel separated by commas,

```
prod = !prod:matrix.example.com, slack:C0123456789
staging = telegram:-1001234567890/17
# lines starting with # are comments
```

Saving needs your current password. Each destination is checked with the same rules as the config
file (unknown scheme, malformed target or unconfigured channel are errors shown in the form); up to
200 routes and 20 destinations per route. UI routes are stored in the database and merged with the
ones in `server.yaml` (destinations of the same label are combined). Default and ops destinations are
config-only: the settings page shows them read-only. Routes stored before Slack and Telegram existed
(JSON key `rooms`) still load; saving rewrites them with the key `to`.

## Message types

| Message | Header | Sent when | Destinations |
|---|---|---|---|
| Exploitable | `EXPLOITABLE: <vuln> on <host>` | A finding is new with verdict `exploitable`, or its verdict changed to `exploitable`. | host labels |
| Check (unknown critical) | `CHECK: <vuln> on <host>` | A new finding is `conditions_unknown` and is on the KEV list or has severity Critical. Not repeated when only the reason changes. | host labels |
| Resolved | `RESOLVED: <vuln> on <host>` | A finding that was notified became `resolved`, `affected_not_exploitable` or `not_affected`. | host labels |
| Agent silent | `AGENT SILENT: <host>` | A host that checked in before has not checked in for `alerts.agent_silent_after` (default 30 m). | host labels |
| Agent back | `AGENT BACK: <host>` | A silent host checks in again. | host labels |
| Feed stale | `FEED STALE:` | The vulnerability DB is older than `alerts.feed_stale_after` (default 48 h), or refreshing failed on more than 2 consecutive checks. A separate alert whose text starts with "rules feed" is sent when the signed rules feed ([rules-feed.md](rules-feed.md#health)) has had no successful poll for `rules.feed.stale_after` (default 7 d) or 3 polls in a row failed. | ops destinations |
| Feed OK | `FEED OK:` | The feed recovered. | ops destinations |
| Pipeline error | `PIPELINE ERROR: <host>` | Matching failed 3 runs in a row for a host, a target was skipped (invalid or poisoned SBOM), or a host limit was hit. At most once per host per 24 h; more than 5 hosts are aggregated. | ops destinations |

An exploitable or check message names the host, lists the affected packages with fixed versions
(up to 5), the severity, CVSS, EPSS and KEV flag, the reason (the facts that decided), the rule's
explanation, a package-manager upgrade command for that host's OS, the rule's mitigation, and a link
to the finding in the admin UI (from `public_url`). For a draft (unreviewed LLM) rule only a warning and
the server-generated fix command are shown; the reason of a draft is a fixed string and the notifier
replaces any reason that starts with `LLM draft` by a fixed text, so nothing a model wrote is ever relayed
([llm.md](llm.md#prompt-injection-defenses)).

Mass silence: when more than max(5, 30% of the fleet) hosts go silent in one pass, one aggregated
`AGENT SILENT` event naming up to 50 hosts goes to the ops destinations, and one event per label lists the
silent hosts with that label for that label's destinations ("server or network problem?"). Silence alerts are
held back for twice the check-in interval after the server starts. Delivery is tracked **per destination** (the ops overview, each label's destinations, the hosts without a label). A host counts as announced to a destination only when a delivered message to that destination named it. If one destination fails, only the missing messages are retried on the next pass (every minute, as the health loop runs), destinations that already received the alert are not sent it again, and a host is recorded as notified once every message naming it was delivered. A silent host that no delivered message named is announced again on the next pass. The silent-host list in each message is limited to 50 hosts, newest check-in first.

Safety of the text: every untrusted field (hostnames, package names, reasons) is cut to 300
characters with control characters removed, a zero-width space follows every `@` so nothing pings
`@room`, `@channel` or a user, every Matrix message carries empty `m.mentions`, and each channel escapes
the text for its own markup (see the channel sections). Matrix bodies are capped at 8 KiB. At most 50
events are rendered per message. The content is built once as a channel-neutral message (header line,
severity/KEV/EPSS facts, host lines, reason, fix hint, links) and formatted per channel.

## Deduplication, grace and bursts

- **Dedup.** A notification is keyed by (host, target, package, vulnerability, kind) and never sent
  twice in a row. Re-running agents, restarting the server or re-evaluating hosts does not repeat
  alerts. After a finding is `resolved`, a later re-appearance alerts again. Dedup records older than
  `retention.notifications` (90 days) are deleted, except for still-open findings.
- **Grouping.** One vulnerability on one target of one host is one message, even when several
  binary packages from the same source are affected (for example `openssh-client` and
  `openssh-server`).
- **Grace for unknown.** With an LLM configured, a `CHECK` alert is held back until the finding has
  been `conditions_unknown` for 2 hours, giving the drafter time to produce a rule (which may turn
  it into a verdict). Without an LLM there is no delay. A pass every 5 minutes emits the held-back
  alerts.
- **Burst.** When one destination would receive more than 15 messages in one pass, the 10 most important
  (exploitable before check before resolved, KEV first, then higher CVSS) are sent individually and
  the rest are summarised in one message of up to 50 `vuln@host` lines with a link to the findings
  page. Health events are never part of a burst.
- **Retries.** Each message is tried up to 4 times, honouring the service's retry delay (Matrix `retry_after_ms`, Slack `Retry-After`, Telegram
  `parameters.retry_after`; capped at 30 s) and backing off exponentially otherwise. Events that still fail are retried on later passes; a message is not posted again to destinations it
  already reached.

## Delivery problems

If a channel rejects messages (wrong room or channel ID, bot not a member, expired token, service
down), the server logs the status and destination at most once per 10 minutes per (destination,
status) and shows a **banner on the dashboard** with the last 20 distinct problems (time, destination,
status, kind, whether permanent; status 0 is a network error, an empty destination means none was
resolved). Slack answers most errors with HTTP 200 and `"ok": false`; the error code is mapped to a
status in the table.

| Status | Usual cause |
|---|---|
| 401 / 403 | Matrix: token invalid or revoked, or the bot may not send in the room. Slack: `invalid_auth`, `account_inactive`, `token_revoked` (401); `not_in_channel`, `missing_scope`, `is_archived` (403): invite the bot, add `chat:write`. Telegram: bad token (401), bot kicked or blocked (403). |
| 404 | Matrix: wrong room ID (an alias or a typo), or the room was deleted. Slack: `channel_not_found` (use the ID, not the name). |
| 400 | Telegram: `chat not found` (wrong chat ID, or the bot never joined), bad topic. Slack: any other API error. |
| 429 | Rate limited; retried after the delay the service asks for. |
| 5xx | Service trouble; retried with backoff. |
| 0 | The service is unreachable from the server. |

Discord answers 401, 403 or 404 when the webhook was deleted or the URL is wrong; Teams answers 400 or
404 for a workflow that is turned off or deleted; a generic webhook reports whatever status the
receiver returned; email reports the SMTP reply code (`535` bad login, `550` rejected recipient,
`452`/`421` temporary).

For `exploitable`, `check`, `agent silent` and `feed stale` messages a permanent failure keeps the event
pending and it is retried later (so fixing the room, channel or token delivers the backlog). For
`resolved`, `agent back`, `feed OK` and `pipeline error` messages a permanent failure is recorded as
delivered, not retried forever. Delivery state is tracked per destination: one failing destination
does not stop the others, and a retried event is not posted again where it already arrived.
A destination whose channel is not configured on the running server is a permanent problem as well.
More help: [operations.md](operations.md#troubleshooting).
