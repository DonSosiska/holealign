# Notifications (Matrix)

Panoptes sends alerts to Matrix/Element rooms. Findings are routed by the labels of the affected
host; server-level events (stale feed, failing pipeline, mass silence) go to separate ops rooms.
This page is a step-by-step Matrix setup, the message types, and the deduplication, grace and burst
behaviour, including what you see when delivery fails.

Contents: [Matrix setup](#matrix-setup) - [Routing](#routing) - [Message types](#message-types) -
[Deduplication, grace and bursts](#deduplication-grace-and-bursts) -
[Delivery problems](#delivery-problems)

## Matrix setup

1. **Create a bot user** on your homeserver, for example `@panoptes:matrix.example.com`. A dedicated
   account keeps the token's reach small.
2. **Get an access token** for it. Do not sign in with Element and later sign that session out,
   because logging out invalidates the token. Request a separate login instead:

   ```sh
   curl -sS -X POST https://matrix.example.com/_matrix/client/v3/login \
     -H 'Content-Type: application/json' \
     -d '{"type":"m.login.password","identifier":{"type":"m.id.user","user":"panoptes"},"password":"BOT_PASSWORD","initial_device_display_name":"panoptes-server"}'
   ```

   The reply contains `access_token`. (In Element: Settings, Help & About, Advanced, Access Token,
   but that token belongs to your Element session.)
3. **Create the rooms** (for example `prod-alerts`, `staging-alerts`, `panoptes-ops`), **invite the
   bot, and accept the invite as the bot** (sign in as the bot once, or accept through the API). The
   server does not join rooms by itself: it only sends messages, so the bot must already be a member
   and allowed to send.
4. **Find the room IDs.** Panoptes needs the internal ID (`!abc123:matrix.example.com`), not an
   alias (`#prod-alerts:...`). In Element: Room settings, Advanced, "Internal room ID".
5. **Configure the server.** The token goes in the environment, the rest in `server.env`/`.env` or
   `server.yaml`:

   ```sh
   # server.env or deploy/.env
   PANOPTES_MATRIX_TOKEN=syt_...
   PANOPTES_MATRIX_HOMESERVER=https://matrix.example.com
   PANOPTES_ALERTS_OPS_ROOMS=!ops:matrix.example.com
   ```

   ```yaml
   # server.yaml
   matrix:
     default_rooms: ["!default:matrix.example.com"]   # used when no label route matches
     routes:
       - {label: prod,    rooms: ["!prod:matrix.example.com"]}
       - {label: staging, rooms: ["!staging:matrix.example.com"]}
   alerts:
     ops_rooms: ["!ops:matrix.example.com"]
   ```

6. **Restart the server** and look for `matrix notifier enabled` in the log
   (`matrix notifier disabled` with a reason means the config is invalid). There is no "send test
   message" button; the first real alert, or the delivery-problem banner on the dashboard, tells
   you whether delivery works.

**Encryption.** Panoptes does not implement Matrix end-to-end encryption. It posts plain
`m.room.message` events through the client API. Use unencrypted rooms for alerts; do not put the
bot in an encrypted room and expect confidential content. Alerts contain hostnames, package
versions and vulnerability IDs. The access token is a secret: keep `server.env` mode 0600.

All Matrix keys: [configuration.md](configuration.md#matrix).

## Routing

- A finding event goes to the **union of the rooms** of all labels of its host
  (`matrix.routes` plus the routes edited in the web UI, deduplicated). If no label of the host has a
  route, the event goes to `matrix.default_rooms`.
- **Server-level events** (feed stale/ok, pipeline error, and aggregated silence with no single host)
  go to `alerts.ops_rooms`; if empty, to `matrix.default_rooms`.
- If no room can be resolved for an event, that is reported as a delivery problem, not dropped
  silently.
- Host labels come from the enrollment token (authoritative when the token has labels) or from the
  agent's `labels`. See [installation.md](installation.md#agents).

**Editing routes in the web UI.** Settings, "Matrix routes": one line per label,

```
prod = !prod:matrix.example.com, !secops:matrix.example.com
staging = !staging:matrix.example.com
# lines starting with # are comments
```

Saving needs your current password. Room IDs must look like `!id:server`; up to 200 routes and 20
rooms per route. UI routes are stored in the database and merged with the ones in `server.yaml`
(rooms of the same label are combined). Default rooms and ops rooms are config-only: the settings
page shows them read-only.

## Message types

| Message | Header | Sent when | Rooms |
|---|---|---|---|
| Exploitable | `EXPLOITABLE: <vuln> on <host>` | A finding is new with verdict `exploitable`, or its verdict changed to `exploitable`. | host labels |
| Check (unknown critical) | `CHECK: <vuln> on <host>` | A new finding is `conditions_unknown` and is on the KEV list or has severity Critical. Not repeated when only the reason changes. | host labels |
| Resolved | `RESOLVED: <vuln> on <host>` | A finding that was notified became `resolved`, `affected_not_exploitable` or `not_affected`. | host labels |
| Agent silent | `AGENT SILENT: <host>` | A host that checked in before has not checked in for `alerts.agent_silent_after` (default 30 m). | host labels |
| Agent back | `AGENT BACK: <host>` | A silent host checks in again. | host labels |
| Feed stale | `FEED STALE:` | The vulnerability DB is older than `alerts.feed_stale_after` (default 48 h), or refreshing failed on more than 2 consecutive checks. A separate alert whose text starts with "rules feed" is sent when the signed rules feed ([rules-feed.md](rules-feed.md#health)) has had no successful poll for `rules.feed.stale_after` (default 7 d) or 3 polls in a row failed. | ops rooms |
| Feed OK | `FEED OK:` | The feed recovered. | ops rooms |
| Pipeline error | `PIPELINE ERROR: <host>` | Matching failed 3 runs in a row for a host, a target was skipped (invalid or poisoned SBOM), or a host limit was hit. At most once per host per 24 h; more than 5 hosts are aggregated. | ops rooms |

An exploitable or check message names the host, lists the affected packages with fixed versions
(up to 5), the severity, CVSS, EPSS and KEV flag, the reason (the facts that decided), the rule's
explanation, a package-manager upgrade command for that host's OS, the rule's mitigation, and a link
to the finding in the admin UI (from `public_url`). For a draft (unreviewed LLM) rule only a warning and
the server-generated fix command are shown; the reason of a draft is a fixed string and the notifier
replaces any reason that starts with `LLM draft` by a fixed text, so nothing a model wrote is ever relayed
([llm.md](llm.md#prompt-injection-defenses)).

Mass silence: when more than max(5, 30% of the fleet) hosts go silent in one pass, one aggregated
`AGENT SILENT` event naming up to 50 hosts goes to the ops rooms, and one event per label lists the
silent hosts with that label for that label's rooms ("server or network problem?"). Silence alerts are
held back for twice the check-in interval after the server starts. Delivery is tracked **per destination** (the ops overview, each label's rooms, the hosts without a label). A host counts as announced to a destination only when a delivered message to that destination named it. If one destination fails, only the missing messages are retried on the next pass (every minute, as the health loop runs), destinations that already received the alert are not sent it again, and a host is recorded as notified once every message naming it was delivered. A silent host that no delivered message named is announced again on the next pass. The silent-host list in each message is limited to 50 hosts, newest check-in first.

Safety of the text: every untrusted field (hostnames, package names, reasons) is cut to 300
characters with control characters removed, a zero-width space follows every `@` so nothing pings
`@room`, every message carries empty `m.mentions`, and bodies are capped at 8 KiB. At most 50
events are rendered per message.

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
- **Burst.** When one room would receive more than 15 messages in one pass, the 10 most important
  (exploitable before check before resolved, KEV first, then higher CVSS) are sent individually and
  the rest are summarised in one message of up to 50 `vuln@host` lines with a link to the findings
  page. Health events are never part of a burst.
- **Retries.** Each message is tried up to 4 times, honouring the homeserver's `retry_after` (capped
  at 30 s). Events that still fail are retried on later passes; a message is not posted again to rooms it
  already reached.

## Delivery problems

If Matrix rejects messages (wrong room ID, bot not in the room, expired token, homeserver down), the
server logs the status and room at most once per 10 minutes per (room, status) and shows a **banner on
the dashboard** with the last 20 distinct problems (time, room, HTTP status, kind, whether permanent;
status 0 is a network error, an empty room means no room was resolved).

| Status | Usual cause |
|---|---|
| 401 / 403 | Token invalid or revoked, or the bot is not allowed to send in the room (not joined, or muted). |
| 404 | Wrong room ID (an alias or a typo), or the room was deleted. |
| 429 | Rate limited by the homeserver; retried with its `retry_after`. |
| 0 | The homeserver is unreachable from the server. |

For `exploitable`, `check`, `agent silent` and `feed stale` messages a permanent failure keeps the event
pending and it is retried later (so fixing the room or token delivers the backlog). For `resolved`, `agent back`, `feed OK` and
`pipeline error` messages a permanent failure is recorded as delivered, not retried forever.
More help: [operations.md](operations.md#troubleshooting).
