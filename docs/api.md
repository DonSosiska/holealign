# Agent API and command-line reference

The HTTP API that agents use to talk to the server, and the commands and flags of the two binaries.
The API is for agents: there is no public management API, administration is the web UI and the
`holealign-server` CLI. The formal contract, with every policy detail, is
[contracts.md section 1](contracts.md#1-agent--server-http-api-apiv1); the Go types are in
`internal/model`. If this page and the code disagree, the code wins and this page is a bug.

Contents: [Conventions](#conventions) - [Endpoints](#endpoints) - [Enrollment and re-enrollment](#enrollment-and-re-enrollment) -
[Limits and status codes](#limits-and-status-codes) - [Agent behaviour](#agent-behaviour) -
[holealign-server](#holealign-server) - [holealign-agent](#holealign-agent)

## Conventions

- Base path `/api/v1`. The agent listener (`listen`, default `:8080`) serves only `/api/v1/*` and
  `/healthz`; everything else is 404. The web UI is on the separate admin listener.
- All bodies are JSON (`Content-Type: application/json`). Error responses are
  `{"error": "<message>"}` with a 4xx or 5xx status.
- After enrollment, requests carry `Authorization: Bearer <agent_key>`. The server stores only the SHA-256
  hash of agent keys and enrollment tokens.
- Agents always speak TLS 1.2 or newer, verify the chain and host name, and never follow redirects.
- `429` and `503` responses carry `Retry-After` (seconds).
- The server never initiates a connection to an agent and has no command channel.

## Endpoints

| Method and path | Auth | Purpose |
|---|---|---|
| `GET /healthz` | none | Liveness. `200` with the text `ok`. Also served on the admin listener. |
| `POST /api/v1/enroll` | enrollment token in the body | Register a host, receive its agent key. |
| `POST /api/v1/checkin` | Bearer agent key | Heartbeat: send facts and OS info, receive instructions. |
| `POST /api/v1/inventory` | Bearer agent key | Upload the SBOMs (gzip). |

Other methods on these paths are rejected by the router (405).

### `POST /api/v1/enroll`

Request (`EnrollRequest`):

| Field | Type | Rules |
|---|---|---|
| `token` | string | Enrollment token from `holealign-server token create` (or the web UI). Required. |
| `hostname` | string | Truncated to 253 characters; control, format (zero-width) and bidi characters removed. |
| `machine_id` | string | `^[0-9a-f]{32,64}$`. The agent sends `hex(sha256("panoptes-machine-id:" + /etc/machine-id))`. |
| `labels` | list of strings | At most 32, each `^[a-z0-9][a-z0-9._-]{0,63}$`. Ignored when the token carries labels. |
| `agent_version` | string | Truncated to 64 characters. |

Response `200` (`EnrollResponse`):

| Field | Type | Meaning |
|---|---|---|
| `agent_id` | string | The host's ID on the server. |
| `agent_key` | string | `pa_...`. Shown once; the agent stores it in `<state_dir>/credentials.json` (0600). |

Statuses: `400` bad JSON, bad `machine_id` or labels; `401` unknown, revoked or expired token (or an empty
token); `403` the token's `max_hosts` is reached; `409` the machine is already enrolled and the request is
not authorised to replace it (see below); `413` body over 1 MiB; `429` too many invalid requests from this
client; `500`.

### `POST /api/v1/checkin`

Sent every 5 minutes by default (the interval is the agent's `checkin_interval`).

Request (`CheckinRequest`):

| Field | Type | Meaning |
|---|---|---|
| `hostname` | string | As in enroll. Empty keeps the stored value. |
| `labels` | list of strings | Same syntax as enroll. Ignored for hosts enrolled with a token that has labels; an absent list keeps the stored labels. |
| `agent_version` | string | |
| `os` | object | `id` and `version_id` (`^[a-z0-9][a-z0-9._-]*$`, else dropped), `pretty_name`, `kernel`, `arch`; cleaned and length-capped. An all-empty object means unchanged. |
| `facts` | map | Fact name to value ([catalog](contracts.md#3-fact-catalog)). Values: string, number, bool, list, map. |
| `facts_complete` | bool | `true`: `facts` is the full snapshot and replaces the stored facts. `false`: a diff, merged into the stored facts; a `null` value deletes the fact. |
| `inventory_hash` | string | Hash of the last inventory the agent uploaded. |

Facts after the merge: at most 1000 keys, at most 1 MiB as JSON, each value at most 64 KiB; otherwise `413`.

Response `200` (`CheckinResponse`):

| Field | Type | Meaning |
|---|---|---|
| `fact_requests` | list | Parametrised facts the server wants, always `file.match` requests from **reviewed** rules: `{name, collector, params: {path, pattern}}`. Always a list, possibly empty. The agent filters these again. |
| `want_inventory` | bool | True when the server has no inventory whose hash equals `inventory_hash`. |
| `want_full_facts` | bool | True on a host's first check-in when the request was a diff. |
| `next_checkin_seconds` | int | `0` (keep the agent's interval). The current server always sends 0; an agent clamps any value to 60 s - 1 h. |

A change of facts for a host that already has an inventory re-runs matching.

Statuses: `400` bad JSON or labels; `401` bad key; `413` body over 8 MiB or facts over the limits;
`429` per-host bucket (burst 3, one token per 20 s) with `Retry-After`; `500`.

### `POST /api/v1/inventory`

The body is an `InventoryPayload`, normally gzip-compressed (`Content-Encoding: gzip`; `identity` or no
header is accepted):

| Field | Type | Meaning |
|---|---|---|
| `collected_at` | RFC 3339 time | |
| `hash` | string | Required, at most 256 characters. SHA-256 over the target SBOMs; echoed in the next check-in. |
| `targets` | list | At most 1000. Each target below. |

Target:

| Field | Type | Rules |
|---|---|---|
| `kind` | string | `host` or `container_image`. |
| `name` | string | Required, at most 512 bytes. `host`, or the image reference. |
| `image_id` | string | Optional, at most 128 bytes (`sha256:...`). |
| `containers` | list of strings | Names of running containers using the image; at most 200, each at most 256 bytes. |
| `sbom` | JSON object | A CycloneDX JSON document: top-level `"bomFormat":"CycloneDX"` exactly; at most 50 000 components (nested counted). Keys equal to `components` or `bomFormat` only case-insensitively are rejected. |

Targets are validated one by one. An invalid target (unknown kind, empty or long name, bad SBOM, too many
components, duplicate) is **skipped**, not fatal; the valid ones are stored and the previous findings of a
skipped target are kept. Response `202`:

```json
{"status": "accepted", "skipped": [{"kind": "container_image", "name": "big:latest", "reason": "more than 50000 components"}]}
```

`skipped` is omitted when empty. An upload whose `hash` equals the stored one is answered `202` at once,
without re-matching and without spending the inventory token (a still-skipped list is repeated).
Otherwise the server replaces all targets of the host and re-runs matching asynchronously.

Statuses: `202` accepted; `400` invalid gzip or JSON, missing or too long `hash`, more than 1000 targets;
`413` body (compressed or decompressed) over 64 MiB, or a `Content-Length` above it (refused before reading);
`415` unsupported `Content-Encoding`, or no target is a CycloneDX document (the `skipped` list is included);
`429` a limit below, with `Retry-After`; `503` all decode slots are busy, with `Retry-After: 5`.

## Enrollment and re-enrollment

**First enrollment.** An administrator creates a token (`holealign-server token create web-prod -labels
prod,web -max-hosts 20 -expires 72h`). The agent posts `enroll` with the token. The server checks the
hash, expiry and `max_hosts`, creates the host, stores the key hash and returns `agent_id` and `agent_key`.
Token labels are **authoritative**: hosts enrolled with such a token get exactly those labels (the token name
is stored on the host) and labels sent later are ignored. After the first successful check-in the agent
blanks `enroll_token` in `agent.yaml`.

**Re-enrolling an existing machine** (a reinstalled agent, a lost `state_dir`, rotated credentials). The
same `machine_id` is already known, so the server requires one of:

1. `Authorization: Bearer <the host's current agent key>` on the enroll request (the agent sends its stored
   key automatically), or
2. an administrator's one-time permission: `holealign-server host allow-reenroll <host> [-ttl 1h]`
   (default 1 h, at most 168 h; cleared on first use).

Otherwise the answer is `409 {"error":"host exists; previous key required (admin: holealign-server host
allow-reenroll <host>)"}`. A permitted re-enroll reuses the host record and **rotates the key**; it keeps
the host's token name, labels and label lock unless the new token itself carries labels (then the token's
labels apply, its `max_hosts` is checked, and the host moves to it). An agent that lost its credentials
and has no token in `agent.yaml` (it was blanked) needs a fresh token as well.

A key that the server no longer knows gives `401` on check-in. The agent then re-enrolls (sending the old
key as Bearer) if an enrollment token is still configured; otherwise it logs and retries hourly.

## Limits and status codes

| Limit | Value | Result |
|---|---|---|
| Enroll body | 1 MiB (`Content-Length` above it is refused before reading) | `413` |
| Check-in body | 8 MiB; facts after merge: 1000 keys, 1 MiB, 64 KiB per value | `413` |
| Inventory body | 64 MiB compressed and 64 MiB decompressed | `413` |
| Inventory content | 1000 targets; per-target field limits above; 50 000 components per SBOM | `400`, or target skipped |
| Invalid enrollment requests | 10 per minute per client | `429` |
| Enrollment with a valid token | 600 per minute per client | `429` |
| Failed Bearer authentication | 30 per minute per client | `429` (instead of `401`) |
| Check-in | per host: burst 3, one token per 20 s | `429` + `Retry-After` |
| Inventory attempts | per host, every request, charged before the body is read: burst `limits.inventory_attempt_burst` (6), refill `limits.inventory_attempts_per_minute` (10) | `429` |
| Inventory uploads that fail validation | 6 per minute per host, checked before the body is read | `429` |
| Inventory uploads (changed hash) | per host: burst 3, one token per 5 min; `Retry-After` is the time to the next token | `429` |
| Concurrent inventory decode per host | 1 | `429`, `Retry-After: 5` |
| Concurrent inventory decodes, server-wide | `limits.inventory_concurrent_decodes` (4), no queue | `503`, `Retry-After: 5` |

A "client" is the peer IPv4 address or the IPv6 /64; behind a reverse proxy the client is taken from
`X-Forwarded-For` only for peers in `trusted_proxies`. The per-client maps are bounded LRUs: a new client is
never denied for lack of space. Requests with valid credentials are never throttled by the per-client
failure limits.

## Agent behaviour

What a well-behaved client does (this is what `holealign-agent` does):

- Retry network errors and 5xx with exponential backoff (2 s base, jitter, cap 5 min).
- A `429` is not retried inside the backoff loop: it is reported with the `Retry-After` value
  (default 30 s, clamped to 5 s - 15 min) and the next cycle is scheduled no earlier than that.
  A scanned-but-rejected inventory is kept and re-sent without rescanning.
- `401`: re-enroll as above. `409` on enroll: log an error and wait for an administrator.
- Clamp `next_checkin_seconds` to 60 s - 1 h; honour `want_inventory` at most once per 10 minutes.
- Per request timeouts: 30 s, and 5 minutes for the inventory upload.

## holealign-server

```
holealign-server [-config file] [-version] [command]
```

`-config` defaults to `$HOLEALIGN_CONFIG`, else `/etc/holealign/server.yaml`; it may also follow the
command. `-version` prints the version. Configuration keys and `HOLEALIGN_*` overrides:
[configuration.md](configuration.md).

| Command | Purpose |
|---|---|
| `serve` (default) | Run the server. |
| `token create <name> [-max-hosts N] [-expires 72h] [-labels a,b]` | Create an enrollment token; the secret is printed once. `-max-hosts 0` and `-expires 0` mean unlimited. Name: `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`. |
| `token list` | List tokens with status (active, revoked, expired, exhausted), host counts, expiry, labels. |
| `token revoke <name>` | Revoke a token. Hosts already enrolled keep working. |
| `host list` | List hosts: ID, hostname, labels, last check-in, token, re-enroll permission. |
| `host allow-reenroll <id\|hostname> [-ttl 1h]` | Allow one re-enrollment without the old key; TTL 1 s to 168 h. |
| `host delete <id\|hostname>` | Delete a host with its findings, notification dedup rows and per-host state. |
| `user set-password <user>` | Create or update a web account. The password (at least 12 characters) is read from one line of stdin. |
| `rules keygen -out <file>` | Create an ed25519 signing key (mode 0600, never overwritten); prints the public key and `key_id`. |
| `rules build -rules <dir> -tests <dir> -seq N -out <dir> [-created-at RFC3339] [-min-server-version V]` | Validate, test and pack a deterministic bundle. |
| `rules sign -key <file> [-url URL] <tarball>` | Write `<tarball>.sig` and `latest.json` next to it. |
| `rules verify -pub <base64>[,<base64>] [-sig file] <tarball>` | Check the signature and the whole bundle. |
| `rules import [-sig file] <tarball>` | Install a bundle offline (needs `rules.feed.trusted_keys`). |
| `rules status` | Show the installed feed bundle. |
| `rules candidates -packages <file> [...]` | List CVEs worth a rule (bot; flags in [rules-feed.md](rules-feed.md#rules-candidates)). |
| `rules draft (-candidate <json> \| -candidate-file <file> -index N) -rules <dir> -tests <dir> [...]` | Draft a rule and tests with an LLM (bot; [rules-feed.md](rules-feed.md#rules-draft)). |

`token`, `host` and `user` open the database. When run as root they drop to the uid and gid that own the data
directory first, so no root-owned files appear; if that is impossible they refuse and suggest
`sudo -u <service-user>`. `rules keygen|build|sign|verify|candidates|draft` need no configuration or database.
Exit status: 0 success, 1 error, 2 usage.

## holealign-agent

```
holealign-agent [flags]
```

| Flag | Default | Meaning |
|---|---|---|
| `-config <file>` | `$HOLEALIGN_AGENT_CONFIG`, else `/etc/holealign/agent.yaml` | Agent configuration ([contracts.md section 2](contracts.md#2-agent-configuration-etcholealignagentyaml)). |
| `-mode all\|collector\|sender` | `all` | `all`: one process (containers, `-once`, tests). `collector`: root, no network, serves host data on a unix socket. `sender`: unprivileged, talks to the server and gets data from the collector. |
| `-once` | off | One check-in and inventory upload, then exit. Waits out a `Retry-After` of up to 60 s once. |
| `-print-facts` | off | Collect and print the facts as JSON; no server needed. |
| `-print-inventory` | off | Scan and print the inventory payload as JSON; no server needed. |
| `-print-server-pin` | off | Connect to `server_url`, validate the chain and print the leaf's SPKI SHA-256 (not trust-on-first-use). |
| `-log-level` | `info` | `debug`, `info`, `warn` or `error`. |
| `-version` | off | Print the version. |

`-print-facts`, `-print-inventory` and `-once` always run in-process.
