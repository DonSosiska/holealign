# Architecture

Panoptes has two kinds of process. On every monitored host a privilege-separated agent (a root
collector with no network, and an unprivileged sender) pushes an inventory and configuration facts
to the server. The server matches vulnerabilities, evaluates rules, and alerts. This page describes
the components, the data flow, who may do what, and where data lives. Protocol-level detail is in
[contracts.md](contracts.md).

Contents: [Components](#components) - [Data flow](#data-flow) - [Pipeline stages](#pipeline-stages) -
[Concurrency and limits](#concurrency-and-limits) - [Background workers](#background-workers) -
[Privilege separation](#privilege-separation) - [Trust boundaries](#trust-boundaries) -
[What each process may do](#what-each-process-may-do) - [Where data is stored](#where-data-is-stored)

## Components

```
  Monitored host                                       Server (one process, panoptes-server)
 +------------------------------------+            +--------------------------------------------+
 | panoptes-collector   (root)        |            | agent listener  :8080                      |
 |   no network, unix socket only     |            |   POST /api/v1/enroll | checkin | inventory|
 |   facts + Syft inventory           |            |   GET  /healthz                            |
 |        ^                           |   HTTPS    |                                            |
 |        | /run/panoptes/            |  (agent    | admin listener  :8081 (127.0.0.1 default)  |
 |        |   collector.sock          |  initiates)|   web UI, login, rule review, settings     |
 | panoptes-agent -mode sender        | ---------> |                                            |
 |   (user "panoptes")                |            | pipeline: Grype match -> CEL rules -> diff |
 +------------------------------------+            | health loop (silence/feed alerts, 1/min)   |
                                                   | vuln DB updater (Grype DB, KEV, EPSS)      |
                                                   | rules feed poller (optional)               |
                                                   | retention job (daily)                      |
                                                   | local agent (optional, in-process)         |
                                                   | Matrix notifier  ---> Matrix homeserver    |
                                                   | LLM drafter (optional) ---> LLM API, OSV   |
                                                   +--------------------------------------------+
                                                       SQLite (panoptes.db) + Grype DB cache
                                                       + rules feed bundle (data_dir/rules-feed)
```

| Component | Binary and unit | Runs as | Network |
|---|---|---|---|
| Collector | `panoptes-agent -mode collector`, `panoptes-collector.service` | root, capabilities `CAP_DAC_READ_SEARCH`, `CAP_DAC_OVERRIDE`, `CAP_SYS_PTRACE` | none (`PrivateNetwork=yes`, AF_UNIX only) |
| Sender | `panoptes-agent -mode sender`, `panoptes-agent.service` | user `panoptes`, no capabilities | outbound to the server only |
| Server | `panoptes-server serve`, `panoptes-server.service` or container | unprivileged systemd `DynamicUser` (the static `panoptes` user instead when it talks to the collector socket for the local agent) or uid 65532 (container) | listens on `:8080` and `127.0.0.1:8081`; outbound to Matrix, the LLM API, OSV and feed hosts |
| Agentless local agent | inside the server process | the server's user | none; reads the collector socket or scans in-process |

The agent has a third mode, `-mode all` (the default): one process doing both roles. It is used by
`-once`, by containers and by the end-to-end tests. See [Privilege separation](#privilege-separation).

The built-in local agent (agentless mode) lets the server monitor its own host without a separately
enrolled agent. It runs the same agent runner inside the server process and talks to the server's own
agent API through an in-memory transport, so nothing goes over the network. Its data comes from the
root collector's socket (`source: collector`) or from the server process itself (`source: inprocess`).
The server never scans its own `data_dir`. See [installation.md](installation.md#agentless-mode) and
[contracts.md §6](contracts.md#agentless-mode-local_agent).

## Data flow

```
 agent (sender)                 server                                              outside
 --------------                 ------------------------------------------------   -------
 enroll  ------------------->   token check -> host row, key hash
 checkin (facts, os) ------->   merge facts -> store; reply: fact_requests,
                                want_inventory                    (facts changed -> trigger)
 inventory (gzip SBOMs) ---->   validate per target -> store; trigger
                                                    |
                                                    v
                                pipeline: inventory -> match (Grype) -> evaluate (CEL rules)
                                          -> cap -> store/diff -> notify ----------> Matrix rooms
                                                    ^         \
 Grype DB updater ----------(db updated: re-run)----+          -> draft queue ----> LLM (OSV text)
 rules feed poller ---------(bundle installed: re-run)
 web UI rule edits/approvals (rules changed: re-run)
```

1. **Enroll.** The sender sends the enrollment token, hostname, machine ID and labels. The server checks
   the token (hash lookup, expiry, `max_hosts`), creates the host, and returns an `agent_id` and
   `agent_key`. The sender stores them in `state_dir`. After the first successful check-in the collector
   blanks `enroll_token` in `agent.yaml`. Details: [api.md](api.md#enrollment-and-re-enrollment).
2. **Check-in** (every 5 minutes by default). The sender asks the collector for facts and OS info and
   sends them (a full snapshot or a diff). The server merges the facts and answers with `fact_requests`
   (extra `file.match` reads wanted by reviewed rules), `want_inventory`, and `want_full_facts`. The
   response can carry a different interval (`next_checkin_seconds`, clamped by the agent to 60 s - 1 h), but
   the current server never sets it. A fact change triggers the pipeline for that host.
3. **Inventory.** The collector runs Syft on the host root filesystem and on each Docker image, producing
   CycloneDX SBOMs. The sender uploads them gzip-compressed when the package databases or image set change
   (and every 6 hours as a safety net), or when the server asks. An identical hash is a no-op.
4. **Match and decide.** The pipeline runs Grype on each target SBOM, then evaluates the rule that covers
   each finding against the host's facts ([rules.md](rules.md)). See [Pipeline stages](#pipeline-stages).
5. **Alert.** The pipeline compares each finding with its stored state and emits events (`exploitable`,
   `unknown_critical`, `resolved`). The health loop emits silence, feed and pipeline events. The Matrix
   notifier routes events to rooms by host label ([notifications.md](notifications.md)).
6. **Draft rules** (optional). A finding without a rule that is High/Critical or on the KEV list is queued
   for the LLM drafter. The draft is stored with status `draft` and is inert until a human approves it
   ([llm.md](llm.md)).

The agent only connects out. Nothing on the monitored host listens for the server.

## Pipeline stages

A run for one host (`internal/server/pipeline`) is triggered by an inventory upload, a fact change on
check-in, a vulnerability-DB update, or a rules change (web UI, feed bundle, LLM draft). Stages:

| Stage | What happens |
|---|---|
| **Inventory** | The stored target SBOMs of the host (host root plus Docker images) are the input. A target that previously panicked is skipped until a new inventory arrives. |
| **Match** | Grype matches each target SBOM against the local vulnerability DB (offline; the DB includes KEV and EPSS). Each target has its own 5 minute timeout; a target that fails or times out is isolated (its previous findings are carried over, a `pipeline_error` is recorded) and the others still run. A missing DB (right after start) changes nothing and is retried when the DB loads. |
| **Evaluate** | Each finding goes to the rule engine with the host's facts: rule lookup by vulnerability ID or alias and package selector, then the verdict algorithm ([rules.md](rules.md#how-verdicts-are-decided)). |
| **Cap** | Open findings per host are capped (`limits.findings_per_host`, default 20 000) after rule evaluation: exploitable findings are kept first, then `conditions_unknown`, then KEV/severity/CVSS. A dropped finding is never marked resolved and emits no event. |
| **Store** | Upsert keyed by `(host, target, package, version, vuln)`; findings no longer present become `resolved`. The previous verdict is read first, to detect changes. |
| **Notify** | Events for new or changed verdicts go to the notifier with per-event delivery results; only failed events are retried. Findings without a rule and with High/Critical severity or KEV are enqueued for the drafter. |

Each run has a 10 minute timeout, and a panic in any background goroutine is logged and recovered.

## Concurrency and limits

- At most 2 hosts are matched concurrently; slots are granted FIFO.
- Matcher time per host is budgeted per rolling hour (`limits.match_seconds_per_host_hour`, default 900 s);
  over budget the runs are deferred.
- API: per-host token buckets for check-in and inventory, a cheap per-host attempt bucket charged before an
  inventory body is read, one decode in flight per host and `limits.inventory_concurrent_decodes` (4)
  server-wide; per-client limits for invalid enrollments and failed authentication. See
  [api.md](api.md#limits-and-status-codes).
- Collector (on the host): one inventory scan at a time and at most one real scan per 10 minutes, at most 2
  facts collections concurrently, results cached (facts 30 s); excess requests fail with `busy`.
- LLM: queue of 256, daily call limit, per-host and global enqueue caps ([llm.md](llm.md#cost-control)).
- Matrix: bursts of more than 15 messages for one room are summarised ([notifications.md](notifications.md)).
- Everything external is bounded: bodies, SBOM components, facts, notification bodies, feed bundles.
- The server is one process with one SQLite database; there is no clustering.

## Background workers

| Worker | Interval | Job |
|---|---|---|
| Vulnerability DB updater | `feeds.interval` (6 h) | Downloads the Grype DB (with KEV and EPSS) and re-runs the pipeline for all hosts when it changes. Runs once at start. |
| Rules feed poller | `rules.feed.interval` (6 h), only when `rules.feed.enabled` | Fetches `latest.json`, verifies and installs a newer signed bundle, reloads the engine, re-runs the pipeline ([rules-feed.md](rules-feed.md)). The persisted bundle is re-verified at start. |
| Health loop | every minute | `agent_silent` / `agent_back`, `feed_stale` / `feed_ok` (vulnerability DB and rules feed), `pipeline_error`; dedup through the notification table. Held back for twice the check-in interval after start. |
| Notify loop | every 5 minutes | Emits held-back `unknown_critical` alerts and retries undelivered events. |
| Retention job | daily and at start | Deletes resolved findings and notification dedup rows older than `retention.*`. |
| LLM drafter | queue | Drafts rules for uncovered High/Critical/KEV findings, within daily limits. |
| Local agent | `local_agent.checkin_interval` | Optional: the agent runner inside the server process for its own host (below). |

**Health.** Silence alerts name the hosts that stopped checking in; when more than max(5, 30%) of the fleet
goes silent in one pass one aggregated message goes to the ops rooms and one per label to that label's
rooms. The dashboard shows active feed, pipeline and delivery problems.

**Local agent.** With `local_agent.enabled` the server runs the normal agent runner for its own host. It
gets an `http.Client` whose transport calls the agent API handler in memory (no network), enrolls itself by a
direct store call, keeps its key in `data_dir/local-agent/credentials.json`, and takes data from the
collector socket or in-process. All API validation, limits and authentication apply as for a remote agent.

## Privilege separation

Reading sshd, nginx, package databases and the Docker socket needs root. Parsing untrusted local
files (configs, package databases, container images) as root is the risky part. So the work is
split:

- The **collector** (root) parses everything but has no network. It serves results on
  `/run/panoptes/collector.sock` (directory `0750 root:panoptes`, socket `0660 root:panoptes`) and
  checks `SO_PEERCRED`: only root and the `collector_user` may use it. It applies the collection
  policy itself (`file.match` allow/deny lists and budgets, binary trust checks, scan timeouts)
  and rate-limits scans.
- The **sender** (user `panoptes`) holds the agent key, talks to the server, and never reads
  untrusted local files.

A bug in a parser therefore cannot open a connection, and a compromised sender is not root.
A test (`go list -deps`) keeps the collector's code from importing the HTTP transport.

Socket protocol and limits: [contracts.md section 2](contracts.md#2-agent-configuration-etcpanoptesagentyaml).

## Trust boundaries

```
 [attacker-influenced input]          [boundary]                    [trusted by]
 package names, config files   -->  collector (parsers)  -->  sender  (validated, size-capped)
 sender payload (inventory)    -->  server API validation -->  pipeline, SQLite
 server responses              -->  sender hardening      -->  collector requests (filtered)
 advisory text, package names  -->  prompt sanitising     -->  LLM  -->  validator  -->  inert draft
 event text (hostnames, ...)   -->  render sanitising     -->  Matrix message
```

- **Agent does not trust the server.** Only `file.match` requests of a fixed shape are accepted
  from check-in responses; the collector re-applies its own policy; `next_checkin_seconds` and
  `want_inventory` are clamped. The server cannot run commands on a host.
- **Server does not trust agents.** Input is size-limited, schema-checked, rate-limited per host
  and per client address, and an SBOM must be CycloneDX with a bounded component count. Labels
  asserted by an agent are ignored when the enrollment token carries labels.
- **The admin UI is a separate listener.** Monitored hosts reach `:8080`, which serves only
  `/api/v1/*` and `/healthz`; the login page is on `:8081`.
- **LLM output and advisory text are untrusted.** See [llm.md](llm.md) and
  [security-model.md](security-model.md).

## What each process may do

| Capability | Collector | Sender | Server |
|---|---|---|---|
| Read root-only host files (`sshd -T`, package databases, `docker.sock`) | yes | no | no |
| Run helper binaries (`sshd`, `nginx`, `php`, ...) with fixed argv, no shell | yes | no | no |
| Open network connections | no | yes, to `server_url` only | yes: Matrix, LLM, OSV, feed download |
| Hold the agent key | no | yes (`state_dir`, 0600) | stores a SHA-256 hash |
| Rewrite `/etc/panoptes/agent.yaml` | yes, only to blank `enroll_token` | no | no |
| Write the SQLite database | no | no | yes |
| Run commands on a monitored host | n/a | no | cannot |
| Decide verdicts | no | no | yes |
| Approve LLM-drafted rules | no | no | only via the admin UI, after password re-entry |
| Fetch the rules feed | no | no | yes, verified against `rules.feed.trusted_keys` |

## Where data is stored

| Data | Location | Notes |
|---|---|---|
| Server database (hosts, findings, rules, tokens, users, sessions, notification dedup, settings, key-value state such as feed status and health) | `<data_dir>/panoptes.db` (default `/var/lib/panoptes`) | SQLite, WAL, file mode 0600, server `umask 077`. Only SHA-256 hashes of enrollment tokens, agent keys and session tokens; bcrypt password hashes. |
| Grype vulnerability DB (includes KEV, EPSS) | `<data_dir>/grype-db/` | Downloaded and refreshed every `feeds.interval`; about 100 MB. |
| Built-in rules | embedded in the binary; optional `rules_dir` (default `/usr/share/panoptes/rules`) | `rules_dir` adds rules and replaces embedded ones with the same ID; read at start. |
| Signed rules feed bundle | `<data_dir>/rules-feed/` | The accepted bundle and its signature; re-verified at every start. Only when the feed is enabled or a bundle was imported. |
| Local rules (LLM drafts, edits in the UI) | database | Override a built-in or feed rule with the same ID, except that a draft never replaces one. |
| Local agent credentials | `<data_dir>/local-agent/credentials.json` | 0600; only with `local_agent.enabled`. |
| Matrix label routes edited in the UI | database, setting `matrix.routes` | Merged with `matrix.routes` from `server.yaml`. |
| Agent credentials | `<state_dir>/` (default `/var/lib/panoptes-agent`) | `agent_id`, `agent_key`; owned by `panoptes`, mode 0700 directory. |
| Agent configuration | `/etc/panoptes/agent.yaml` | `root:panoptes`, 0640. Holds the enrollment token until the first successful check-in. |
| Server configuration | `/etc/panoptes/server.yaml`, secrets in `/etc/panoptes/server.env` | The env file holds the admin password, Matrix token, LLM key (0600). |
| Facts and inventory | server database only | The agent does not keep a copy besides in-memory caches in the collector. |

Backup and retention: [operations.md](operations.md#backup-and-restore).
