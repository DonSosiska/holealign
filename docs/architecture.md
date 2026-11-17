# Architecture

Panoptes has two kinds of process. On every monitored host a privilege-separated agent (a root
collector with no network, and an unprivileged sender) pushes an inventory and configuration facts
to the server. The server matches vulnerabilities, evaluates rules, and alerts. This page describes
the components, the data flow, who may do what, and where data lives. Protocol-level detail is in
[contracts.md](contracts.md).

Contents: [Components](#components) - [Data flow](#data-flow) - [Privilege separation](#privilege-separation) -
[Trust boundaries](#trust-boundaries) - [What each process may do](#what-each-process-may-do) -
[Where data is stored](#where-data-is-stored)

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
                                                   | feed updater (Grype DB, KEV, EPSS)         |
                                                   | retention job (daily)                      |
                                                   | Matrix notifier  ---> Matrix homeserver    |
                                                   | LLM drafter (optional) ---> LLM API, OSV   |
                                                   +--------------------------------------------+
                                                       SQLite (panoptes.db) + Grype DB cache
```

| Component | Binary and unit | Runs as | Network |
|---|---|---|---|
| Collector | `panoptes-agent -mode collector`, `panoptes-collector.service` | root, capabilities `CAP_DAC_READ_SEARCH`, `CAP_DAC_OVERRIDE`, `CAP_SYS_PTRACE` | none (`PrivateNetwork=yes`, AF_UNIX only) |
| Sender | `panoptes-agent -mode sender`, `panoptes-agent.service` | user `panoptes`, no capabilities | outbound to the server only |
| Server | `panoptes-server serve`, `panoptes-server.service` or container | unprivileged dynamic user (systemd) or uid 65532 (container) | listens on `:8080` and `127.0.0.1:8081` |
| Agentless local agent | inside the server process | the server's user | none; reads the collector socket or scans in-process |

The agent has a third mode, `-mode all` (the default): one process doing both roles. It is used by
`-once`, by containers and by the end-to-end tests. See [Privilege separation](#privilege-separation).

The agentless local agent is new: the server can monitor its own host without a separately enrolled
agent. See [installation.md](installation.md#agentless-mode).

## Data flow

1. **Enroll.** The sender sends the enrollment token, hostname, machine ID and labels. The server
   checks the token (hash lookup, expiry, `max_hosts`), creates the host, and returns an
   `agent_id` and `agent_key`. The sender stores them in `state_dir`. After the first successful
   check-in the collector blanks `enroll_token` in `agent.yaml`.
2. **Check-in** (every 5 minutes by default). The sender asks the collector for facts and OS
   info and sends them. The server answers with `fact_requests` (extra `file.match` reads wanted
   by reviewed rules), `want_inventory`, and optionally a different interval (the agent clamps it
   to 60 s - 1 h).
3. **Inventory.** The collector runs Syft on the host root filesystem and on each Docker image,
   producing CycloneDX SBOMs. The sender uploads them gzip-compressed when the package databases
   or image set change (and every 6 hours as a safety net), or when the server asks.
4. **Match and decide.** After an inventory, a fact change, a rule change or a vulnerability-DB
   update, the pipeline runs Grype on each target SBOM, then evaluates the rule that covers each
   finding against the host's facts. The result is stored as a finding with a verdict and a
   reason.
5. **Alert.** The pipeline compares each finding with its stored state and emits events
   (`exploitable`, `unknown_critical`, `resolved`). The health loop emits silence, feed and
   pipeline events. The Matrix notifier routes events to rooms by host label.
6. **Draft rules** (optional). A finding without a rule that is High/Critical or on the KEV list
   is queued for the LLM drafter. The draft is stored with status `draft` and is inert until a
   human approves it.

The agent only connects out. Nothing on the monitored host listens for the server.

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

## Where data is stored

| Data | Location | Notes |
|---|---|---|
| Server database (hosts, findings, rules, tokens, users, sessions, notification dedup, settings) | `<data_dir>/panoptes.db` (default `/var/lib/panoptes`) | SQLite, WAL, file mode 0600, server `umask 077`. Only SHA-256 hashes of enrollment tokens, agent keys and session tokens; bcrypt password hashes. |
| Grype vulnerability DB (includes KEV, EPSS) | `<data_dir>/grype-db/` | Downloaded and refreshed every `feeds.interval`; about 100 MB. |
| Rules shipped with the release | `rules_dir` (default `/usr/share/panoptes/rules`) | Read at start. DB rules (LLM drafts, edits in the UI) override a file rule with the same ID. |
| Matrix label routes edited in the UI | database, setting `matrix.routes` | Merged with `matrix.routes` from `server.yaml`. |
| Agent credentials | `<state_dir>/` (default `/var/lib/panoptes-agent`) | `agent_id`, `agent_key`; owned by `panoptes`, mode 0700 directory. |
| Agent configuration | `/etc/panoptes/agent.yaml` | `root:panoptes`, 0640. Holds the enrollment token until the first successful check-in. |
| Server configuration | `/etc/panoptes/server.yaml`, secrets in `/etc/panoptes/server.env` | The env file holds the admin password, Matrix token, LLM key (0600). |
| Facts and inventory | server database only | The agent does not keep a copy besides in-memory caches in the collector. |

Backup and retention: [operations.md](operations.md#backup-and-restore).
