# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

First public state of the project. No tagged release yet.

### Changed

- `matrix.default_rooms`, `matrix.routes[].rooms` and `alerts.ops_rooms` are deprecated aliases of
  `notify.default`, `notify.routes[].to` and `notify.ops`: still accepted, merged, with one WARN at startup.
  Routes edited in the web UI are stored with the key `to` (rows with the old key `rooms` still load).
  A Matrix destination now requires `matrix.homeserver` (previously rooms without a homeserver were
  silently ignored). The settings page is titled "Notification routes".
- The project is renamed from Panoptes to Holealign: Go module path
  `github.com/DonSosiska/holealign`, binaries `holealign-agent` and `holealign-server`, systemd units
  `holealign-*.service`, system user `holealign`, environment prefix `HOLEALIGN_`, paths
  `/etc/holealign`, `/var/lib/holealign`, `/run/holealign`, `/usr/share/holealign`, container image
  `ghcr.io/donsosiska/holealign-server`, and the rules feed at
  `https://donsosiska.github.io/holealign-rules/latest.json`. There is no compatibility layer for the
  old names. The salt of the hashed machine ID is unchanged, so hosts keep their identity.

### Added

- Server: notifications go through a channel abstraction. Routing targets are destinations, strings
  `scheme:target`; a destination without a known scheme is a Matrix room, so existing configs and stored
  routes keep working. New channels: Slack (`slack:<channel ID>`, bot token with `chat:write`,
  `chat.postMessage`, mrkdwn, no unfurling) and Telegram (`telegram:<chat_id>[/<topic>]`, Bot API HTML,
  4096 character limit respected, link previews off). Config: new `notify:` section (`default`, `routes[].to`,
  `ops`), `slack.token_env`, `telegram.bot_token_env`; every destination is validated at load and in the web
  UI (unknown scheme, malformed target or unconfigured channel is an error). Retry with `Retry-After`,
  burst summaries, partial-delivery memory and delivery-problem banner work per destination for every
  channel. Untrusted text is escaped per channel and mentions are neutralised. API base URLs are constants.
- Agent: privilege-separated Linux agent. A root collector with no network access reads host state
  and serves it on a unix socket; an unprivileged sender is the only process that talks to the
  server. `-mode all` keeps the single-process behaviour for `-once`, containers and tests.
- Agent: configuration facts (OS and libc, kernel modules and sysctl, services, listening sockets,
  sshd, nginx, Apache, PHP, OpenSSL, Docker, runc, sudo) and bounded `file.match` reads with a strict
  allowlist, denylist and secret masking.
- Agent: host and Docker image inventory with Syft (CycloneDX SBOMs), change detection, per-scan
  time limits.
- Agent: server identity checks: TLS 1.2+, private CA as the only trust root, SPKI pinning, optional
  mTLS, `-print-server-pin`.
- Server: HTTP API for enrollment, check-in and inventory, with per-host and per-client rate limits.
- Server: vulnerability matching with Grype, including KEV and EPSS, and a CEL rule engine with the
  verdicts `exploitable`, `affected_not_exploitable`, `conditions_unknown`, `not_affected` and
  `resolved`. Eight shipped rules.
- Server: optional LLM rule drafting (Anthropic or OpenAI-compatible); drafts are inert until a human
  approves them and can never lower a verdict.
- Server: Matrix/Element alerts routed by host labels, with grouping, deduplication, burst summaries,
  a grace period for unknown findings, and delivery-problem reporting.
- Server: health alerts for silent agents, a stale vulnerability feed and a failing pipeline.
- Server: admin web UI (hosts, findings, rule review, enrollment tokens, Matrix routes, users) on a
  separate listener, loopback by default.
- Server: native TLS options, trusted reverse proxies, retention and per-host limits, SQLite storage.
- Packaging: `install.sh` with cosign verification, `.deb` and `.rpm` packages, systemd units, a
  distroless server image, Docker Compose file, and an end-to-end test with a real Matrix homeserver.
- Releases: GoReleaser build, keyless cosign signatures, SPDX SBOMs, build provenance, gated by a
  protected `release` environment and tags on `main`.
- Documentation: README (English and Ukrainian) and operator documentation in `docs/`.
- Agentless mode: the server can monitor its own host through a built-in local agent, with no
  separate `holealign-agent` and no enrollment token (`local_agent.*`, off by default). Data comes from
  the root collector socket (`source: collector`), from the server process (`source: inprocess`), or
  is picked at start (`source: auto`). The host is marked "local (built-in)" in the web UI. The server's
  own `data_dir` is never scanned. `install.sh --collector-only` installs just the collector and the
  `holealign` user for this mode.

### Changed

- License: PolyForm Noncommercial License 1.0.0 (source-available; commercial use needs a separate
  license). Package metadata uses `PolyForm-Noncommercial-1.0.0`.

### Security

- Audit round 1: hardened web authentication, sessions and audit logging; made LLM drafts inert and
  introduced the `file.match` policy and rule precedence; hardened the server API, enrollment,
  limits and notifier; hardened the agent (`file.match`, transport, scans, installer); supply chain
  pinning, signed releases, SBOMs and provenance.
- Audit round 2: drafts never lower verdicts and must be grounded in host facts; strict `file.match`
  policy; strict SBOM validation, per-target failure isolation, limiter and retention fixes;
  login throttling without lock-out, password re-authentication for sensitive actions, delivery
  problem reporting and silence routing; masked secret matching, exec trust checks, collector
  robustness and systemd unit changes; gated releases, pinned tooling and exact signing identity.
