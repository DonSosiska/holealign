# Panoptes end-to-end test

One command, needs Docker (Compose v2), `curl`, `jq`, `openssl`:

```sh
deploy/e2e/run.sh
# with a ready Grype DB cache (skips the ~100 MB download):
GRYPE_DB_CACHE=/path/to/grype-db-dir deploy/e2e/run.sh
```

Works on arm64 and amd64 (all images are multi-arch; the Go binaries are built from source
with `CGO_ENABLED=0`).

## What runs

| Service | Image | Role |
|---|---|---|
| `matrix` | `ghcr.io/continuwuity/continuwuity:latest` (conduwuit successor, single binary) | real Matrix homeserver `panoptes.test`, federation off, registration only with a random token, database on tmpfs |
| `panoptes-server` | built from source (`Dockerfile`, target `server`, `golang:1.27` builder) | config via `PANOPTES_*` env + a generated `server.yaml` (Matrix routes) |
| `web-default` | built from source (target `host`) | Debian 12 as of 2024-06-01 (snapshot.debian.org, `Check-Valid-Until=false`), `openssh-server 1:9.2p1-2+deb12u2` + nginx, labels `prod,web`, default sshd config |
| `web-lgt0` | same | labels `prod,web`, `LoginGraceTime 0` appended to `sshd_config` |
| `staging-1` | same | labels `staging`, default config |

Each host writes a unique `/etc/machine-id` and `/etc/panoptes/agent.yaml` from env, runs
`panoptes-agent -once`, then idles so the test can re-run the agent with `docker compose exec`.

`run.sh` registers a bot and an observer user, creates rooms `prod`, `staging`, `default`
(observer joins all), writes `server.yaml` (routes `prod` -> prod room, `staging` -> staging room),
starts the server with the bot token and the default room, creates an enrollment token with
`panoptes-server token create e2e`, starts the hosts and polls the rooms as the observer.

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `GRYPE_DB_CACHE` | unset | Host directory with a ready Grype DB (the dir that contains `6/vulnerability.db`). Mounted at `/var/lib/panoptes/grype-db`, and `PANOPTES_FEEDS_UPDATE=false`. Unset: the server downloads the DB itself (`feeds.update=true`, ~100 MB). |
| `E2E_WAIT_TIMEOUT` | `180` | Seconds to wait for the first alerts. |
| `E2E_KEEP` | `0` | `1` leaves the stack running afterwards (the cleanup trap otherwise runs `docker compose down -v`). |
| `E2E_MATRIX_PORT` / `E2E_SERVER_PORT` | `18008` / `18080` | Host ports (bound to 127.0.0.1). |
| `E2E_ADMIN_PORT` | `18081` | Host port of the admin web UI (container port 8081, bound to 127.0.0.1); used by assertion f. |
| `MATRIX_IMAGE` | `ghcr.io/continuwuity/continuwuity:latest` | Alternative homeserver image (must honour `CONDUWUIT_*` env). |

## Assertions

a. prod room has exactly one message with `CVE-2024-6387` and `EXPLOITABLE`; it names `web-default`, lists `openssh-server` and contains `apt-get install --only-upgrade`.
b. No `EXPLOITABLE` CVE-2024-6387 message in any room mentions `web-lgt0` (LoginGraceTime 0 -> `affected_not_exploitable`).
c. The staging room has the EXPLOITABLE message for `staging-1`; nothing about `staging-1` reaches prod.
d. Dedup: re-running all agents and restarting the server (which re-runs the whole pipeline) adds no messages. A failed agent re-run fails this assertion.
e. Fix flow: on `web-default` apt sources are switched to the current Debian repos, `apt-get install --only-upgrade openssh-server`, agent re-run -> a `RESOLVED` message for CVE-2024-6387 on `web-default` arrives in prod.
f. Web UI: `GET /login` is 200, form login as `admin` (CSRF cookie + hidden field, random `PANOPTES_ADMIN_PASSWORD`) redirects, and `GET /findings?q=CVE-2024-6387` is 200 and lists `web-default`.

On any failure the transcripts of all three rooms and the server log tail are printed. The script
ends with a PASS/FAIL summary per assertion and the total runtime, and exits non-zero on failure.

## Notes

- The host images pull packages from `snapshot.debian.org`; that site is occasionally slow
  (apt retries are configured). The first build takes a few minutes, later runs use the layer cache.
- The fix flow (e) needs internet access to `deb.debian.org` from the `web-default` container.
