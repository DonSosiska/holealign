#!/usr/bin/env bash
# Panoptes end-to-end test: real Matrix homeserver, real server, three simulated hosts.
# See README.md. Usage: deploy/e2e/run.sh
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
START=$SECONDS

for bin in docker curl jq openssl; do
  command -v "$bin" >/dev/null || { echo "missing required tool: $bin" >&2; exit 2; }
done

# ---- configuration -----------------------------------------------------------
export E2E_MATRIX_PORT="${E2E_MATRIX_PORT:-18008}"
export E2E_SERVER_PORT="${E2E_SERVER_PORT:-18080}"
export E2E_ADMIN_PORT="${E2E_ADMIN_PORT:-18081}"
export E2E_REG_TOKEN
E2E_REG_TOKEN="e2e-$(openssl rand -hex 8)"
export PANOPTES_ADMIN_PASSWORD
PANOPTES_ADMIN_PASSWORD="$(openssl rand -hex 12)"
WAIT_TIMEOUT="${E2E_WAIT_TIMEOUT:-180}"
KEEP="${E2E_KEEP:-0}"
HS="http://127.0.0.1:${E2E_MATRIX_PORT}"
SRV="http://127.0.0.1:${E2E_SERVER_PORT}"
ADMIN="http://127.0.0.1:${E2E_ADMIN_PORT}"   # admin web UI listener (the agent API port serves no UI)
BOT_PASS="$(openssl rand -hex 12)"
OBS_PASS="$(openssl rand -hex 12)"

export E2E_TMP; E2E_TMP="$(mktemp -d)"
export E2E_FEEDS_UPDATE=true
if [[ -n "${GRYPE_DB_CACHE:-}" ]]; then
  [[ -d "$GRYPE_DB_CACHE" ]] || { echo "GRYPE_DB_CACHE=$GRYPE_DB_CACHE is not a directory" >&2; exit 2; }
  export E2E_GRYPE_MOUNT; E2E_GRYPE_MOUNT="$(cd "$GRYPE_DB_CACHE" && pwd)"
  E2E_FEEDS_UPDATE=false
fi

dc() { docker compose -f "$DIR/docker-compose.yml" --profile server --profile hosts "$@"; }

# ---- result bookkeeping ---------------------------------------------------------
RESULTS=()
FAILED=0
pass() { RESULTS+=("PASS  $1"); echo "  PASS: $1"; }
fail() { RESULTS+=("FAIL  $1"); FAILED=1; echo "  FAIL: $1" >&2; }
die()  { echo "FATAL: $*" >&2; exit 1; }

FINISHED=""
cleanup() {
  local rc=$?
  if [[ -z "$FINISHED" && $rc -ne 0 ]]; then
    echo "--- aborted (rc=$rc); panoptes-server log tail ---" >&2
    dc logs --no-color --tail 60 panoptes-server >&2 2>&1 || true
  fi
  if [[ "$KEEP" == 1 ]]; then
    echo "E2E_KEEP=1: leaving the stack running (docker compose -f $DIR/docker-compose.yml --profile server --profile hosts down -v)"
  else
    dc down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  rm -rf "$E2E_TMP"
}
trap cleanup EXIT

# ---- Matrix helpers --------------------------------------------------------------
uri() { jq -rn --arg s "$1" '$s|@uri'; }

register() { # user pass token -> prints access token
  local user=$1 pass=$2 tok=$3 r session
  r=$(curl -sS -X POST "$HS/_matrix/client/v3/register" -H 'Content-Type: application/json' -d '{}')
  session=$(jq -r '.session // empty' <<<"$r")
  [[ -n "$session" ]] || die "register $user: no UIA session: $r"
  r=$(curl -sS -X POST "$HS/_matrix/client/v3/register" -H 'Content-Type: application/json' -d "$(jq -n \
      --arg u "$user" --arg p "$pass" --arg t "$tok" --arg s "$session" \
      '{username:$u,password:$p,inhibit_login:false,auth:{type:"m.login.registration_token",token:$t,session:$s}}')")
  if [[ -z "$(jq -r '.access_token // empty' <<<"$r")" ]]; then # some servers want a dummy stage too
    r=$(curl -sS -X POST "$HS/_matrix/client/v3/register" -H 'Content-Type: application/json' -d "$(jq -n \
        --arg u "$user" --arg p "$pass" --arg s "$session" \
        '{username:$u,password:$p,auth:{type:"m.login.dummy",session:$s}}')")
  fi
  jq -er '.access_token' <<<"$r" || die "register $user failed: $r"
}

mx() { # token method path [json]
  local tok=$1 method=$2 path=$3 body=${4:-}
  curl -fsS -X "$method" "$HS/_matrix/client/v3$path" -H "Authorization: Bearer $tok" \
    -H 'Content-Type: application/json' ${body:+-d "$body"}
}

create_room() { # name -> room id (bot creates, observer invited + joins)
  local name=$1 id
  id=$(mx "$BOT_TOKEN" POST /createRoom "$(jq -n --arg n "$name" --arg o "$OBS_MXID" \
        '{name:$n,preset:"private_chat",invite:[$o]}')" | jq -er '.room_id')
  mx "$OBS_TOKEN" POST "/join/$(uri "$id")" '{}' >/dev/null
  echo "$id"
}

room_bodies() { # room id -> JSON array of message bodies (newest first)
  mx "$OBS_TOKEN" GET "/rooms/$(uri "$1")/messages?dir=b&limit=50" |
    jq -c '[.chunk[] | select(.type=="m.room.message") | .content.body]'
}

# count_msgs ROOM JQ-EXPR  (expr gets one body as input, must yield boolean)
count_msgs() { room_bodies "$1" | jq "[.[] | select($2)] | length"; }

transcript() { # room name, room id
  echo "---- transcript of room '$1' ($2) ----" >&2
  room_bodies "$2" | jq -r 'reverse | .[] | "* " + gsub("\n"; "\n  ")' >&2 || true
  echo "---- end ----" >&2
}

wait_for() { # description timeout cmd...  (cmd succeeds when ready)
  local timeout=$2; shift 2
  local end=$((SECONDS + timeout))
  until "$@"; do
    (( SECONDS < end )) || return 1
    sleep 3
  done
}

# message predicates (jq) ---------------------------------------------------------
EXPLOIT='(contains("CVE-2024-6387") and contains("EXPLOITABLE"))'
RESOLVED='(contains("CVE-2024-6387") and contains("RESOLVED"))'
has_expl() { [[ "$(count_msgs "$1" "$EXPLOIT and contains(\"$2\")")" -ge 1 ]]; }
has_resolved() { [[ "$(count_msgs "$1" "$RESOLVED and contains(\"$2\")")" -ge 1 ]]; }
counts() { local r; for r in "$ROOM_PROD" "$ROOM_STAGING" "$ROOM_DEFAULT"; do room_bodies "$r" | jq length; done | paste -sd, -; }

# ---- 1. build + homeserver ---------------------------------------------------------
echo "== building images (server, host) and starting Matrix homeserver"
dc up -d matrix >/dev/null &
UP_PID=$!
dc build panoptes-server web-default
wait "$UP_PID" || die "homeserver failed to start"

wait_for homeserver 90 curl -fsS "$HS/_matrix/client/versions" -o /dev/null || die "homeserver did not come up"
echo "   homeserver up"

echo "== registering users and creating rooms"
# Continuwuity prints a one-time bootstrap registration token on first start; the configured
# token only works after the first account exists. Use the bootstrap token for the first user.
BOOT_TOKEN=$(dc logs --no-color matrix 2>&1 | sed $'s/\x1b\\[[0-9;]*m//g' | sed -n 's/.*using the registration token \([A-Za-z0-9]*\).*/\1/p' | head -1)
BOT_TOKEN=$(register e2ebot "$BOT_PASS" "${BOOT_TOKEN:-$E2E_REG_TOKEN}")
OBS_TOKEN=$(register e2eobserver "$OBS_PASS" "$E2E_REG_TOKEN")
OBS_MXID="@e2eobserver:panoptes.test"
ROOM_PROD=$(create_room prod)
ROOM_STAGING=$(create_room staging)
ROOM_DEFAULT=$(create_room default)
echo "   prod=$ROOM_PROD staging=$ROOM_STAGING default=$ROOM_DEFAULT"

# ---- 2. panoptes-server ------------------------------------------------------------
cat > "$E2E_TMP/server.yaml" <<YAML
matrix:
  routes:
    - {label: prod, rooms: ["$ROOM_PROD"]}
    - {label: staging, rooms: ["$ROOM_STAGING"]}
YAML
export E2E_BOT_TOKEN="$BOT_TOKEN" E2E_ROOM_DEFAULT="$ROOM_DEFAULT"

echo "== starting panoptes-server (feeds.update=$E2E_FEEDS_UPDATE${GRYPE_DB_CACHE:+, grype cache $GRYPE_DB_CACHE})"
dc up -d panoptes-server >/dev/null
wait_for server 90 curl -fsS "$SRV/healthz" -o /dev/null || die "panoptes-server did not become healthy"

E2E_ENROLL_TOKEN=$(dc exec -T panoptes-server panoptes-server token create e2e 2>/dev/null | grep -Eo '^pt_[A-Za-z0-9_-]+' | head -1)
[[ -n "$E2E_ENROLL_TOKEN" ]] || die "could not create enrollment token"
export E2E_ENROLL_TOKEN

# ---- 3. hosts ------------------------------------------------------------------------
echo "== starting hosts"
dc up -d web-default web-lgt0 staging-1 >/dev/null

first_runs_done() {
  local h
  for h in web-default web-lgt0 staging-1; do
    dc exec -T "$h" test -f /tmp/agent-first-run-done 2>/dev/null || return 1
  done
}
wait_for agents 120 first_runs_done || die "agents did not finish their first run"
echo "   agents done; waiting up to ${WAIT_TIMEOUT}s for findings in Matrix"

both_alerts() { has_expl "$ROOM_PROD" web-default && has_expl "$ROOM_STAGING" staging-1; }
T0=$SECONDS
if wait_for alerts "$WAIT_TIMEOUT" both_alerts; then
  echo "   alerts arrived after $((SECONDS - T0))s"
else
  echo "   timed out waiting for alerts" >&2
fi
sleep 10 # let any (wrongly) additional messages arrive before asserting

# ---- 4. assertions ---------------------------------------------------------------------
echo "== assertions"
dump=0

# a
n=$(count_msgs "$ROOM_PROD" "$EXPLOIT")
good=$(count_msgs "$ROOM_PROD" "$EXPLOIT and contains(\"web-default\") and contains(\"openssh-server\") and contains(\"apt-get install --only-upgrade\")")
if [[ "$n" == 1 && "$good" == 1 ]]; then
  pass "a. prod room: exactly one EXPLOITABLE CVE-2024-6387 message for web-default (openssh-server, apt-get fix)"
else
  fail "a. prod room: expected exactly one EXPLOITABLE CVE-2024-6387 message for web-default with openssh-server + 'apt-get install --only-upgrade' (EXPLOITABLE messages: $n, fully matching: $good)"; dump=1
fi

# b
nb=0
for r in "$ROOM_PROD" "$ROOM_STAGING" "$ROOM_DEFAULT"; do
  nb=$((nb + $(count_msgs "$r" "$EXPLOIT and contains(\"web-lgt0\")")))
done
if [[ "$nb" == 0 ]]; then pass "b. no EXPLOITABLE message for web-lgt0 (LoginGraceTime 0) in any room"
else fail "b. found $nb EXPLOITABLE CVE-2024-6387 message(s) mentioning web-lgt0"; dump=1; fi

# c
if has_expl "$ROOM_STAGING" staging-1 && [[ "$(count_msgs "$ROOM_PROD" 'contains("staging-1")')" == 0 ]]; then
  pass "c. staging-1 alert in staging room, none in prod"
else
  fail "c. expected EXPLOITABLE for staging-1 in staging room and nothing about staging-1 in prod"; dump=1
fi

# d: re-run agents and restart the server (re-runs the whole pipeline) -> no new messages
before=$(counts)
rerun_ok=1
for h in web-default web-lgt0 staging-1; do
  dc exec -T "$h" panoptes-agent -once >/dev/null 2>&1 || { echo "   agent re-run on $h failed" >&2; rerun_ok=0; }
done
sleep 15
dc restart panoptes-server >/dev/null 2>&1
wait_for server 90 curl -fsS "$SRV/healthz" -o /dev/null || die "panoptes-server did not come back after restart"
sleep 30
after=$(counts)
if [[ "$rerun_ok" == 1 && "$before" == "$after" ]]; then pass "d. dedup: agent re-run + server restart produced no new messages (counts prod,staging,default = $before)"
elif [[ "$rerun_ok" != 1 ]]; then fail "d. dedup: an agent re-run failed (see above); identical inventories must be accepted"; dump=1
else fail "d. dedup: message counts (prod,staging,default) changed from $before to $after"; dump=1; fi

# e: fix flow
echo "   fixing web-default (upgrade openssh-server from current Debian repos)"
if dc exec -T web-default bash -c '
      set -e
      printf "%s\n" "deb http://deb.debian.org/debian bookworm main" \
                    "deb http://deb.debian.org/debian-security bookworm-security main" > /etc/apt/sources.list
      rm -f /etc/apt/apt.conf.d/99snapshot
      apt-get update -qq
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --only-upgrade openssh-server
      dpkg-query -W openssh-server' >"$E2E_TMP/upgrade.log" 2>&1; then
  echo "   upgraded: $(tail -1 "$E2E_TMP/upgrade.log")"
else
  echo "   upgrade failed:" >&2; tail -20 "$E2E_TMP/upgrade.log" >&2
fi
dc exec -T web-default panoptes-agent -once >/dev/null 2>&1 || echo "   agent re-run after upgrade failed" >&2
if wait_for resolved 120 has_resolved "$ROOM_PROD" web-default; then
  pass "e. fix flow: RESOLVED message for web-default arrived in prod"
else
  fail "e. fix flow: no RESOLVED CVE-2024-6387 message for web-default in prod within 120s"; dump=1
fi

# f: web UI smoke
JAR="$E2E_TMP/cookies"
code=$(curl -s -o "$E2E_TMP/login.html" -w '%{http_code}' -c "$JAR" "$ADMIN/login")
csrf=$(grep -Eo 'name="csrf" value="[^"]+"' "$E2E_TMP/login.html" | sed -E 's/.*value="([^"]+)"/\1/' | head -1 || true)
if [[ "$code" != 200 ]]; then
  fail "f. web: GET /login returned $code"
elif [[ -z "$csrf" ]]; then
  fail "f. web: no CSRF token on /login"
else
  lcode=$(curl -s -o /dev/null -w '%{http_code}' -b "$JAR" -c "$JAR" --data-urlencode "csrf=$csrf" \
    --data-urlencode "username=admin" --data-urlencode "password=$PANOPTES_ADMIN_PASSWORD" "$ADMIN/login")
  fcode=$(curl -s -o "$E2E_TMP/findings.html" -w '%{http_code}' -b "$JAR" "$ADMIN/findings?q=CVE-2024-6387&resolved=1")
  if [[ "$lcode" == 303 && "$fcode" == 200 ]] && grep -q 'web-default' "$E2E_TMP/findings.html"; then
    pass "f. web: /login 200, form login 303, /findings?q=CVE-2024-6387 200 and lists web-default"
  else
    fail "f. web: login=$lcode findings=$fcode, web-default occurrences: $(grep -c web-default "$E2E_TMP/findings.html" || true)"
  fi
fi

if [[ "$dump" == 1 ]]; then
  transcript prod "$ROOM_PROD"; transcript staging "$ROOM_STAGING"; transcript default "$ROOM_DEFAULT"
  dc logs --no-color --tail 40 panoptes-server >&2 2>&1 || true
fi

# ---- 5. summary --------------------------------------------------------------------------
FINISHED=1
echo
echo "================ E2E SUMMARY ================"
printf '%s\n' "${RESULTS[@]}"
echo "runtime: $((SECONDS - START))s"
if [[ "$FAILED" == 0 ]]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; exit 1; fi
