#!/bin/sh
# Integration test of the privilege separation (collector as root, sender as user "panoptes").
# Builds the agent and a fake server for Linux, then runs everything inside a debian:12 container:
#   - the collector runs as root, the sender as the unprivileged user panoptes
#   - facts and inventory must arrive at the fake server through the collector socket
#   - the sender user must not be able to read /etc/shadow itself
# Needs Docker and Go. Usage: deploy/e2e/split-mode.sh
set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

case "$(uname -m)" in
    arm64|aarch64) GOARCH=arm64 ;;
    *) GOARCH=amd64 ;;
esac

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM
export CGO_ENABLED=0 GOOS=linux GOARCH
echo "==> building linux/$GOARCH binaries"
go build -o "$WORK/panoptes-agent" ./cmd/panoptes-agent
go build -o "$WORK/fakeserver" ./deploy/e2e/fakeserver

cat > "$WORK/inner.sh" <<'INNER'
#!/bin/sh
set -eu
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }

PT=/opt/pt/panoptes-agent
useradd --system --no-create-home --shell /usr/sbin/nologin panoptes
echo 0123456789abcdef0123456789abcdef > /etc/machine-id

mkdir -p /etc/panoptes /var/lib/panoptes-agent /run/panoptes /tmp/fakeserver
chown panoptes:panoptes /var/lib/panoptes-agent
chmod 0700 /var/lib/panoptes-agent
chown root:panoptes /run/panoptes
chmod 0750 /run/panoptes
umask 077
cat > /etc/panoptes/agent.yaml <<YAML
server_url: http://127.0.0.1:8099
allow_insecure_http: true
enroll_token: "pt_split_test"
labels: [split]
state_dir: /var/lib/panoptes-agent
collector_socket: /run/panoptes/collector.sock
collector_user: panoptes
checkin_interval: 1m
YAML
chown root:panoptes /etc/panoptes/agent.yaml
chmod 0640 /etc/panoptes/agent.yaml
umask 022

# something listening on a known port: sockets.listening must report it via /proc/1/net
/opt/pt/fakeserver -addr 127.0.0.1:8099 -out /tmp/fakeserver > /tmp/fakeserver.log 2>&1 &

$PT -mode collector -config /etc/panoptes/agent.yaml > /tmp/collector.log 2>&1 &
COLLECTOR_PID=$!
i=0
while [ ! -S /run/panoptes/collector.sock ]; do
    i=$((i + 1)); [ "$i" -lt 50 ] || { cat /tmp/collector.log; fail "collector socket did not appear"; }
    sleep 0.2
done
ok "collector (uid $(awk '/^Uid:/ {print $2}' /proc/$COLLECTOR_PID/status)) listening"
[ "$(stat -c '%a %U:%G' /run/panoptes/collector.sock)" = "660 root:panoptes" ] || fail "socket perms: $(stat -c '%a %U:%G' /run/panoptes/collector.sock)"
ok "socket is root:panoptes 0660"

setpriv --reuid=panoptes --regid=panoptes --init-groups \
    $PT -mode sender -config /etc/panoptes/agent.yaml > /tmp/sender.log 2>&1 &
SENDER_PID=$!

# the sender must not run as root
sleep 1
SENDER_UID="$(awk '/^Uid:/ {print $2}' /proc/$SENDER_PID/status)"
[ "$SENDER_UID" != "0" ] || fail "sender runs as root"
ok "sender process uid is $SENDER_UID (not 0)"

i=0
while [ ! -s /tmp/fakeserver/inventory.json ]; do
    i=$((i + 1)); [ "$i" -lt 600 ] || { echo "--- sender"; cat /tmp/sender.log; echo "--- collector"; cat /tmp/collector.log; fail "inventory did not arrive"; }
    sleep 0.5
done
sleep 1
ok "facts and inventory arrived"

grep -q '"os.id"' /tmp/fakeserver/checkin.json || fail "checkin has no os.id fact"
grep -q '"sockets.ports"' /tmp/fakeserver/checkin.json || fail "checkin has no sockets.ports fact"
grep -q '8099' /tmp/fakeserver/checkin.json || fail "sockets.ports does not contain the fake server port 8099 (/proc/1/net)"
grep -q '"targets"' /tmp/fakeserver/inventory.json || fail "inventory has no targets"
grep -q '"machine_id"' /tmp/fakeserver/enroll.json || fail "enroll has no machine_id"
ok "checkin carries os and sockets facts (port 8099 seen through /proc/1/net); inventory has targets; enroll has machine_id"

# the root collector blanks the enrollment token after the first successful check-in
i=0
while ! grep -q '^enroll_token: ""$' /etc/panoptes/agent.yaml; do
    i=$((i + 1)); [ "$i" -lt 50 ] || { cat /etc/panoptes/agent.yaml; cat /tmp/collector.log; fail "enroll_token was not removed from agent.yaml"; }
    sleep 0.2
done
! grep -q pt_split_test /etc/panoptes/agent.yaml || fail "the enrollment token is still in agent.yaml"
grep -q '^server_url: http://127.0.0.1:8099$' /etc/panoptes/agent.yaml || fail "agent.yaml lost its other content"
[ "$(stat -c '%a %U:%G' /etc/panoptes/agent.yaml)" = "640 root:panoptes" ] || fail "agent.yaml perms changed: $(stat -c '%a %U:%G' /etc/panoptes/agent.yaml)"
ok "enroll_token removed from agent.yaml (content, mode and owner kept)"

[ "$(stat -c '%U' /var/lib/panoptes-agent/credentials.json)" = "panoptes" ] || fail "credentials not owned by panoptes"
ok "credentials stored by the sender in its own state dir"

if setpriv --reuid=panoptes --regid=panoptes --init-groups cat /etc/shadow >/dev/null 2>&1; then
    fail "the panoptes user can read /etc/shadow"
fi
ok "panoptes user cannot read /etc/shadow"

# the sender cannot talk to anything but the collector through the filesystem: a stranger can't connect
if setpriv --reuid=nobody --regid=nogroup --clear-groups $PT -mode sender -once -config /etc/panoptes/agent.yaml >/tmp/stranger.log 2>&1; then
    fail "a user outside the panoptes group could run the sender"
fi
ok "users outside the panoptes group cannot use the collector socket"

kill "$SENDER_PID" "$COLLECTOR_PID" 2>/dev/null || true
echo "SPLIT-MODE OK"
INNER
chmod +x "$WORK/inner.sh"

echo "==> running in debian:12"
docker run --rm -v "$WORK":/opt/pt:ro --cap-add=SYS_PTRACE debian:12 sh /opt/pt/inner.sh
