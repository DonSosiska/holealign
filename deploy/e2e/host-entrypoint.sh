#!/bin/sh
# Simulated host: unique machine-id, agent config from env, optional sshd tweak,
# one agent check-in, then idle so the test can `docker compose exec` re-runs.
set -eu
: "${HOLEALIGN_SERVER_URL:?}" "${HOLEALIGN_ENROLL_TOKEN:?}" "${HOST_LABELS:?}" "${HOST_MACHINE_ID:?}"

echo "$HOST_MACHINE_ID" > /etc/machine-id
mkdir -p /etc/holealign /run/sshd /var/lib/holealign-agent

if [ -n "${SSHD_EXTRA:-}" ]; then
  printf '%s\n' "$SSHD_EXTRA" >> /etc/ssh/sshd_config
fi

labels=$(printf '%s' "$HOST_LABELS" | sed 's/,/, /g')
umask 077
cat > /etc/holealign/agent.yaml <<YAML
server_url: ${HOLEALIGN_SERVER_URL}
enroll_token: "${HOLEALIGN_ENROLL_TOKEN}"
labels: [${labels}]
state_dir: /var/lib/holealign-agent
allow_insecure_http: true   # test network only; production requires https
YAML

ssh-keygen -A >/dev/null 2>&1
sshd -T >/dev/null  # fail early if sshd_config is broken
/usr/sbin/sshd
holealign-agent -once || echo "initial agent run failed" >&2
touch /tmp/agent-first-run-done
exec sleep infinity
