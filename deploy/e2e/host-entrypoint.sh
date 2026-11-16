#!/bin/sh
# Simulated host: unique machine-id, agent config from env, optional sshd tweak,
# one agent check-in, then idle so the test can `docker compose exec` re-runs.
set -eu
: "${PANOPTES_SERVER_URL:?}" "${PANOPTES_ENROLL_TOKEN:?}" "${HOST_LABELS:?}" "${HOST_MACHINE_ID:?}"

echo "$HOST_MACHINE_ID" > /etc/machine-id
mkdir -p /etc/panoptes /run/sshd /var/lib/panoptes-agent

if [ -n "${SSHD_EXTRA:-}" ]; then
  printf '%s\n' "$SSHD_EXTRA" >> /etc/ssh/sshd_config
fi

labels=$(printf '%s' "$HOST_LABELS" | sed 's/,/, /g')
umask 077
cat > /etc/panoptes/agent.yaml <<YAML
server_url: ${PANOPTES_SERVER_URL}
enroll_token: "${PANOPTES_ENROLL_TOKEN}"
labels: [${labels}]
state_dir: /var/lib/panoptes-agent
allow_insecure_http: true   # test network only; production requires https
YAML

sshd -T >/dev/null  # fail early if sshd_config is broken
panoptes-agent -once || echo "initial agent run failed" >&2
touch /tmp/agent-first-run-done
exec sleep infinity
