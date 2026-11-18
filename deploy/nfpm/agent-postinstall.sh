#!/bin/sh
# holealign-agent postinstall: config readable by the sender (root:holealign 0640), reload systemd
# and ENABLE (not start) both services. They are started by the operator once agent.yaml has
# server_url and an enroll token: systemctl start holealign-collector holealign-agent
set -e
if [ -f /etc/holealign/agent.yaml ]; then
    chgrp holealign /etc/holealign/agent.yaml
    chmod 0640 /etc/holealign/agent.yaml
fi
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    systemctl enable holealign-collector.service holealign-agent.service >/dev/null 2>&1 || true
fi
