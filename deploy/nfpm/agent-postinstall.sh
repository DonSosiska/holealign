#!/bin/sh
# panoptes-agent postinstall: config readable by the sender (root:panoptes 0640), reload systemd
# and ENABLE (not start) both services. They are started by the operator once agent.yaml has
# server_url and an enroll token: systemctl start panoptes-collector panoptes-agent
set -e
if [ -f /etc/panoptes/agent.yaml ]; then
    chgrp panoptes /etc/panoptes/agent.yaml
    chmod 0640 /etc/panoptes/agent.yaml
fi
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    systemctl enable panoptes-collector.service panoptes-agent.service >/dev/null 2>&1 || true
fi
