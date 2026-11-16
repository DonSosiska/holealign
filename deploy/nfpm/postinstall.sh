#!/bin/sh
# Package postinstall: reload systemd so the new unit is visible.
# Deliberately does NOT enable or start the service: the agent needs server_url
# and an enroll token first; the server needs its secrets first.
set -e
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi
