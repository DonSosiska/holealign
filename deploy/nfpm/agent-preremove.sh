#!/bin/sh
# holealign-agent preremove: stop and disable both services on removal (not on upgrade).
# deb passes "remove", rpm passes 0 for a final removal.
set -e
case "${1:-}" in
    remove|0)
        if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
            systemctl disable --now holealign-agent.service holealign-collector.service >/dev/null 2>&1 || true
        fi
        ;;
esac
