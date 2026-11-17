#!/bin/sh
# panoptes-agent preinstall: create the unprivileged system user the sender runs as.
# The collector (root) shares its group to reach the socket.
set -e
if ! id panoptes >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin panoptes
fi
