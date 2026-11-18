#!/bin/sh
# holealign-agent preinstall: create the unprivileged system user the sender runs as.
# The collector (root) shares its group to reach the socket.
#
# A pre-existing "holealign" must be a plain system account (uid 100-999, no login shell);
# a real user or a low static system id is not taken over: the install aborts instead.
set -e
if id holealign >/dev/null 2>&1; then
    uid="$(id -u holealign)"
    shell="$(getent passwd holealign 2>/dev/null | cut -d: -f7)"
    case "$uid" in
        ''|*[!0-9]*) uid=-1 ;;
    esac
    shell_ok=0
    case "$shell" in
        ''|*/nologin|*/false) shell_ok=1 ;;
    esac
    if [ "$uid" -lt 100 ] || [ "$uid" -ge 1000 ] || [ "$shell_ok" -ne 1 ]; then
        echo "holealign-agent: the existing user 'holealign' is not a plain system account (uid $uid, shell '$shell'); expected a uid between 100 and 999 and a nologin shell. Remove or fix that user and install again." >&2
        exit 1
    fi
else
    useradd --system --no-create-home --shell /usr/sbin/nologin holealign
fi
