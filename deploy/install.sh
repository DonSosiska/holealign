#!/bin/sh
# Panoptes agent installer (Linux with systemd, root required).
#
#   curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/OWNER/panoptes/main/deploy/install.sh | \
#     sudo PANOPTES_ENROLL_TOKEN=pt_xxx sh -s -- --server https://panoptes.example.com --labels prod,web
#
# Options:
#   --server URL      panoptes-server base URL (https://, no user:password@). Required on first install.
#   --token-file PATH read the enrollment token (from `panoptes-server token create`) from PATH.
#   --token TOKEN     enrollment token; visible in `ps` and shell history, prefer --token-file or
#                     the PANOPTES_ENROLL_TOKEN environment variable. One of the three is required
#                     on first install.
#   --allow-insecure-http  accept an http:// --server (testing only).
#   --labels a,b      comma-separated labels (optional).
#   --ca-file PATH    PEM bundle of the CA(s) that sign the server certificate. It is copied to
#                     /etc/panoptes/ca.pem and, when set, ONLY these roots are trusted.
#   --server-pin HEX  pin the server: hex SHA-256 of the server certificate's SubjectPublicKeyInfo
#                     (see `panoptes-agent -print-server-pin`). Repeatable.
#   --skip-signature-check  install without verifying the release signature (not recommended).
#                     Without this flag the install aborts if cosign is not installed.
#   --version VER     release to install, e.g. 1.2.3 or v1.2.3 (default: latest).
#   --binary PATH     install this local panoptes-agent binary instead of downloading (air-gapped).
#   --force           overwrite an existing /etc/panoptes/agent.yaml.
#                     With --uninstall, also remove the config and state.
#   --uninstall       stop the service and remove the unit and binary (/usr/bin and the old
#                     /usr/local/bin location).
#   -h, --help        show this help.
#
# Environment:
#   PANOPTES_REPO     GitHub repository to download from (default: OWNER/panoptes).
#   PANOPTES_ENROLL_TOKEN  enrollment token (alternative to --token-file).
#
# The token is written to the config file only and is never printed.
# The systemd units below are identical to deploy/systemd/panoptes-agent.service and
# panoptes-collector.service (a test compares them). Keep them in sync.
#
# Privilege separation: panoptes-collector (root, no network) reads the host and serves it on
# /run/panoptes/collector.sock; panoptes-agent (user "panoptes") talks to the server.
#
# Release verification: checksums.txt is verified with cosign (keyless Sigstore signature
# made by this repository's release workflow) before any checksum is trusted. Without
# cosign, install the .deb/.rpm (verify them as described in the README) or pass
# --skip-signature-check.

set -eu

REPO="${PANOPTES_REPO:-OWNER/panoptes}"
VERSION="latest"
SERVER=""
TOKEN="${PANOPTES_ENROLL_TOKEN:-}"
TOKEN_FILE=""
ALLOW_HTTP=0
LABELS=""
CA_FILE=""
PINS=""
SKIP_SIG=0
BINARY_SRC=""
FORCE=0
UNINSTALL=0

BIN_PATH="/usr/bin/panoptes-agent"
OLD_BIN_PATH="/usr/local/bin/panoptes-agent" # group-writable on some distros; removed on install/uninstall
CA_DEST="/etc/panoptes/ca.pem"
CONF_DIR="/etc/panoptes"
CONF_FILE="/etc/panoptes/agent.yaml"
UNIT_NAME="panoptes-agent"
UNIT_PATH="/etc/systemd/system/panoptes-agent.service"
COLLECTOR_UNIT_NAME="panoptes-collector"
COLLECTOR_UNIT_PATH="/etc/systemd/system/panoptes-collector.service"
SVC_USER="panoptes"
STATE_DIR="/var/lib/panoptes-agent"

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

log() {
    printf '==> %s\n' "$*"
}

usage() {
    sed -n '2,43p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//' || true
}

# --- argument parsing -------------------------------------------------------

while [ $# -gt 0 ]; do
    case "$1" in
        --server)
            [ $# -ge 2 ] || die "--server needs a value"
            SERVER="$2"; shift 2 ;;
        --token)
            [ $# -ge 2 ] || die "--token needs a value"
            printf 'warning: --token is visible in the process list and shell history; use --token-file or PANOPTES_ENROLL_TOKEN\n' >&2
            TOKEN="$2"; shift 2 ;;
        --token-file)
            [ $# -ge 2 ] || die "--token-file needs a path"
            TOKEN_FILE="$2"; shift 2 ;;
        --allow-insecure-http)
            ALLOW_HTTP=1; shift ;;
        --labels)
            [ $# -ge 2 ] || die "--labels needs a value"
            LABELS="$2"; shift 2 ;;
        --ca-file)
            [ $# -ge 2 ] || die "--ca-file needs a path"
            CA_FILE="$2"; shift 2 ;;
        --server-pin)
            [ $# -ge 2 ] || die "--server-pin needs a value"
            PINS="$PINS $2"; shift 2 ;;
        --skip-signature-check)
            SKIP_SIG=1; shift ;;
        --version)
            [ $# -ge 2 ] || die "--version needs a value"
            VERSION="$2"; shift 2 ;;
        --binary)
            [ $# -ge 2 ] || die "--binary needs a path"
            BINARY_SRC="$2"; shift 2 ;;
        --force)
            FORCE=1; shift ;;
        --uninstall)
            UNINSTALL=1; shift ;;
        -h|--help)
            usage; exit 0 ;;
        *)
            die "unknown option: $1 (see --help)" ;;
    esac
done

printf '%s\n' "$REPO" | grep -Eq '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' || die "PANOPTES_REPO must look like owner/name"

[ "$(id -u)" -eq 0 ] || die "must run as root (use sudo)"
[ "$(uname -s)" = "Linux" ] || die "only Linux is supported"
command -v systemctl >/dev/null 2>&1 || die "systemd (systemctl) is required"

# --- uninstall --------------------------------------------------------------

if [ "$UNINSTALL" -eq 1 ]; then
    log "stopping and disabling $UNIT_NAME and $COLLECTOR_UNIT_NAME"
    systemctl disable --now "$UNIT_NAME" >/dev/null 2>&1 || true
    systemctl disable --now "$COLLECTOR_UNIT_NAME" >/dev/null 2>&1 || true
    rm -f "$UNIT_PATH" "$COLLECTOR_UNIT_PATH" "$BIN_PATH" "$OLD_BIN_PATH"
    systemctl daemon-reload || true
    if [ "$FORCE" -eq 1 ]; then
        log "removing $CONF_FILE and $STATE_DIR"
        rm -f "$CONF_FILE" "$CA_DEST"
        rm -rf "${STATE_DIR:?}"
        rmdir "$CONF_DIR" 2>/dev/null || true
        if id "$SVC_USER" >/dev/null 2>&1; then
            userdel "$SVC_USER" >/dev/null 2>&1 || true
        fi
    else
        log "kept $CONF_FILE and $STATE_DIR (use --uninstall --force to remove them)"
    fi
    log "panoptes-agent removed"
    exit 0
fi

# --- validate input ---------------------------------------------------------

CONFIG_EXISTS=0
[ -f "$CONF_FILE" ] && CONFIG_EXISTS=1
WRITE_CONFIG=0
if [ "$CONFIG_EXISTS" -eq 0 ] || [ "$FORCE" -eq 1 ]; then
    WRITE_CONFIG=1
fi
# the config holds the enrollment token: readable by root and the service group only
if [ "$CONFIG_EXISTS" -eq 1 ]; then
    chown root:"$SVC_USER" "$CONF_FILE"
    chmod 0640 "$CONF_FILE"
fi

if [ "$WRITE_CONFIG" -eq 1 ]; then
    [ -n "$SERVER" ] || die "--server is required"
    case "$SERVER" in
        https://*) ;;
        http://*) [ "$ALLOW_HTTP" -eq 1 ] || die "--server must use https:// (or pass --allow-insecure-http for testing)" ;;
        *) die "--server must start with https://" ;;
    esac
    server_authority="${SERVER#*://}"
    server_authority="${server_authority%%/*}"
    case "$server_authority" in
        *@*) die "--server must not contain user:password@" ;;
    esac
    case "$SERVER" in
        *[!A-Za-z0-9._:/~%@+-]*) die "--server contains unsupported characters" ;;
    esac
    if [ -n "$TOKEN_FILE" ]; then
        [ -f "$TOKEN_FILE" ] || die "--token-file: file not found: $TOKEN_FILE"
        TOKEN="$(tr -d ' \t\r\n' < "$TOKEN_FILE")"
    fi
    [ -n "$TOKEN" ] || die "an enrollment token is required (--token-file PATH or PANOPTES_ENROLL_TOKEN)"
    case "$TOKEN" in
        *[!A-Za-z0-9_-]*) die "--token has an invalid format" ;;
    esac
    if [ -n "$CA_FILE" ]; then
        [ -f "$CA_FILE" ] || die "--ca-file: file not found: $CA_FILE"
        grep -q -- '-----BEGIN CERTIFICATE-----' "$CA_FILE" || die "--ca-file: no PEM certificate found in $CA_FILE"
    fi
    for pin in $PINS; do
        pin_clean="$(printf '%s' "$pin" | tr -d ':' | tr 'A-F' 'a-f')"
        case "$pin_clean" in
            *[!0-9a-f]*) die "--server-pin must be hexadecimal (SHA-256 of the SPKI): $pin" ;;
        esac
        [ "${#pin_clean}" -eq 64 ] || die "--server-pin must be 64 hex characters (SHA-256): $pin"
    done
    if [ -n "$LABELS" ]; then
        case "$LABELS" in
            *[!A-Za-z0-9._,-]*) die "--labels may contain only letters, digits, '.', '_', '-' and ','" ;;
        esac
        case ",$LABELS," in
            *,,*) die "--labels contains an empty label" ;;
        esac
    fi
fi

case "$VERSION" in
    *[!A-Za-z0-9._-]*) die "--version has an invalid format" ;;
esac

case "$(uname -m)" in
    x86_64|amd64)  ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) die "unsupported architecture: $(uname -m)" ;;
esac

# --- prerequisites ----------------------------------------------------------

detect_pm() {
    for pm in apt-get dnf yum zypper pacman; do
        if command -v "$pm" >/dev/null 2>&1; then
            printf '%s\n' "$pm"
            return 0
        fi
    done
    printf 'none\n'
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

ensure_prerequisites() {
    missing=""
    for t in curl tar; do
        command -v "$t" >/dev/null 2>&1 || missing="$missing $t"
    done
    if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
        missing="$missing sha256sum"
    fi
    [ -z "$missing" ] && return 0

    PM="$(detect_pm)"
    log "installing missing tools:$missing (package manager: $PM)"
    case "$PM" in
        apt-get)
            apt-get update -qq
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl ca-certificates tar coreutils ;;
        dnf|yum)
            "$PM" install -y -q curl ca-certificates tar coreutils ;;
        zypper)
            zypper --non-interactive install curl ca-certificates tar coreutils ;;
        pacman)
            pacman -Sy --needed --noconfirm curl ca-certificates tar coreutils ;;
        *)
            die "missing required tools:$missing and no supported package manager found" ;;
    esac
}

ensure_prerequisites

# verify_signature checks the keyless Sigstore signature of checksums.txt: it must come from
# this repository's release workflow on a v* tag. Aborts on failure.
verify_signature() {
    if [ "$SKIP_SIG" -eq 1 ]; then
        printf 'warning: --skip-signature-check: the release signature is NOT verified; only the sha256 from the same download origin is checked\n' >&2
        return 0
    fi
    if ! command -v cosign >/dev/null 2>&1; then
        die "cosign is not installed, so the release signature cannot be verified.
  Install cosign (https://docs.sigstore.dev/cosign/system_config/installation/) and run this again,
  install the signed .deb/.rpm package instead (see README, \"Verifying releases\"),
  or pass --skip-signature-check to accept the unverified download (not recommended)."
    fi
    log "verifying the release signature with cosign"
    cosign verify-blob --certificate "$TMP/checksums.txt.pem" --signature "$TMP/checksums.txt.sig" \
        --certificate-identity-regexp "^https://github.com/${REPO}/\.github/workflows/release\.yml@refs/tags/v" \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com \
        "$TMP/checksums.txt" || die "release signature verification FAILED; refusing to install"
    log "release signature verified"
}

# --- service user -----------------------------------------------------------

# The sender runs as this unprivileged user; the collector (root) shares its group for the socket.
if ! id "$SVC_USER" >/dev/null 2>&1; then
    log "creating system user $SVC_USER"
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER" \
        || die "cannot create the system user $SVC_USER"
fi

# --- get the binary ---------------------------------------------------------

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP:?}"' EXIT INT TERM

if [ -n "$BINARY_SRC" ]; then
    [ -f "$BINARY_SRC" ] || die "--binary: file not found: $BINARY_SRC"
    log "installing local binary"
    install -o root -g root -m 0755 "$BINARY_SRC" "$BIN_PATH"
else
    if [ "$VERSION" = "latest" ]; then
        log "resolving latest release of $REPO"
        final_url="$(curl --proto '=https' --tlsv1.2 -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest")" \
            || die "cannot resolve the latest release of $REPO"
        TAG="${final_url##*/}"
    else
        case "$VERSION" in
            v*) TAG="$VERSION" ;;
            *)  TAG="v$VERSION" ;;
        esac
    fi
    case "$TAG" in
        v[0-9]*) ;;
        *) die "no release found for '$VERSION' in $REPO" ;;
    esac
    VER="${TAG#v}"
    ASSET="panoptes-agent_${VER}_linux_${ARCH}.tar.gz"
    BASE="https://github.com/$REPO/releases/download/$TAG"

    log "downloading panoptes-agent $TAG ($ARCH)"
    curl --proto '=https' --tlsv1.2 -fsSL -o "$TMP/$ASSET" "$BASE/$ASSET" || die "download failed: $ASSET"
    curl --proto '=https' --tlsv1.2 -fsSL -o "$TMP/checksums.txt" "$BASE/checksums.txt" || die "download failed: checksums.txt"
    if [ "$SKIP_SIG" -eq 0 ]; then
        curl --proto '=https' --tlsv1.2 -fsSL -o "$TMP/checksums.txt.sig" "$BASE/checksums.txt.sig" || die "download failed: checksums.txt.sig"
        curl --proto '=https' --tlsv1.2 -fsSL -o "$TMP/checksums.txt.pem" "$BASE/checksums.txt.pem" || die "download failed: checksums.txt.pem"
    fi

    verify_signature

    expected="$(awk -v f="$ASSET" '$2 == f {print $1; exit}' "$TMP/checksums.txt")"
    [ -n "$expected" ] || die "no checksum listed for $ASSET"
    actual="$(sha256_of "$TMP/$ASSET")"
    [ "$actual" = "$expected" ] || die "sha256 mismatch for $ASSET (expected $expected, got $actual)"
    log "sha256 verified"

    tar -xzf "$TMP/$ASSET" -C "$TMP" panoptes-agent
    install -o root -g root -m 0755 "$TMP/panoptes-agent" "$BIN_PATH"
fi
# an older install put the binary in /usr/local/bin; do not leave a stale copy behind
rm -f "$OLD_BIN_PATH"

"$BIN_PATH" -version >/dev/null || die "installed binary does not run: $BIN_PATH"
log "installed $("$BIN_PATH" -version) to $BIN_PATH"

# --- configuration ----------------------------------------------------------

if [ "$WRITE_CONFIG" -eq 1 ]; then
    if [ -n "$LABELS" ]; then
        yaml_labels="$(printf '%s' "$LABELS" | awk -F, '{
            s = ""
            for (i = 1; i <= NF; i++) s = s (i > 1 ? ", " : "") "\"" $i "\""
            printf "[%s]", s
        }')"
    else
        yaml_labels="[]"
    fi

    mkdir -p "$CONF_DIR"
    chmod 0755 "$CONF_DIR"
    old_umask="$(umask)"
    umask 077
    tmp_conf="$CONF_FILE.tmp.$$"
    cat > "$tmp_conf" <<EOF
# Written by install.sh. See deploy/agent.yaml.example for all keys.
server_url: "$SERVER"
enroll_token: "$TOKEN"
labels: $yaml_labels
state_dir: $STATE_DIR
EOF
    if [ "$ALLOW_HTTP" -eq 1 ]; then
        printf 'allow_insecure_http: true\n' >> "$tmp_conf"
    fi
    if [ -n "$CA_FILE" ]; then
        install -o root -g "$SVC_USER" -m 0640 "$CA_FILE" "$CA_DEST"
        printf 'ca_file: %s\n' "$CA_DEST" >> "$tmp_conf"
    fi
    if [ -n "$PINS" ]; then
        yaml_pins=""
        for pin in $PINS; do
            pin_clean="$(printf '%s' "$pin" | tr -d ':' | tr 'A-F' 'a-f')"
            yaml_pins="${yaml_pins:+$yaml_pins, }\"$pin_clean\""
        done
        printf 'server_cert_sha256: [%s]\n' "$yaml_pins" >> "$tmp_conf"
    fi
    chown root:"$SVC_USER" "$tmp_conf"
    chmod 0640 "$tmp_conf"
    mv -f "$tmp_conf" "$CONF_FILE"
    umask "$old_umask"
    log "wrote $CONF_FILE (root:$SVC_USER, mode 0640)"
else
    log "keeping existing $CONF_FILE (use --force to overwrite)"
    if [ -n "$SERVER" ] || [ -n "$TOKEN" ] || [ -n "$LABELS" ]; then
        log "warning: --server, --token and --labels were not applied"
    fi
fi

# --- systemd unit -----------------------------------------------------------

umask 022
cat > "$COLLECTOR_UNIT_PATH" <<'EOF'
[Unit]
Description=Panoptes collector (root, no network: reads host state, serves it on a unix socket)
Documentation=https://github.com/OWNER/panoptes/blob/main/docs/contracts.md
After=docker.service

[Service]
Type=simple
# Root, because it must run sshd -T, nginx -T, read all package databases and docker.sock.
# It parses untrusted local files (configs, package databases, container images), so it has
# NO network: it only listens on /run/panoptes/collector.sock. The network-facing half is
# panoptes-agent.service, which runs unprivileged as user "panoptes".
User=root
# Group panoptes + UMask 0007 + RuntimeDirectoryMode 0750: /run/panoptes is root:panoptes 0750 and the
# socket root:panoptes 0660, so only root and the panoptes user can reach it (the collector also
# checks SO_PEERCRED).
Group=panoptes
ExecStart=/usr/bin/panoptes-agent -mode collector -config /etc/panoptes/agent.yaml
Restart=always
RestartSec=10

RuntimeDirectory=panoptes
RuntimeDirectoryMode=0750
UMask=0007

# No network at all. PrivateNetwork=yes puts the service in an empty network namespace;
# IPAddressDeny=any and AF_UNIX only are belt and braces.
#
# Consequence: /proc/net/tcp is per network namespace and would be empty here, which would make
# the `sockets.listening` fact silently wrong. We keep PrivateNetwork and instead read
# /proc/1/net/* (the host network namespace of PID 1, readable by root with CAP_SYS_PTRACE,
# which is kept below) in -mode collector. Socket inode -> process mapping still works because
# inode numbers are global. If /proc/1/net is unreadable the sockets facts are omitted
# (unknown) rather than reported empty. The alternative (no private namespace, only
# IPAddressDeny=any and AF_UNIX) also blocks all IP traffic but leaves the process in the host
# namespace; the empty namespace is the stronger isolation, so we pay for it with /proc/1/net.
PrivateNetwork=yes
IPAddressDeny=any
RestrictAddressFamilies=AF_UNIX

# Hardening that keeps read access to the whole system. The collector needs to read
# everything, so ProtectHome and ProtectProc are deliberately not set.
ProtectSystem=strict
PrivateTmp=yes
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
PrivateDevices=yes
SystemCallArchitectures=native
# DAC_READ_SEARCH/DAC_OVERRIDE: read root-only files and open docker.sock;
# SYS_PTRACE: resolve /proc/*/fd socket inodes of other users' processes and read /proc/1/net.
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE CAP_SYS_PTRACE
AmbientCapabilities=
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @mount
# NOTE: child processes (sshd -T, nginx -T, php -i, apachectl, systemctl, ...) inherit
# these limits. Verify on a real host that every collector still works
# (run `panoptes-agent -print-facts` under `systemd-run` with the same properties).

# Resource limits: scans must not disturb the host.
Nice=10
IOSchedulingClass=idle
CPUQuota=50%
MemoryMax=1G

[Install]
WantedBy=multi-user.target
EOF
cat > "$UNIT_PATH" <<'EOF'
[Unit]
Description=Panoptes agent (unprivileged sender: talks to the server)
Documentation=https://github.com/OWNER/panoptes/blob/main/docs/contracts.md
Wants=network-online.target
Requires=panoptes-collector.service
After=network-online.target panoptes-collector.service

[Service]
Type=simple
# Unprivileged: the only process with network access. It gets facts and inventory from the root
# collector (panoptes-collector.service) over /run/panoptes/collector.sock and never reads
# untrusted local files itself.
User=panoptes
Group=panoptes
ExecStart=/usr/bin/panoptes-agent -mode sender -config /etc/panoptes/agent.yaml
Restart=always
RestartSec=10

# State (agent_id, agent_key) lives in /var/lib/panoptes-agent, owned by panoptes; state_dir in
# agent.yaml must match. /etc/panoptes/agent.yaml is root:panoptes 0640 (group-readable by this
# service; it holds the enroll token). ca_file/client_cert/client_key must be readable by group panoptes.
StateDirectory=panoptes-agent
StateDirectoryMode=0700
UMask=0077

ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @mount

Nice=10
CPUQuota=25%
MemoryMax=512M

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$UNIT_PATH" "$COLLECTOR_UNIT_PATH"

# state from an older (root) install becomes owned by the service user; systemd also does this
# for StateDirectory=, this keeps a manual run working too
if [ -d "$STATE_DIR" ]; then
    chown -R "$SVC_USER":"$SVC_USER" "$STATE_DIR" 2>/dev/null || true
fi

systemctl daemon-reload
systemctl enable --now "$COLLECTOR_UNIT_NAME" "$UNIT_NAME"
# Restart so an upgraded binary or a rewritten config takes effect.
systemctl restart "$COLLECTOR_UNIT_NAME" "$UNIT_NAME"

log "panoptes-collector (root, no network) and panoptes-agent (user $SVC_USER) are running"
log "follow the logs with: journalctl -u panoptes-agent -u panoptes-collector -f"
