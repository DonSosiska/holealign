#!/bin/sh
# Panoptes agent installer (Linux with systemd, root required).
#
#   curl -fsSL https://raw.githubusercontent.com/OWNER/panoptes/main/deploy/install.sh | \
#     sudo sh -s -- --server https://panoptes.example.com --token pt_xxx --labels prod,web
#
# Options:
#   --server URL      panoptes-server base URL (http:// or https://). Required on first install.
#   --token TOKEN     enrollment token from `panoptes-server token create`. Required on first install.
#   --labels a,b      comma-separated labels (optional).
#   --version VER     release to install, e.g. 1.2.3 or v1.2.3 (default: latest).
#   --binary PATH     install this local panoptes-agent binary instead of downloading (air-gapped).
#   --force           overwrite an existing /etc/panoptes/agent.yaml.
#                     With --uninstall, also remove the config and state.
#   --uninstall       stop the service and remove the unit and binary.
#   -h, --help        show this help.
#
# Environment:
#   PANOPTES_REPO     GitHub repository to download from (default: OWNER/panoptes).
#
# The token is written to the config file only and is never printed.
# The systemd unit below mirrors deploy/systemd/panoptes-agent.service, except that
# the binary lives in /usr/local/bin. Keep the two in sync.

set -eu

REPO="${PANOPTES_REPO:-OWNER/panoptes}"
VERSION="latest"
SERVER=""
TOKEN=""
LABELS=""
BINARY_SRC=""
FORCE=0
UNINSTALL=0

BIN_PATH="/usr/local/bin/panoptes-agent"
CONF_DIR="/etc/panoptes"
CONF_FILE="/etc/panoptes/agent.yaml"
UNIT_NAME="panoptes-agent"
UNIT_PATH="/etc/systemd/system/panoptes-agent.service"
STATE_DIR="/var/lib/panoptes-agent"

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

log() {
    printf '==> %s\n' "$*"
}

usage() {
    sed -n '2,22p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//' || true
}

# --- argument parsing -------------------------------------------------------

while [ $# -gt 0 ]; do
    case "$1" in
        --server)
            [ $# -ge 2 ] || die "--server needs a value"
            SERVER="$2"; shift 2 ;;
        --token)
            [ $# -ge 2 ] || die "--token needs a value"
            TOKEN="$2"; shift 2 ;;
        --labels)
            [ $# -ge 2 ] || die "--labels needs a value"
            LABELS="$2"; shift 2 ;;
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

[ "$(id -u)" -eq 0 ] || die "must run as root (use sudo)"
[ "$(uname -s)" = "Linux" ] || die "only Linux is supported"
command -v systemctl >/dev/null 2>&1 || die "systemd (systemctl) is required"

# --- uninstall --------------------------------------------------------------

if [ "$UNINSTALL" -eq 1 ]; then
    log "stopping and disabling $UNIT_NAME"
    systemctl disable --now "$UNIT_NAME" >/dev/null 2>&1 || true
    rm -f "$UNIT_PATH" "$BIN_PATH"
    systemctl daemon-reload || true
    if [ "$FORCE" -eq 1 ]; then
        log "removing $CONF_FILE and $STATE_DIR"
        rm -f "$CONF_FILE"
        rm -rf "$STATE_DIR"
        rmdir "$CONF_DIR" 2>/dev/null || true
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

if [ "$WRITE_CONFIG" -eq 1 ]; then
    [ -n "$SERVER" ] || die "--server is required"
    case "$SERVER" in
        http://*|https://*) ;;
        *) die "--server must start with http:// or https://" ;;
    esac
    case "$SERVER" in
        *[!A-Za-z0-9._:/~%@+-]*) die "--server contains unsupported characters" ;;
    esac
    [ -n "$TOKEN" ] || die "--token is required"
    case "$TOKEN" in
        *[!A-Za-z0-9_-]*) die "--token has an invalid format" ;;
    esac
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

# --- get the binary ---------------------------------------------------------

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT INT TERM

if [ -n "$BINARY_SRC" ]; then
    [ -f "$BINARY_SRC" ] || die "--binary: file not found: $BINARY_SRC"
    log "installing local binary"
    install -m 0755 "$BINARY_SRC" "$BIN_PATH"
else
    if [ "$VERSION" = "latest" ]; then
        log "resolving latest release of $REPO"
        final_url="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest")" \
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
    curl -fsSL -o "$TMP/$ASSET" "$BASE/$ASSET" || die "download failed: $ASSET"
    curl -fsSL -o "$TMP/checksums.txt" "$BASE/checksums.txt" || die "download failed: checksums.txt"

    expected="$(awk -v f="$ASSET" '$2 == f {print $1; exit}' "$TMP/checksums.txt")"
    [ -n "$expected" ] || die "no checksum listed for $ASSET"
    actual="$(sha256_of "$TMP/$ASSET")"
    [ "$actual" = "$expected" ] || die "sha256 mismatch for $ASSET (expected $expected, got $actual)"
    log "sha256 verified"

    tar -xzf "$TMP/$ASSET" -C "$TMP" panoptes-agent
    install -m 0755 "$TMP/panoptes-agent" "$BIN_PATH"
fi

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
    chmod 0600 "$tmp_conf"
    mv -f "$tmp_conf" "$CONF_FILE"
    umask "$old_umask"
    log "wrote $CONF_FILE (mode 0600)"
else
    log "keeping existing $CONF_FILE (use --force to overwrite)"
    if [ -n "$SERVER" ] || [ -n "$TOKEN" ] || [ -n "$LABELS" ]; then
        log "warning: --server, --token and --labels were not applied"
    fi
fi

# --- systemd unit -----------------------------------------------------------

umask 022
cat > "$UNIT_PATH" <<'EOF'
[Unit]
Description=Panoptes agent (host facts and package inventory)
Wants=network-online.target
After=network-online.target docker.service

[Service]
Type=simple
ExecStart=/usr/local/bin/panoptes-agent -config /etc/panoptes/agent.yaml
Restart=always
RestartSec=10

StateDirectory=panoptes-agent
StateDirectoryMode=0700
ReadWritePaths=/var/lib/panoptes-agent

ProtectSystem=strict
PrivateTmp=yes
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes

Nice=10
IOSchedulingClass=idle
CPUQuota=50%
MemoryMax=1G

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$UNIT_PATH"

systemctl daemon-reload
systemctl enable --now "$UNIT_NAME"
# Restart so an upgraded binary or a rewritten config takes effect.
systemctl restart "$UNIT_NAME"

log "panoptes-agent is running"
log "follow the logs with: journalctl -u panoptes-agent -f"
