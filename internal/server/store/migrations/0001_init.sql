CREATE TABLE hosts (
    id             TEXT PRIMARY KEY,
    machine_id     TEXT NOT NULL UNIQUE,
    hostname       TEXT NOT NULL DEFAULT '',
    labels         TEXT NOT NULL DEFAULT '[]',
    os             TEXT NOT NULL DEFAULT '{}',
    facts          TEXT NOT NULL DEFAULT '{}',
    agent_version  TEXT NOT NULL DEFAULT '',
    inventory_hash TEXT NOT NULL DEFAULT '',
    created_at     INTEGER NOT NULL,
    last_checkin   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE agent_keys (
    key_hash   TEXT PRIMARY KEY,
    host_id    TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL
);
CREATE INDEX agent_keys_host ON agent_keys(host_id);

CREATE TABLE enroll_tokens (
    token_hash TEXT PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    revoked    INTEGER NOT NULL DEFAULT 0,
    last_used  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE targets (
    host_id    TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL,
    name       TEXT NOT NULL,
    image_id   TEXT NOT NULL DEFAULT '',
    containers TEXT NOT NULL DEFAULT '[]',
    sbom       BLOB NOT NULL,
    PRIMARY KEY (host_id, kind, name)
);

CREATE TABLE findings (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id        TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    target         TEXT NOT NULL,
    target_kind    TEXT NOT NULL DEFAULT 'host',
    package_name   TEXT NOT NULL,
    package_version TEXT NOT NULL,
    package_type   TEXT NOT NULL DEFAULT '',
    purl           TEXT NOT NULL DEFAULT '',
    vuln_id        TEXT NOT NULL,
    aliases        TEXT NOT NULL DEFAULT '[]',
    severity       TEXT NOT NULL DEFAULT '',
    cvss           REAL NOT NULL DEFAULT 0,
    epss           REAL NOT NULL DEFAULT 0,
    kev            INTEGER NOT NULL DEFAULT 0,
    fixed_versions TEXT NOT NULL DEFAULT '[]',
    fix_state      TEXT NOT NULL DEFAULT '',
    verdict        TEXT NOT NULL,
    verdict_reason TEXT NOT NULL DEFAULT '',
    rule_id        TEXT NOT NULL DEFAULT '',
    rule_status    TEXT NOT NULL DEFAULT '',
    first_seen     INTEGER NOT NULL,
    last_seen      INTEGER NOT NULL,
    UNIQUE (host_id, target, package_name, package_version, vuln_id)
);
CREATE INDEX findings_verdict ON findings(verdict);
CREATE INDEX findings_vuln_id ON findings(vuln_id);
CREATE INDEX findings_host ON findings(host_id);

CREATE TABLE notifications_sent (
    dedup_key   TEXT PRIMARY KEY,
    finding_key TEXT NOT NULL,
    kind        TEXT NOT NULL,
    sent_at     INTEGER NOT NULL
);
CREATE INDEX notifications_finding ON notifications_sent(finding_key);

CREATE TABLE rules (
    id         TEXT PRIMARY KEY,
    json       TEXT NOT NULL,
    status     TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE users (
    username      TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    created_at    INTEGER NOT NULL
);

CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    username   TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE kv (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);
