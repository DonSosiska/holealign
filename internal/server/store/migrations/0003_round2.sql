-- Round 2: re-enroll TTL, per-target skip marker, retention indexes.
ALTER TABLE hosts ADD COLUMN reenroll_allowed_until INTEGER NOT NULL DEFAULT 0;
UPDATE hosts SET reenroll_allowed_until = (CAST(strftime('%s','now') AS INTEGER) + 3600) * 1000 WHERE reenroll_allowed <> 0;
ALTER TABLE targets ADD COLUMN skipped TEXT NOT NULL DEFAULT '';
CREATE INDEX findings_resolved_seen ON findings(verdict, last_seen);
CREATE INDEX notifications_sent_at ON notifications_sent(sent_at);
