-- Timestamps are UTC, formatted as 2006-01-02T15:04:05Z, so they sort as text.

CREATE TABLE users (
    id           INTEGER PRIMARY KEY,
    name         TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    github_login TEXT    COLLATE NOCASE,
    is_admin     INTEGER NOT NULL DEFAULT 0 CHECK (is_admin IN (0, 1)),
    disabled_at  TEXT,
    created_at   TEXT    NOT NULL
) STRICT;

CREATE TABLE keys (
    id                 INTEGER PRIMARY KEY,
    user_id            INTEGER NOT NULL REFERENCES users (id),
    fingerprint_sha256 TEXT    NOT NULL UNIQUE,
    public_key         TEXT    NOT NULL, -- "<type> <base64>", no comment
    key_type           TEXT    NOT NULL,
    source             TEXT    NOT NULL CHECK (source IN ('manual', 'github')),
    added_at           TEXT    NOT NULL,
    last_used_at       TEXT
) STRICT;

CREATE INDEX keys_user_id ON keys (user_id);

-- detail NEVER contains secret values.
CREATE TABLE audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              TEXT    NOT NULL,
    user_id         INTEGER REFERENCES users (id),
    key_fingerprint TEXT,
    remote_addr     TEXT    NOT NULL,
    action          TEXT    NOT NULL,
    target          TEXT    NOT NULL DEFAULT '',
    result          TEXT    NOT NULL CHECK (result IN ('ok', 'denied', 'error')),
    detail          TEXT    NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX audit_log_ts ON audit_log (ts);

-- The audit log is append-only, enforced by the database as well as the code.
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;
