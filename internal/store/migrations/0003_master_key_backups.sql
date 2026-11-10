-- One row per master key whose backup the operator has confirmed with
-- `ssshhh-env admin confirm-backup`. Holds key ids only, never key material.
CREATE TABLE master_key_backups (
    key_id       TEXT NOT NULL PRIMARY KEY,
    confirmed_at TEXT NOT NULL
) STRICT;
