-- wrapped_dek is the project's data key, encrypted under the master key
-- named by master_key_id. The master key itself is never in this database.
CREATE TABLE projects (
    id            INTEGER PRIMARY KEY,
    name          TEXT    NOT NULL UNIQUE,
    wrapped_dek   BLOB    NOT NULL,
    dek_nonce     BLOB    NOT NULL,
    master_key_id TEXT    NOT NULL,
    created_by    INTEGER NOT NULL REFERENCES users (id),
    created_at    TEXT    NOT NULL
) STRICT;

CREATE TABLE environments (
    id         INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects (id),
    name       TEXT    NOT NULL,
    created_at TEXT    NOT NULL,
    UNIQUE (project_id, name)
) STRICT;

CREATE TABLE members (
    project_id INTEGER NOT NULL REFERENCES projects (id),
    user_id    INTEGER NOT NULL REFERENCES users (id),
    role       TEXT    NOT NULL CHECK (role IN ('owner', 'writer', 'reader')),
    granted_by INTEGER NOT NULL REFERENCES users (id),
    granted_at TEXT    NOT NULL,
    PRIMARY KEY (project_id, user_id)
) STRICT, WITHOUT ROWID;

CREATE INDEX members_user_id ON members (user_id);

-- ciphertext is the .env file sealed under the project's data key.
-- key_names_json holds variable names only, never values.
CREATE TABLE versions (
    id             INTEGER PRIMARY KEY,
    env_id         INTEGER NOT NULL REFERENCES environments (id),
    version        INTEGER NOT NULL CHECK (version > 0),
    nonce          BLOB    NOT NULL,
    ciphertext     BLOB    NOT NULL,
    size_bytes     INTEGER NOT NULL CHECK (size_bytes >= 0),
    key_names_json TEXT    NOT NULL,
    author_id      INTEGER NOT NULL REFERENCES users (id),
    message        TEXT    NOT NULL DEFAULT '',
    created_at     TEXT    NOT NULL,
    UNIQUE (env_id, version)
) STRICT;

-- History is append-only, enforced by the database as well as the code.
CREATE TRIGGER versions_no_update BEFORE UPDATE ON versions
BEGIN
    SELECT RAISE(ABORT, 'versions is append-only');
END;

CREATE TRIGGER versions_no_delete BEFORE DELETE ON versions
BEGIN
    SELECT RAISE(ABORT, 'versions is append-only');
END;
