-- +goose Up
-- +goose StatementBegin

CREATE TABLE users (
    id              TEXT PRIMARY KEY,
    email           TEXT NOT NULL UNIQUE,
    password_hash   TEXT,
    role            TEXT NOT NULL CHECK (role IN ('admin','user')),
    oidc_provider   TEXT,
    oidc_subject    TEXT,
    disabled        INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    UNIQUE (oidc_provider, oidc_subject)
);

CREATE TABLE sessions (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token      TEXT NOT NULL,
    ip              TEXT,
    user_agent      TEXT,
    created_at      INTEGER NOT NULL,
    last_seen_at    INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL
);
CREATE INDEX sessions_user ON sessions(user_id);
CREATE INDEX sessions_expires ON sessions(expires_at);

CREATE TABLE devices (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label           TEXT NOT NULL,
    secret_hash     TEXT NOT NULL,
    current_ipv4    TEXT,
    current_ipv6    TEXT,
    hostname        TEXT,
    os              TEXT,
    client_version  TEXT,
    last_seen_at    INTEGER,
    disabled        INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    UNIQUE (user_id, label)
);
CREATE INDEX devices_user ON devices(user_id);

CREATE TABLE ip_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id       TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    ipv4            TEXT,
    ipv6            TEXT,
    observed_at     INTEGER NOT NULL,
    client_version  TEXT
);
CREATE INDEX ip_history_device_observed ON ip_history(device_id, observed_at DESC);

CREATE TABLE enrollment_codes (
    code            TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label           TEXT NOT NULL,
    expires_at      INTEGER NOT NULL,
    used_at         INTEGER,
    device_id       TEXT REFERENCES devices(id) ON DELETE SET NULL
);
CREATE INDEX enrollment_codes_expires ON enrollment_codes(expires_at);

CREATE TABLE replay_nonces (
    signature       TEXT PRIMARY KEY,
    expires_at      INTEGER NOT NULL
);
CREATE INDEX replay_nonces_expires ON replay_nonces(expires_at);

CREATE TABLE audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_user_id   TEXT,
    event_type      TEXT NOT NULL,
    target_type     TEXT,
    target_id       TEXT,
    details_json    TEXT,
    ip              TEXT,
    user_agent      TEXT,
    created_at      INTEGER NOT NULL
);
CREATE INDEX audit_log_created ON audit_log(created_at DESC);
CREATE INDEX audit_log_actor ON audit_log(actor_user_id, created_at DESC);

CREATE TABLE bootstrap (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    token_hash      TEXT,
    created_at      INTEGER NOT NULL,
    consumed_at     INTEGER
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS bootstrap;
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS replay_nonces;
DROP TABLE IF EXISTS enrollment_codes;
DROP TABLE IF EXISTS ip_history;
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS users;

-- +goose StatementEnd
