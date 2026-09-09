-- +goose Up
-- +goose StatementBegin
-- Endpoints become server-global and admin-managed (#106). Rows created under
-- the per-user model are dropped, not carried over: a URL one user chose must
-- not start receiving every user's events. Deliveries cascade with them.
DELETE FROM notification_endpoints;

CREATE TABLE notification_endpoints_new (
    id            TEXT PRIMARY KEY,
    label         TEXT NOT NULL,
    url           TEXT NOT NULL UNIQUE,
    secret_sealed TEXT NOT NULL,
    enabled       INTEGER NOT NULL DEFAULT 1,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
);
DROP TABLE notification_endpoints;
ALTER TABLE notification_endpoints_new RENAME TO notification_endpoints;

-- The per-user attempt budget goes with the per-user model (design §8.3):
-- its ledger, and the delivery stamp + partial index that only the budget read.
DROP TABLE notification_attempts;
DROP INDEX notification_deliveries_user_initiated;
ALTER TABLE notification_deliveries DROP COLUMN user_initiated_at;

CREATE TABLE feed_tokens (
    id            TEXT PRIMARY KEY,
    label         TEXT NOT NULL UNIQUE,
    token_hash    TEXT NOT NULL UNIQUE,
    created_by    TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at    INTEGER NOT NULL,
    last_used_at  INTEGER
);

CREATE TABLE feed_state (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    seq         INTEGER NOT NULL,
    changed_at  INTEGER NOT NULL
);
INSERT INTO feed_state (id, seq, changed_at) VALUES (1, 0, strftime('%s','now'));
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE feed_state;
DROP TABLE feed_tokens;
ALTER TABLE notification_deliveries ADD COLUMN user_initiated_at INTEGER;
CREATE INDEX notification_deliveries_user_initiated
    ON notification_deliveries(endpoint_id, user_initiated_at)
    WHERE user_initiated_at IS NOT NULL;
CREATE TABLE notification_attempts (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    at      INTEGER NOT NULL
);
CREATE INDEX notification_attempts_user_at ON notification_attempts(user_id, at);
-- Down cannot restore user ownership; it recreates the per-user shape EMPTY,
-- and the DELETE cascades every notification_deliveries row with it.
DELETE FROM notification_endpoints;
CREATE TABLE notification_endpoints_old (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label         TEXT NOT NULL,
    url           TEXT NOT NULL,
    secret_sealed TEXT NOT NULL,
    enabled       INTEGER NOT NULL DEFAULT 1,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL,
    UNIQUE(user_id, url)
);
DROP TABLE notification_endpoints;
ALTER TABLE notification_endpoints_old RENAME TO notification_endpoints;
CREATE INDEX notification_endpoints_user ON notification_endpoints(user_id);
-- +goose StatementEnd
