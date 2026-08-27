-- +goose Up
-- +goose StatementBegin
CREATE TABLE notification_endpoints (
    id                TEXT PRIMARY KEY,
    user_id           TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label             TEXT NOT NULL,
    url               TEXT NOT NULL,
    secret_sealed     TEXT NOT NULL,
    enabled           INTEGER NOT NULL DEFAULT 1,
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL,
    UNIQUE(user_id, url)
);
CREATE INDEX notification_endpoints_user ON notification_endpoints(user_id);

CREATE TABLE notification_deliveries (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint_id       TEXT NOT NULL REFERENCES notification_endpoints(id) ON DELETE CASCADE,
    event_type        TEXT NOT NULL,
    event_id          INTEGER NOT NULL,
    payload           BLOB NOT NULL,
    attempts          INTEGER NOT NULL DEFAULT 0,
    next_attempt_at   INTEGER,
    status            TEXT NOT NULL,
    last_failure      TEXT,
    user_initiated_at INTEGER,
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL
);
CREATE INDEX notification_deliveries_endpoint
    ON notification_deliveries(endpoint_id);
CREATE INDEX notification_deliveries_next_attempt
    ON notification_deliveries(next_attempt_at)
    WHERE next_attempt_at IS NOT NULL;
CREATE INDEX notification_deliveries_user_initiated
    ON notification_deliveries(endpoint_id, user_initiated_at)
    WHERE user_initiated_at IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE notification_deliveries;
DROP TABLE notification_endpoints;
-- +goose StatementEnd
