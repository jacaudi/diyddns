-- +goose Up
-- +goose StatementBegin
CREATE TABLE oidc_device_flows (
    flow_id        TEXT PRIMARY KEY,
    device_code    TEXT NOT NULL,
    interval       INTEGER NOT NULL,
    expires_at     INTEGER NOT NULL,
    last_polled_at INTEGER NOT NULL DEFAULT 0,
    created_at     INTEGER NOT NULL
);
CREATE INDEX oidc_device_flows_expires ON oidc_device_flows(expires_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS oidc_device_flows;
-- +goose StatementEnd
