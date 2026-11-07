-- +goose Up
-- +goose StatementBegin
-- #173: agent mTLS. This table and these columns hold only PUBLIC material:
-- CA certificates (DER) and the serial and expiry of each device's current
-- certificate. Private keys are never stored here; they live on the server's
-- disk (CA, serving key) and on the device (device key).
-- agent_ca is a singleton: the CHECK pins the one row to id = 1, so a second
-- CA row is unrepresentable. active_der signs device certs; backup_der is
-- the standby promoted on rotation.
-- cert_serial is lowercase hex; NULL on both columns means no certificate is
-- recorded for the device. cert_not_after is unix seconds.
CREATE TABLE agent_ca (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    active_der  BLOB NOT NULL,
    backup_der  BLOB NOT NULL,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);

ALTER TABLE devices ADD COLUMN cert_serial TEXT;
ALTER TABLE devices ADD COLUMN cert_not_after INTEGER;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE devices DROP COLUMN cert_not_after;
ALTER TABLE devices DROP COLUMN cert_serial;
DROP TABLE agent_ca;
-- +goose StatementEnd
