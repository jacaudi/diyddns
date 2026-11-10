-- +goose Up
-- +goose StatementBegin
-- #175: server-directed credential rotation. rotate_secret_at and
-- rotate_cert_at are unix seconds when an admin requested a rotation on that
-- track; NULL means none pending. pending_secret_hash is sealed exactly like
-- secret_hash (auth.SealSecret), so promotion is a column copy.
-- pending_cert_serial is lowercase hex. There is no pending_cert_not_after:
-- promotion writes the presented leaf's NotAfter into cert_not_after.
-- supports_rotation records that the client advertised the rotation
-- capability; last_checkin_mtls records whether its last check-in arrived
-- over mTLS.
ALTER TABLE devices ADD COLUMN rotate_secret_at INTEGER;
ALTER TABLE devices ADD COLUMN rotate_cert_at INTEGER;
ALTER TABLE devices ADD COLUMN pending_secret_hash TEXT;
ALTER TABLE devices ADD COLUMN pending_cert_serial TEXT;
ALTER TABLE devices ADD COLUMN supports_rotation INTEGER NOT NULL DEFAULT 0;
ALTER TABLE devices ADD COLUMN last_checkin_mtls INTEGER NOT NULL DEFAULT 0;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE devices DROP COLUMN last_checkin_mtls;
ALTER TABLE devices DROP COLUMN supports_rotation;
ALTER TABLE devices DROP COLUMN pending_cert_serial;
ALTER TABLE devices DROP COLUMN pending_secret_hash;
ALTER TABLE devices DROP COLUMN rotate_cert_at;
ALTER TABLE devices DROP COLUMN rotate_secret_at;
-- +goose StatementEnd
