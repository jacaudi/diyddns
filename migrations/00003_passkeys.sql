-- +goose Up
-- +goose StatementBegin
CREATE TABLE webauthn_credentials (
    credential_id   BLOB PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_json BLOB NOT NULL,
    name            TEXT NOT NULL,
    aaguid          BLOB,
    created_at      INTEGER NOT NULL,
    last_used_at    INTEGER
);
CREATE INDEX webauthn_credentials_user ON webauthn_credentials(user_id);

ALTER TABLE users ADD COLUMN webauthn_handle BLOB;
CREATE UNIQUE INDEX users_webauthn_handle ON users(webauthn_handle);

CREATE TABLE account_recovery_tokens (
    token_hash   TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reason       TEXT NOT NULL,
    expires_at   INTEGER NOT NULL,
    used_at      INTEGER
);
CREATE INDEX account_recovery_tokens_expires ON account_recovery_tokens(expires_at);

-- Local password auth is removed (Plan 10 flip): passkeys + OIDC only. Drop
-- the now-unused password_hash column. The Down block re-adds the column
-- (schema-reversible) but cannot restore the hashes — data is not recoverable.
ALTER TABLE users DROP COLUMN password_hash;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE users ADD COLUMN password_hash TEXT;
DROP TABLE IF EXISTS account_recovery_tokens;
DROP INDEX IF EXISTS users_webauthn_handle;
ALTER TABLE users DROP COLUMN webauthn_handle;
DROP TABLE IF EXISTS webauthn_credentials;
-- +goose StatementEnd
