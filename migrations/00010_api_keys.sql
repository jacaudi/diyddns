-- +goose Up
-- +goose StatementBegin
-- #149: account-scoped API keys. Deliberately a NEW table, not an extension
-- of feed_tokens -- the issue's own "alternatives considered" rejects
-- reusing the feed token mechanism (design D2). user_id is ON DELETE CASCADE
-- (the opposite of feed_tokens.created_by's ON DELETE SET NULL): a feed
-- token outlives the admin who minted it, but an API key IS the issuing
-- user's own authority extended over HTTP, so it must vanish with them.
-- UNIQUE(user_id, label), not a global-unique label: two different users
-- must each be free to call a key "laptop". key_hash carries its own UNIQUE
-- (and therefore an index) because GetByHash is the lookup on every
-- key-authenticated request, on a pool of exactly one SQLite connection.
-- admin_scope exists and defaults to 0 from day one as a deliberate seam
-- for #167 (admin-scoped keys); #149 never sets it to anything but 0.
CREATE TABLE api_keys (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label         TEXT NOT NULL,
    key_hash      TEXT NOT NULL UNIQUE,
    admin_scope   INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL,
    last_used_at  INTEGER,
    UNIQUE(user_id, label)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE api_keys;
-- +goose StatementEnd
