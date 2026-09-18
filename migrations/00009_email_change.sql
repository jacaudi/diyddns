-- +goose Up
-- +goose StatementBegin
-- #131: a self-service email change is PENDING until the new address confirms
-- (design D2/D4). The pending change lives on the users row -- one pending
-- change per account by construction, and confirm-and-apply is a single
-- conditional UPDATE (store.UserRepo.ConfirmPendingEmail), so there is no
-- "token consumed but address not applied" window to log as CRITICAL. The
-- three columns are always all NULL or all non-NULL. No index: every lookup
-- that touches the token hash also filters on the primary key.
ALTER TABLE users ADD COLUMN pending_email            TEXT;
ALTER TABLE users ADD COLUMN pending_email_token_hash TEXT;
ALTER TABLE users ADD COLUMN pending_email_expires_at INTEGER;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE users DROP COLUMN pending_email_expires_at;
ALTER TABLE users DROP COLUMN pending_email_token_hash;
ALTER TABLE users DROP COLUMN pending_email;
-- +goose StatementEnd
