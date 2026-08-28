-- +goose Up
-- +goose StatementBegin
-- notification_attempts is the ledger the user-initiated outbound-attempt
-- budget (design §10.3) counts. It exists as its own table because the budget
-- previously counted stamped rows in notification_deliveries, whose endpoint_id
-- is ON DELETE CASCADE: a user could delete their endpoint, recreate it, and
-- get a fresh window with zero rows. Measured at 20 attempts in one 5-minute
-- window against a stated cap of 5, unbounded — which falsified §5.8's claim
-- that this budget bounds the residual SSRF/oracle channel.
--
-- Keying the count on the owner instead was necessary but not sufficient: the
-- cascade destroys the evidence regardless of how it is counted (verified — 5
-- stamped rows before the delete, 0 after). So the evidence has to live
-- somewhere endpoint deletion cannot reach.
--
-- The only foreign key is to users, ON DELETE CASCADE, which is correct: with
-- no user there is no budget to enforce. Nothing here references endpoints.
CREATE TABLE notification_attempts (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    at      INTEGER NOT NULL
);
CREATE INDEX notification_attempts_user_at ON notification_attempts(user_id, at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE notification_attempts;
-- +goose StatementEnd
