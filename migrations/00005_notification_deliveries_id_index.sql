-- +goose Up
-- +goose StatementBegin
-- ListByEndpoint (internal/store/notifications.go) ordered by
-- created_at DESC, id DESC, which the (endpoint_id) index below cannot
-- satisfy, forcing SQLite to materialise and sort every row for the
-- endpoint before applying LIMIT (confirmed via EXPLAIN QUERY PLAN:
-- "USE TEMP B-TREE FOR ORDER BY"). id is INTEGER PRIMARY KEY AUTOINCREMENT
-- and created_at is set once at insert, so ordering by id DESC alone is
-- equivalent, and a composite (endpoint_id, id) index lets SQLite walk it
-- directly with no temp b-tree, on the process-wide single-connection
-- database (store.SetMaxOpenConns(1)).
--
-- The old single-column index is dropped rather than kept alongside the new
-- one: every current query that filters on endpoint_id alone (this one) or
-- on (endpoint_id, id) can use the composite index equally well, and no
-- query in this package filters on endpoint_id together with any other
-- leading column the old index would have served better — keeping both
-- would just be a second index with the same leading column, maintained on
-- every insert/delete for no query it uniquely serves.
DROP INDEX notification_deliveries_endpoint;
CREATE INDEX notification_deliveries_endpoint_id
    ON notification_deliveries(endpoint_id, id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX notification_deliveries_endpoint_id;
CREATE INDEX notification_deliveries_endpoint
    ON notification_deliveries(endpoint_id);
-- +goose StatementEnd
