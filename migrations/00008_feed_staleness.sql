-- +goose Up
-- +goose StatementBegin
-- #127: the gateway feed must expire a device that has stopped confirming an
-- address. Each address family expires on its own clock (D5), measured from a
-- per-family confirmation instant (D6) rather than the device-level
-- last_seen_at -- a host that loses IPv6 but keeps reporting IPv4 is never
-- silent, so last_seen_at would leave its stale IPv6 prefix in the feed
-- forever.
--
-- Expiry CLEARS current_ipv4/current_ipv6 (D7) rather than flagging them, so
-- no visibility column is needed here and the feed query, the membership
-- predicate and every payload renderer stay untouched.
ALTER TABLE devices ADD COLUMN v4_confirmed_at INTEGER;
ALTER TABLE devices ADD COLUMN v6_confirmed_at INTEGER;
ALTER TABLE devices ADD COLUMN v4_warn_level   INTEGER NOT NULL DEFAULT 0;
ALTER TABLE devices ADD COLUMN v6_warn_level   INTEGER NOT NULL DEFAULT 0;

-- Seed the confirmation instants from last_seen_at, per family the device
-- actually carries (design §11.1). An approximation -- history records no
-- per-family assertion -- and exact for every device whose client reports both
-- families. For a device that had already stopped asserting one family before
-- the upgrade, that family's instant is overstated and its expiry is
-- correspondingly late, by at most the time since the upgrade: self-correcting,
-- and strictly safer than backfilling NULL, which maps to Go 0 and would expire
-- every device on the first sweep.
UPDATE devices SET v4_confirmed_at = last_seen_at WHERE current_ipv4 IS NOT NULL;
UPDATE devices SET v6_confirmed_at = last_seen_at WHERE current_ipv6 IS NOT NULL;

-- No index. Measured against 200k devices: a covering index on the sweep's
-- predicate made the materialise statement SLOWER at every population
-- (48.8 -> 66.8 ms steady state), because the sweep reads a large fraction of
-- the table and a full scan is the right plan.
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE devices DROP COLUMN v6_warn_level;
ALTER TABLE devices DROP COLUMN v4_warn_level;
ALTER TABLE devices DROP COLUMN v6_confirmed_at;
ALTER TABLE devices DROP COLUMN v4_confirmed_at;
-- Rolling back is FAIL-CLOSED and needs nothing further (D19): an expired
-- address is already NULL and v0.4.0's listFeedQuery treats NULL as absent, so
-- nothing re-enters the allow-list. The cleared addresses are not restored,
-- which is correct -- they were cleared because they were stale, and
-- ip_history still records them.
-- +goose StatementEnd
