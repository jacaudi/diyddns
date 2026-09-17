# Retention

*Optional, off by default.*

DIYDDNS records an `ip_history` row every time a device's public IP changes, and
an `audit_log` row for every security-relevant action. Both tables grow without
bound unless you set a retention policy.

Retention is **disabled by default**, and that is a supported way to run: a
household deployment can keep everything forever and never think about it.
Nothing is deleted from `ip_history` or `audit_log` by this policy until you
set one of these keys.

> **Note:** separately and unconditionally, DIYDDNS also deletes expired
> single-use tokens — `account_recovery_tokens` and `enrollment_codes` — once
> they expire, whether or not they were used, starting on the first hourly
> sweep after upgrade. This is **not** gated by the retention keys below. The
> audit trail is unaffected (`device.enroll.code` and
> `passkey.recovery_issued` events survive); what is lost is the token rows
> themselves, including `enrollment_codes.device_id`.

| Key | Env var | Notes |
|---|---|---|
| `retention.ip_history_days` | `DIYDDNS_RETENTION_IP_HISTORY_DAYS` | `0` (keep forever) by default; max `36500` |
| `retention.ip_history_per_device_max` | `DIYDDNS_RETENTION_IP_HISTORY_PER_DEVICE_MAX` | `0` (unlimited) by default; max `36500` |
| `retention.audit_log_days` | `DIYDDNS_RETENTION_AUDIT_LOG_DAYS` | `0` (keep forever) by default; max `36500` |
| `retention.notification_deliveries_days` | `DIYDDNS_RETENTION_NOTIFICATION_DELIVERIES_DAYS` | `0` (keep forever) by default; max `36500` |

The two `ip_history` keys combine: a row is removed if it falls outside *either*
window. **The most recent row for each device is always kept**, whatever you
set, so a device never loses its current IP.

`notification_deliveries_days` trims the delivery history shown on an endpoint's
page. **Only completed deliveries are eligible** — a delivery still waiting to
be sent or retried is never removed, however old it is, because deleting one
would silently drop work with nothing left to retry it. Enable this if you use
[notifications](notifications.md): without it the table grows with every IP change, for every
endpoint.

**Deletion is permanent and there is no undo.** When you first enable a key, the
next sweep removes everything already outside the window — on an aged database
that can be a lot of rows. The server logs a warning at startup naming the
values in effect, records a `retention.prune` audit entry for every sweep that
deleted something, and waits a full hour after boot before its first sweep, so
there is time to notice a mistake and revert it.

The sweep runs hourly and is not configurable: retention windows are measured in
days, so an hourly sweep is already far finer than any policy you can express.

If you enable either `ip_history` retention key, consider also setting
`audit_log_days`. Every sweep that deletes something writes one
`retention.prune` audit row, and only `audit_log_days` cleans those up —
leaving it at `0` while pruning `ip_history` trades unbounded `ip_history`
growth for slow, permanent growth in `audit_log` instead.

Retention stops the database file from growing, but it does not shrink it:
SQLite reuses freed pages internally rather than returning them to the
filesystem. To reclaim the disk space after a large prune, stop the server and
run a manual `VACUUM` on the database file.

---
[← Back to README](../README.md)
