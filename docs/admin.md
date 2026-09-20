# Admin

*Always on — no config, no toggle.*

Read-only, cross-user views for administrators, alongside the `/admin/devices` page in the web
UI. Both endpoints below are session + admin gated (GET only, so no CSRF token is required).

## `GET /api/v1/admin/devices`

Every device across every user, not just the caller's own — the same non-secret device view the
owner-scoped `/api/v1/devices` endpoint returns, with one field added: `user_id`, the owning
account.

## `GET /api/v1/admin/devices/ips`

```json
{ "cidrs": ["203.0.113.9/32", "2001:db8::1/128"] }
```

The deduplicated, current address set across every device **currently in the gateway feed** —
squashed to unique CIDRs, not a per-device listing, and scoped by the exact same membership
predicate as the [feed](feed.md)'s own `/feed/v1/devices.json` `cidrs` field: an enabled device,
enabled owner, with at least one address. A disabled device (or one whose owner is disabled) is
excluded here exactly as it is from the feed, not merely omitted by coincidence — its stored
address is frozen once disabled. Field name and CIDR format (`/32`, `/128`) deliberately mirror
the feed's own, so the two can never diverge on format; this endpoint exists to hand a firewall
or WAF the feed's data without needing a feed token.

---
[← Back to README](../README.md)
