# Observability

Every log record emitted while serving a request carries a `request_id`, and the
same id is returned in the response header so a client can quote it in a bug
report. DIYDDNS honours an incoming id, which lets its logs join a reverse
proxy's for the same request.

| Key | Env var | Notes |
|---|---|---|
| `observability.request_id_header` | `DIYDDNS_OBSERVABILITY_REQUEST_ID_HEADER` | `X-Request-Id` by default. Set it to whatever your proxy stamps |

An inbound value is honoured only if it is at most 128 bytes of printable ASCII;
anything else is discarded and a fresh UUIDv7 is minted, so an untrusted client
cannot write unbounded data into the log.

The id is nonetheless **client-supplied and untrusted** unless a proxy you
control overwrites the header on the way in: any unauthenticated caller can send
every request under one id, or under an id it saw in someone else's bug report.
Treat it as a correlation aid, never as attribution.

Two kinds of header name are refused at startup: ones the server itself writes
(`Content-Length`, `Content-Type`, `Location`, ...), and ones that carry a
credential (`Cookie`, `Authorization`, `X-CSRF-Token`, the agent's
`X-Diyddns-*` signing headers) — the configured header's value is copied into
`request_id` on every record, so pointing it at `Cookie` would publish the
session cookie to the log.

## OpenTelemetry Export (OTLP)

*Optional, off by default.*

DIYDDNS can export traces, metrics, and logs over OTLP/HTTP to a collector —
Grafana Alloy, the OpenTelemetry Collector, or anything else that speaks the
protocol. **Off by default**: when `observability.otlp.enabled` is false,
nothing is constructed and no OTel provider or diagnostic global is installed
anywhere in the process.

"Off" means nothing is *exported*, not that nothing runs. The tracing
middleware stays in the chain: it still starts a (no-op) span and still builds
that span's attribute set on every request before the no-op instruments discard
the result — about +13 heap allocations per request on a default-config server.
Small, and deliberately not gated behind the flag (gating it would take the
tracing middleware out of every default-config test), but not zero.

| Key | Env var | Notes |
|---|---|---|
| `observability.otlp.enabled` | `DIYDDNS_OBSERVABILITY_OTLP_ENABLED` | `false` by default |
| `observability.otlp.endpoint` | `DIYDDNS_OBSERVABILITY_OTLP_ENDPOINT` | OTLP/HTTP collector base URL. Scheme (`http://` or `https://`) is required. Leave empty to use `OTEL_EXPORTER_OTLP_ENDPOINT` (or the per-signal `OTEL_EXPORTER_OTLP_{TRACES,METRICS,LOGS}_ENDPOINT`) instead |
| `observability.otlp.service_name` | `DIYDDNS_OBSERVABILITY_OTLP_SERVICE_NAME` | `service.name` on every exported record. Leave empty to use `OTEL_SERVICE_NAME`, falling back to `diyddns` |

Only these three keys exist here on purpose. Everything else — headers,
protocol, TLS, timeouts, sampler, batch tuning — comes from the standard
`OTEL_*` environment variables the SDK already reads (see
[`config.example.yaml`](../config.example.yaml) for the full list DIYDDNS doesn't restate).

**The endpoint is the collector's base URL and its scheme is required.**
`http://` means plaintext, `https://` means TLS. DIYDDNS appends `/v1/traces`,
`/v1/metrics` and `/v1/logs` itself, so give it the base URL — an endpoint that
already ends in one of those is refused rather than doubled. Credentials belong
in `OTEL_EXPORTER_OTLP_HEADERS`, **not** in the URL: the exporter keeps only the
scheme, host and path and silently drops any `user:pass@` userinfo, so an
in-URL credential is never sent and nothing reports that it was ignored.

A few things are worth knowing before you tune the `OTEL_*` variables:

- **The batch tuning knobs use three different prefixes**, one per signal.
  Spans read `OTEL_BSP_SCHEDULE_DELAY`, `OTEL_BSP_EXPORT_TIMEOUT`,
  `OTEL_BSP_MAX_QUEUE_SIZE` and `OTEL_BSP_MAX_EXPORT_BATCH_SIZE`; log records
  read the same four suffixes under `OTEL_BLRP_*`; metrics read
  `OTEL_METRIC_EXPORT_INTERVAL` and `OTEL_METRIC_EXPORT_TIMEOUT`. `OTEL_BSP_*`
  does nothing at all for logs or metrics.
- **`OTEL_PROPAGATORS` is not read.** The W3C `traceparent` propagator is
  hardcoded: an inbound `traceparent` is honoured and continued, and nothing
  else (B3, Jaeger, baggage) is. Neither `go.opentelemetry.io/otel` nor its SDK
  consumes that variable, so setting it is silently ineffective rather than an
  error.
- **`OTEL_EXPORTER_OTLP_TIMEOUT` is not clamped.** It bounds one export
  attempt and defaults to 10s in the SDK. DIYDDNS gives graceful shutdown a
  fixed 20s budget across all three signals; setting a large timeout can push
  a worst-case export past that budget, leaving a batch-export goroutine
  running after `Shutdown` has returned. DIYDDNS documents this rather than
  silently overriding an explicit operator instruction — if you raise the
  timeout, keep the shutdown budget in mind.
- **The shutdown budget bounds when shutdown *returns*, not whether the queue
  fully flushed.** If a collector is unreachable when the server stops, the
  20s budget can be exhausted mid-drain; the process still exits cleanly, but
  some already-queued records may not have been sent.

**A malformed endpoint refuses to start; a missing one only degrades.** The two
look adjacent and are treated differently on purpose:

- An `observability.otlp.endpoint` that is not an absolute `http://` or
  `https://` URL with a host — `otel-collector:4318`, say — **fails the boot**,
  non-zero, before the database is opened or migrated. Without a scheme the
  exporter would POST to `http:///` forever while shutdown reported success, so
  the failure would otherwise be completely invisible. An endpoint that already
  ends in a per-signal path fails the same way.
- **No endpoint at all** — nothing in YAML and none of the four
  `OTEL_EXPORTER_OTLP_*_ENDPOINT` variables — logs one `telemetry not
  exporting` warning at boot and the server runs with telemetry inert. That is
  an operator part-way through wiring a collector up, not a reason to refuse to
  run.
- A misconfigured `OTEL_*` value, or a collector that is simply down, never
  stops the server either: at worst that signal's export fails and the reason
  is logged through the rate-limited error handler.

**What gets exported.** Four metrics:

| Metric | Unit | Notes |
|---|---|---|
| `http.server.request.duration` | `s` | Histogram with seconds-shaped buckets. Attributes: `http.request.method`, `http.route`, `http.response.status_code` |
| `diyddns.notification.delivery` | `{delivery}` | Counter, one per delivery attempt, attribute `class` |
| `diyddns.db.connection.wait_time` | `s` | Cumulative time blocked waiting for the single SQLite connection |
| `diyddns.db.connection.waits` | `{wait}` | Cumulative count of those waits |

Log records are gated at `logging.level`, the same level stdout uses, so a
default `info` server exports one record per **terminal** notification outcome:
`notify: delivered` at Info, plus `notify: delivery failed permanently`,
`notify: write-back failed` and `notify: sweep query failed` at Warn.
Per-attempt detail (`notify: delivery rejected`, `notify: delivery attempt
failed`) is at Debug, and `logging.level: debug` also floods stdout with
everything else at that level. For per-attempt visibility without that, use the
`diyddns.notification.delivery` metric instead — its `class` attribute carries
every attempt's outcome at any log level.

Spans carry **no device id and no user id**, by design: a span's name and
`http.route` are the route template, so an id in the path never reaches a
third-party observability backend. The consequence to plan around is that
`request_id` correlates a span to a *request*, not to a device. A failing
check-in is still attributable, because the error branch logs `device_id`
alongside the `request_id`; a slow but successful one is not.

---
[← Back to README](../README.md)
