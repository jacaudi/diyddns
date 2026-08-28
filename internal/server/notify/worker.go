package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/shared"
	"github.com/jacaudi/diyddns/internal/store"
)

const (
	notifierInterval  = 15 * time.Second // sweep cadence
	deliveryBatchSize = 20               // max rows per sweep; bounds the LIMIT
	backoffBase       = 15 * time.Second // first gap; NOT the same concept as
	// notifierInterval, which it happens to equal
	maxBackoff   = 16 * time.Minute // clamp
	bodyDrainCap = 4 << 10          // bytes drained to io.Discard so the
	// connection can be reused
)

// Budget constants for the user-initiated attempt limit (design §10.3). Task 8
// binds both into its SQL rather than hard-coding 5 and a bare timestamp.
const (
	// UserBudgetCount is the number of user-initiated delivery attempts an
	// endpoint may spend within UserBudgetWindow.
	UserBudgetCount = 5
	// UserBudgetWindow is the rolling window UserBudgetCount is measured over.
	UserBudgetWindow = 5 * time.Minute
)

// The six failure classes that may ever reach notification_deliveries.last_failure.
// No status code, resolved address, or Go error string is a valid seventh
// value — a user configuring an outbound target must not get a readback
// oracle from any richer detail than these fixed strings.
const (
	failureBlocked     = "blocked"     // DNS failure OR guard rejection (deliberately merged)
	failureUnreachable = "unreachable" // timeout or connection refused
	failureTLS         = "tls"         // certificate verification failure
	failureRejected    = "rejected"    // any non-2xx except 410, incl. 3xx
	failureGone        = "gone"        // 410, terminal regardless of attempts remaining
	failureInternal    = "internal"    // render/seal/scheme/nonce/internal error
)

// AuditSink records security-relevant delivery events. Declared here rather
// than imported from service, per the package-dependency rule: notify must
// not import service (service already imports notify for the destination
// policy, and the reverse would be an import cycle).
// service.NewAuditWriter's return value satisfies it structurally.
type AuditSink interface {
	Log(context.Context, store.AuditEntry)
}

// Worker sweeps notification_deliveries for rows due for a fresh attempt and
// delivers them. There is exactly one Worker running per process, started
// once by Server.Run — see sweep's doc comment for why that single-goroutine
// invariant is load-bearing.
type Worker struct {
	st          *store.Store
	clients     *Clients
	key         []byte // raw 32-byte AEAD key for auth.OpenSecret
	maxAttempts int
	audit       AuditSink
	randFloat   func() float64
	log         *slog.Logger
}

// NewWorker constructs a Worker. key is the raw AEAD key passed to
// auth.OpenSecret, not a base64 string. randFloat is the jitter seam
// (injected the same way internal/client/poller/poller.go:163-164 injects
// its own); production callers pass a real [0,1) source.
func NewWorker(st *store.Store, cs *Clients, key []byte, maxAttempts int, audit AuditSink, randFloat func() float64, log *slog.Logger) *Worker {
	return &Worker{st: st, clients: cs, key: key, maxAttempts: maxAttempts, audit: audit, randFloat: randFloat, log: log}
}

// Run sweeps for due deliveries every notifierInterval until ctx is
// cancelled. Started as a goroutine by Server.Run; ctx cancellation is its
// only shutdown path.
func (w *Worker) Run(ctx context.Context) {
	ticker := time.NewTicker(notifierInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.sweep(ctx)
		}
	}
}

// sweep selects up to deliveryBatchSize due rows, then attempts and writes
// back each in turn once the SELECT's statement has finished.
//
// There is deliberately no claim step (no "mark as in-progress" write between
// the select and the delivery). That is safe ONLY because exactly one
// sweeper goroutine ever runs in one process — Worker.Run is started once
// from Server.Run — so no other goroutine can select the same row before
// this one writes it back. A second sweeper (e.g. a multi-process
// deployment) would need a claim column; diyddns does not have one.
func (w *Worker) sweep(ctx context.Context) {
	due, err := w.st.NotificationDeliveries().DueForAttempt(ctx, store.NowUnix(), deliveryBatchSize)
	if err != nil {
		w.log.LogAttrs(ctx, slog.LevelWarn, "notify: sweep query failed", slog.Any("error", err))
		return
	}
	for _, d := range due {
		if ctx.Err() != nil {
			return
		}
		w.deliverOne(ctx, d)
	}
}

// deliverOne attempts d once and writes back exactly one UPDATE with the
// outcome — no HTTP call is ever made while a DB statement is open; the
// SELECT that produced d has already completed by the time this runs.
func (w *Worker) deliverOne(ctx context.Context, d store.DueDelivery) {
	maxAttempts := w.maxAttempts
	if d.EventType == EventTest {
		// endpoint.test is a one-shot probe regardless of configuration.
		maxAttempts = 1
	}

	class := w.attempt(ctx, d)
	if class == "" {
		// ctx was cancelled mid-attempt (server shutting down): no write-back.
		// The row stays exactly as selected and is retried after restart.
		return
	}

	attempts := d.Attempts + 1
	var (
		status        string
		nextAttemptAt int64
		lastFailure   string
	)
	switch {
	case class == store.DeliveryDelivered:
		status = store.DeliveryDelivered
	// 410 is terminal on the first attempt regardless of attempts remaining;
	// everything else is retried until attempts is exhausted.
	case class == failureGone, attempts >= maxAttempts:
		status = store.DeliveryFailed
		lastFailure = class
	default:
		status = store.DeliveryPending
		lastFailure = class
		nextAttemptAt = store.NowUnix() + int64(backoffFor(attempts+1, w.randFloat).Seconds())
	}

	if err := w.st.NotificationDeliveries().UpdateAfterAttempt(ctx, d.ID, attempts, status, nextAttemptAt, lastFailure); err != nil {
		w.log.LogAttrs(ctx, slog.LevelWarn, "notify: write-back failed",
			slog.Int64("delivery_id", d.ID), slog.Any("error", err))
	}
}

// attempt performs one HTTP delivery attempt for d and classifies the
// outcome. It returns "" if ctx was cancelled during the attempt —
// deliverOne treats that as "do not write back," never as a failure class.
// Otherwise it returns "delivered" or one of the six fixed failure classes;
// deliverOne alone decides whether that class is terminal.
func (w *Worker) attempt(ctx context.Context, d store.DueDelivery) string {
	target, err := url.Parse(d.EndpointURL)
	if err != nil {
		return w.logFailure(ctx, d, failureInternal, err)
	}
	client, err := w.clients.For(target.Scheme)
	if err != nil {
		// Unsupported stored scheme never reaches a client.
		return w.logFailure(ctx, d, failureInternal, err)
	}

	nonce, err := auth.RandToken(16)
	if err != nil {
		return w.logFailure(ctx, d, failureInternal, err)
	}
	secret, err := auth.OpenSecret(w.key, d.SecretSealed)
	if err != nil {
		return w.logFailure(ctx, d, failureInternal, err)
	}
	ts := strconv.FormatInt(store.NowUnix(), 10)
	canonical := shared.CanonicalNotification(ts, nonce, shared.BodyHashHex(d.Payload))
	sig := shared.Sign(secret, canonical)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.EndpointURL, bytes.NewReader(d.Payload))
	if err != nil {
		return w.logFailure(ctx, d, failureInternal, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(shared.HeaderTimestamp, ts)
	req.Header.Set(shared.HeaderNonce, nonce)
	req.Header.Set(shared.HeaderSignature, sig)

	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return "" // shutdown mid-attempt: no write-back
		}
		sendClass := classifySendError(err)
		if errors.Is(err, ErrDenied) {
			w.auditBlocked(ctx, d, err)
		}
		return w.logFailure(ctx, d, sendClass, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, bodyDrainCap))
		_ = resp.Body.Close()
	}()

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return store.DeliveryDelivered
	case resp.StatusCode == http.StatusGone:
		return failureGone
	default:
		w.log.LogAttrs(ctx, slog.LevelDebug, "notify: delivery rejected",
			slog.Int64("delivery_id", d.ID), slog.Int("status", resp.StatusCode))
		return failureRejected
	}
}

// logFailure logs the raw error at Debug — never persisted, per the fixed
// six-failure-class rule — and returns class unchanged, so call sites can
// return directly.
func (w *Worker) logFailure(ctx context.Context, d store.DueDelivery, class string, raw error) string {
	w.log.LogAttrs(ctx, slog.LevelDebug, "notify: delivery attempt failed",
		slog.Int64("delivery_id", d.ID), slog.String("class", class), slog.Any("error", raw))
	return class
}

// auditBlocked records a guard rejection to the audit log (admin-visible
// only). The raw error — which may name the resolved address — is safe here
// specifically because the audit log is never shown to the user configuring
// the endpoint; notification_deliveries.last_failure, which is, still only
// ever gets the fixed string "blocked".
func (w *Worker) auditBlocked(ctx context.Context, d store.DueDelivery, raw error) {
	// map[string]string cannot fail to marshal.
	details, _ := json.Marshal(map[string]string{"error": raw.Error()})
	w.audit.Log(ctx, store.AuditEntry{
		EventType:   "notification.target_blocked",
		TargetType:  "notification_endpoint",
		TargetID:    d.EndpointID,
		DetailsJSON: string(details),
	})
}

// classifySendError maps a client.Do error to one of the fixed failure
// classes. ErrDenied and a DNS failure are checked first and both collapse to
// "blocked" by design (see ErrDenied's doc comment): separating a guard
// rejection from "the name doesn't resolve" would reconstruct an
// internal-DNS oracle. Both cases, plus a plain connection error, surface as
// *net.OpError, so string matching cannot tell them apart — the sentinel
// check is the only reliable one.
func classifySendError(err error) string {
	if errors.Is(err, ErrDenied) {
		return failureBlocked
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return failureBlocked
	}
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return failureTLS
	}
	var hostErr x509.HostnameError
	if errors.As(err, &hostErr) {
		return failureTLS
	}
	var authErr x509.UnknownAuthorityError
	if errors.As(err, &authErr) {
		return failureTLS
	}
	var invalidErr x509.CertificateInvalidError
	if errors.As(err, &invalidErr) {
		return failureTLS
	}
	return failureUnreachable
}

// backoffFor returns the delay before attempt (the attempt being SCHEDULED,
// so the minimum valid input is 2 — there is deliberately no backoffFor(1)):
//
//	delay(n) = min(backoffBase * 2^(n-2) * jitter, maxBackoff), jitter in [0.9, 1.1]
//
// Jitter is applied to the base and the RESULT is clamped, not the reverse:
// clamping first and jittering after would let the return value exceed
// maxBackoff by up to 10%. attempt < 2 panics rather than left-shifting by a
// negative amount, which would otherwise produce a hot retry loop on the
// first delivery failure in production — an explicit panic here is
// debuggable, a silent negative delay is not.
func backoffFor(attempt int, randFloat func() float64) time.Duration {
	if attempt < 2 {
		panic(fmt.Sprintf("notify: backoffFor(%d): attempt must be >= 2 (it is the attempt being scheduled, not the one just made)", attempt))
	}
	exp := attempt - 2
	base := backoffBase * time.Duration(1<<exp)
	jitterFactor := 0.9 + 0.2*randFloat() // [0.9, 1.1]
	jittered := time.Duration(float64(base) * jitterFactor)
	return min(jittered, maxBackoff)
}
