package email

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"sync/atomic"

	apprise "github.com/unraid/apprise-go"

	"github.com/jacaudi/diyddns/internal/config"
)

// maxInFlightSends bounds how many SMTP conversations may exist at once,
// including the ones a caller has already abandoned at its deadline. The
// library that owns the conversation sets no deadline of its own (see Send),
// so this is the only thing standing between a wedged peer and unbounded
// goroutines and sockets. Legitimate concurrency is one serial hourly sweep,
// one admin action at a time, and self-service recovery requests; 32 is an
// order of magnitude above that and a negligible resource ceiling.
const maxInFlightSends = 32

// ErrTransportSaturated reports that maxInFlightSends conversations are
// already open, so this send was refused without touching the network.
// Callers treat it like any other delivery failure: on the admin grant paths
// an audit row and a visible failure with the link still shown, elsewhere a
// log line. It clears when a conversation ends; a peer that holds every open
// session forever keeps email refused until restart.
var ErrTransportSaturated = errors.New("email: transport saturated: too many SMTP conversations in flight")

// sendFunc performs one SMTP conversation for one rendered target URL. It is
// a field rather than a direct call so tests can stand in a stub that stalls,
// panics or returns a chosen error without any network I/O.
type sendFunc func(rawURL, subject, body string) error

// appriseMailer sends over SMTP through unraid/apprise-go's mailto service.
//
// The library's public API takes no context and its SMTP path sets no
// deadline (unraid/apprise-go v0.3.3, internal/notify/mailto_target.go
// connect: bare net.Dial / tls.Dial, then smtp.NewClient). Send therefore
// runs every conversation on its own goroutine and returns to the caller at
// the caller's deadline; the conversation itself runs on until the peer
// answers, closes, or goes dark (TCP keepalive). slots bounds how many such
// conversations can exist. See design #129 §0 and §6.3 for the trade-off and
// the alternative.
//
// slots must always be a made channel. A nil channel makes Send's reserving
// select take its default branch forever -- every send refused, silently.
// newAppriseMailer is the only construction path in the tree and always
// makes it; never build an appriseMailer with a bare struct literal.
type appriseMailer struct {
	cfg   config.EmailSection
	log   *slog.Logger
	slots chan struct{} // capacity is the in-flight cap; see the type comment
	send  sendFunc      // production: appriseSend
}

func newAppriseMailer(cfg config.EmailSection, log *slog.Logger) *appriseMailer {
	return &appriseMailer{
		cfg:   cfg,
		log:   log,
		slots: make(chan struct{}, maxInFlightSends),
		send:  appriseSend,
	}
}

// appriseSend is the production send: one URL, one conversation.
func appriseSend(rawURL, subject, body string) error {
	return apprise.Send([]string{rawURL}, body, apprise.WithTitle(subject), apprise.WithInputFormat("text"))
}

func (m *appriseMailer) Enabled() bool { return true }

// Send delivers one message. Callers are expected to supply a deadline on
// ctx: Send returns no later than that deadline, with an error wrapping
// context.DeadlineExceeded if the conversation has not finished by then.
// Without a deadline it blocks until the transport returns, exactly as the
// net/smtp client it replaced did.
//
// The SMTP password never appears in a log attribute or in the returned
// error: the library renders its target URL, credentials included, into
// its errors, and sanitize strips that before anything is logged or returned.
//
// Every log line below carries in_flight: the number of reserved slots at
// the moment the line is written, read without any lock against concurrent
// releases -- so it can already be one lower than the event that triggered
// the line implies. The "refused" line was triggered by a full pool (cap is
// logged beside it); the "abandoned" line normally still counts the
// abandoning caller's own slot; the "completed after" line is written after
// its own release. It is the count at the read, nothing stronger.
func (m *appriseMailer) Send(ctx context.Context, to, subject, body string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("email: context canceled before send: %w", err)
	}

	// The backstop, checked BEFORE the network so it costs no I/O. The
	// boundary validations (service/admin.go, service/bootstrap.go,
	// service/oidc.go, config.validateEmail) are the primary defence; this
	// catches anything already stored before those existed, and any route not
	// yet enumerated.
	//
	// Failing here is deliberate and is the whole handling a bad stored address
	// gets: callers treat a Send error as a delivery failure, so the operator
	// gets an audit row (email.send_failed) and a visible failure, while the
	// user keeps every non-email capability. No migration, no startup scan, no
	// login rejection.
	if err := checkSendable(m.cfg.From, to, subject, body); err != nil {
		m.log.ErrorContext(ctx, "email.send failed", "host", m.cfg.Host, "to", to, "error", err)
		return err
	}

	// Reserve before dialing. The slot is released by the goroutine when the
	// library returns, never by this function: a caller that leaves at its
	// deadline leaves the conversation running, and the slot must keep
	// counting it until it ends. The reservation IS the check, so there is no
	// window in which more than cap(slots) conversations can start.
	select {
	case m.slots <- struct{}{}:
	default:
		m.log.ErrorContext(ctx, "email.send refused", "host", m.cfg.Host, "to", to,
			"error", ErrTransportSaturated, "in_flight", len(m.slots), "cap", cap(m.slots))
		return ErrTransportSaturated
	}

	done := make(chan error, 1) // buffered: the goroutine never blocks on a caller that left
	var abandoned atomic.Bool   // set by the caller when it leaves at its deadline
	go func() {
		err := m.guardedSend(m.targetURL(to), subject, body)
		// Release BEFORE publishing the result, so anything that observes the
		// outcome (the caller, or a test waiting on the late-completion line)
		// also observes the slot free; releasing afterwards leaves a window
		// in which the next Send is refused for a conversation that is over.
		<-m.slots
		done <- err
		if abandoned.Load() {
			// The caller has already reported this send as failed and, on the
			// grant paths, audited it. If err is nil the message was delivered
			// anyway -- late. This line is normally the only record of that
			// outcome and the only drain signal an operator has. A panic in the
			// library reaches here too, as the error guardedSend turned it into.
			m.log.LogAttrs(context.WithoutCancel(ctx), slog.LevelWarn,
				"email.send completed after its caller gave up on it",
				slog.String("host", m.cfg.Host), slog.String("to", to),
				slog.Bool("delivered", err == nil), slog.Any("error", sanitizeNil(err)),
				slog.Int("in_flight", len(m.slots)))
		}
	}()

	select {
	case err := <-done:
		return m.finish(ctx, to, err)
	case <-ctx.Done():
		// If the result landed in the same instant, prefer it: the message
		// may have been delivered, and reporting that as a failure would
		// write an audit row for a send that succeeded.
		select {
		case err := <-done:
			return m.finish(ctx, to, err)
		default:
		}
		abandoned.Store(true)
		m.log.ErrorContext(ctx, "email.send abandoned at deadline; the SMTP conversation may still be open",
			"host", m.cfg.Host, "to", to, "error", ctx.Err(), "in_flight", len(m.slots))
		return fmt.Errorf("email: send to %s abandoned: %w", m.cfg.Host, ctx.Err())
	}
}

// guardedSend runs one conversation and turns a panic into a failed send.
// The library is a large third-party tree running off the HTTP handler
// goroutine, so middleware.Recover cannot catch it; a panic here must be a
// delivery failure, not a dead process, whether or not the caller is still
// waiting. The recovered value is rendered with %v, which sanitize's
// type-based stripping cannot see into; the mailto path of the pinned
// library contains no panic call, so this is a safety net, not a path a
// URL-bearing error travels today.
func (m *appriseMailer) guardedSend(rawURL, subject, body string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("transport panic: %v", r)
		}
	}()
	return m.send(rawURL, subject, body)
}

// sanitizeNil is sanitize for a log attribute: nil stays nil.
func sanitizeNil(err error) error {
	if err == nil {
		return nil
	}
	return sanitize(err)
}

// finish logs and returns one completed send's outcome.
func (m *appriseMailer) finish(ctx context.Context, to string, err error) error {
	if err != nil {
		err = sanitize(err)
		m.log.ErrorContext(ctx, "email.send failed", "host", m.cfg.Host, "to", to, "error", err)
		return err
	}
	m.log.DebugContext(ctx, "email.send ok", "host", m.cfg.Host, "to", to)
	return nil
}

// targetURL renders cfg plus one recipient as the library's mailto URL. The
// password rides in userinfo, percent-encoded by url.URL, and the URL is
// never logged (see sanitize).
//
// Every value here is a bare address (checkSendable has already refused one
// with a space in it), a mode word or a port that is ours: none contains a
// space. That matters because the library decodes query values with
// url.PathUnescape and never turns a '+' back into a space, while
// url.Values.Encode writes a space AS '+'. A display name in ?from= would
// arrive as "DIYDDNS+ <addr>". Do not add a value that can contain a space
// without switching that value to %20 encoding.
//
// ?to= rather than a path segment: the path is additionally split on '/' and
// path-unescaped; the query goes through one parser. ?mode= is always
// explicit so the scheme carries no meaning a reader could misread.
func (m *appriseMailer) targetURL(to string) string {
	q := url.Values{}
	q.Set("from", m.cfg.From)
	q.Set("to", to)
	q.Set("format", "text")
	q.Set("mode", secureMode(m.cfg.TLS))
	u := url.URL{
		Scheme:   "mailto",
		Host:     net.JoinHostPort(m.cfg.Host, strconv.Itoa(m.cfg.Port)),
		RawQuery: q.Encode(),
	}
	if m.cfg.Username != "" {
		u.User = url.UserPassword(m.cfg.Username, m.cfg.Password)
	}
	return u.String()
}

// secureMode maps email.tls onto the library's ?mode= values. An unrecognized
// value is rejected at startup by config.validateEmail; the default branch
// mirrors the old client's fallback to plaintext and is not a documented API.
func secureMode(tlsMode string) string {
	switch tlsMode {
	case "starttls":
		return "starttls"
	case "implicit":
		return "ssl"
	default:
		return "insecure"
	}
}

// sanitize strips anything that could carry the target URL, and with it the
// SMTP password, out of a library error before it is logged or returned.
//   - *apprise.TargetError renders "<url>: <err>"; keep only <err>. This send
//     has exactly one target, so the first TargetError is the only one; a
//     multi-target caller would lose the rest and must not reuse this.
//   - *url.Error renders "<op> \"<url>\": <err>"; keep only <err>. This is
//     also how a parse failure inside the library's AddAll surfaces.
//
// Everything else (apprise.ErrNoTargets, attachment errors) carries no URL.
func sanitize(err error) error {
	if te, ok := errors.AsType[*apprise.TargetError](err); ok {
		err = te.Err
	}
	if ue, ok := errors.AsType[*url.Error](err); ok {
		err = ue.Err
	}
	return fmt.Errorf("email: send: %w", err)
}
