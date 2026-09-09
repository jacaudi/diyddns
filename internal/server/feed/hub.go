package feed

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// Bounds. maxStreamConns and streamBuffer are constants: each has exactly one
// sensible operator value today (the notifierInterval precedent). The three
// timings are package-level vars so export_test.go can shorten them — a test
// seam, not an operator knob (design D19, §12).
const (
	maxStreamConns = 32
	streamBuffer   = 64
	readLimit      = 4096 // a client is expected to send nothing; the library default is 32 KiB
)

var (
	pingInterval = 30 * time.Second
	pingTimeout  = 10 * time.Second
	writeTimeout = 5 * time.Second
)

// Sentinel errors from subscribe; the handler maps both to 503.
var (
	ErrTooManyConnections = errors.New("feed: too many stream connections")
	ErrShuttingDown       = errors.New("feed: hub is shutting down")
)

// closeCause is the ONE type every subscriber cancellation carries (design
// §5.1): the close code the pump sends and its reason. Code 0 means "send no
// frame" — the peer is already gone — and Err then carries the read or write
// error that said so.
type closeCause struct {
	Code   websocket.StatusCode
	Reason string
	Err    error
}

func (c *closeCause) Error() string {
	if c.Err != nil {
		return "feed: " + c.Reason + ": " + c.Err.Error()
	}
	return "feed: " + c.Reason
}

// The six causes. 4001 is a private-use code (RFC 6455 §7.4.2); the library
// accepts 3000–4999 on the wire.
var (
	causeShutdown     = &closeCause{Code: websocket.StatusGoingAway, Reason: "server shutting down"}
	causePingFailed   = &closeCause{Code: websocket.StatusGoingAway, Reason: "ping failed"}
	causeInternal     = &closeCause{Code: websocket.StatusInternalError, Reason: "internal error"}
	causeSlowConsumer = &closeCause{Code: websocket.StatusTryAgainLater, Reason: "slow consumer"}
	causeRevoked      = &closeCause{Code: 4001, Reason: "token revoked"}
)

// causePeerGone is the no-frame cause: the read loop or a Write returned err.
func causePeerGone(err error) *closeCause {
	return &closeCause{Code: 0, Reason: "peer gone", Err: err}
}

// causeOf reads the cause a subscriber context was cancelled with. Every
// cancel in this package passes a *closeCause, so anything else is a bug;
// it degrades to causeShutdown rather than panicking, and the pump logs it.
func causeOf(ctx context.Context) *closeCause {
	if c, ok := errors.AsType[*closeCause](context.Cause(ctx)); ok && c != nil {
		return c
	}
	return causeShutdown
}

// subscriber is one live stream connection's hub-side state. ch is the
// bounded buffer Broadcast feeds and the pump drains; ctx is cancelled — with
// a cause — by the hub (revoke, overflow, shutdown) or by the pump's own
// goroutines (peer gone, ping failed).
type subscriber struct {
	tokenID string
	ch      chan []byte
	ctx     context.Context
	cancel  context.CancelCauseFunc
	once    sync.Once
}

// Hub fans broadcast payloads out to live stream subscribers (design §5.3).
// It has no goroutine of its own; every goroutine is per-connection and
// owned by the stream handler. It is always constructed, whether or not the
// feed is enabled: with no subscribers Broadcast is a no-op and Shutdown
// returns at once.
//
// Lock discipline: mu guards subs and the hub context's cancellation ONLY,
// and is never held across network I/O or across unsubscribe.
type Hub struct {
	mu     sync.Mutex
	subs   map[*subscriber]struct{}
	ctx    context.Context
	cancel context.CancelCauseFunc
	wg     sync.WaitGroup
}

// New constructs an empty Hub.
func New() *Hub {
	ctx, cancel := context.WithCancelCause(context.Background())
	return &Hub{subs: make(map[*subscriber]struct{}), ctx: ctx, cancel: cancel}
}

// subscribe reserves a slot for tokenID. Under mu: refuses once Shutdown has
// begun (so no wg.Add can race the Wait at zero), refuses past
// maxStreamConns, otherwise creates the subscriber's cause-carrying context
// as a child of the hub context, adds it to the map, and wg.Add(1)s.
func (h *Hub) subscribe(tokenID string) (*subscriber, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.ctx.Err() != nil {
		return nil, ErrShuttingDown
	}
	if len(h.subs) >= maxStreamConns {
		return nil, ErrTooManyConnections
	}
	ctx, cancel := context.WithCancelCause(h.ctx)
	s := &subscriber{tokenID: tokenID, ch: make(chan []byte, streamBuffer), ctx: ctx, cancel: cancel}
	h.subs[s] = struct{}{}
	h.wg.Add(1)
	return s, nil
}

// unsubscribe removes s from the map and marks its slot done, exactly once
// however many times it is called (the overflow path and the handler's defer
// may both call it). Takes mu itself, so callers must NOT hold it.
func (h *Hub) unsubscribe(s *subscriber) {
	s.once.Do(func() {
		h.mu.Lock()
		delete(h.subs, s)
		h.mu.Unlock()
		h.wg.Done()
	})
}

// Broadcast delivers payload to every subscriber's buffer without blocking.
// A subscriber whose buffer is full is collected under the lock and, after
// the lock is released, cancelled with causeSlowConsumer and unsubscribed —
// never while holding mu, which unsubscribe takes itself. payload is shared
// by reference with every subscriber; callers must not mutate it after this
// call.
func (h *Hub) Broadcast(payload []byte) {
	var overflowed []*subscriber
	h.mu.Lock()
	for s := range h.subs {
		select {
		case s.ch <- payload:
		default:
			overflowed = append(overflowed, s)
		}
	}
	h.mu.Unlock()
	for _, s := range overflowed {
		s.cancel(causeSlowConsumer)
		h.unsubscribe(s)
	}
}

// CloseToken cancels every subscriber authenticated with tokenID with
// causeRevoked; each connection's own pump sends the 4001 frame.
func (h *Hub) CloseToken(tokenID string) {
	var matched []*subscriber
	h.mu.Lock()
	for s := range h.subs {
		if s.tokenID == tokenID {
			matched = append(matched, s)
		}
	}
	h.mu.Unlock()
	for _, s := range matched {
		s.cancel(causeRevoked)
	}
}

// Shutdown cancels the hub context with causeShutdown (every subscriber
// context inherits it, and no new subscribe succeeds afterwards), then waits
// for every still-subscribed pump to unsubscribe or for ctx to expire,
// returning ctx.Err() in that case.
func (h *Hub) Shutdown(ctx context.Context) error {
	h.mu.Lock()
	h.cancel(causeShutdown)
	h.mu.Unlock()

	done := make(chan struct{})
	go func() {
		h.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// live reports the number of subscribers currently in the map.
func (h *Hub) live() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs)
}
