package feed

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/jacaudi/diyddns/internal/store"
)

// beforeSnapshot is a test seam: when non-nil the stream handler calls it
// immediately before rendering the snapshot (after Accept and SetReadLimit),
// so a test can place a broadcast between subscribe and the snapshot read
// deterministically. Nil in production. Set only through export_test.go.
var beforeSnapshot func()

// snapshotEnvelope is the first frame on every stream: the JSON document
// wrapped with its own type, so a consumer starts from complete state.
type snapshotEnvelope struct {
	Version int             `json:"version"`
	Type    string          `json:"type"`
	Feed    json.RawMessage `json:"feed"`
}

// serveStream is GET /feed/v1/stream (design §5). The handler blocks for the
// connection's lifetime: it is the writer pump, and it owns the read loop
// and the ping loop it spawns. No library call ever receives a cancellable
// context — the library hard-closes the socket when a context it holds is
// cancelled, before any close frame can be sent — so Read/Write/Ping take
// context.Background() plus a per-operation timeout, and sub.ctx is observed
// only with select.
func (h *handler) serveStream(w http.ResponseWriter, r *http.Request) {
	tokenID := TokenIDFrom(r.Context())
	sub, err := h.deps.Hub.subscribe(tokenID)
	if err != nil {
		body := `{"error":"too many streams"}`
		if errors.Is(err, ErrShuttingDown) {
			body = `{"error":"shutting down"}`
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(body))
		return
	}
	defer h.deps.Hub.unsubscribe(sub) // the ONLY unsubscribe site in this handler

	if !h.tokenStillLive(w, r, tokenID) {
		return
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{}) // no OriginPatterns: a service client, not a browser
	if err != nil {
		// Accept has already written its own error response.
		h.deps.Log.LogAttrs(r.Context(), slog.LevelWarn, "feed stream accept failed",
			slog.String("token_id", tokenID), slog.Any("error", err))
		return
	}
	conn.SetReadLimit(readLimit)
	h.deps.Log.LogAttrs(r.Context(), slog.LevelInfo, "feed stream opened", slog.String("token_id", tokenID))
	// r.Context() is not used past this point (design §5.1): it is not
	// cancelled when a hijacked client goes away, and the library's own
	// contexts must never be cancellable.
	logCtx := context.WithoutCancel(r.Context())

	h.runStream(logCtx, conn, sub, tokenID)
}

// tokenStillLive re-checks the token row right after subscribe succeeds but
// before Accept (finding S1): service.FeedService.RevokeToken deletes the
// row BEFORE calling Hub.CloseToken, so a revoke landing strictly between
// TokenMiddleware's Authenticate and this subscribe is invisible to
// CloseToken — the subscriber isn't in the hub's map yet for CloseToken to
// find. This re-check closes that window: a revoke before this call is
// caught here (the row is already gone), and a revoke from this call onward
// is caught by CloseToken, because the subscriber is now in the map. On
// refusal it writes the response itself (the same uniform 401 body the
// middleware uses, or the feed's store-failure 503) and returns false so
// serveStream returns without ever calling Accept; the deferred unsubscribe
// still runs.
func (h *handler) tokenStillLive(w http.ResponseWriter, r *http.Request, tokenID string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
	defer cancel()
	_, err := h.deps.Store.FeedTokens().GetByID(ctx, tokenID)
	if err == nil {
		return true
	}

	reason, status, body := "store_error", http.StatusServiceUnavailable, []byte(`{"error":"feed unavailable"}`)
	if errors.Is(err, store.ErrNotFound) {
		reason, status, body = "revoked", http.StatusUnauthorized, []byte(unauthorizedBody)
	}
	h.deps.Log.LogAttrs(r.Context(), slog.LevelWarn, "feed stream refused",
		slog.String("token_id", tokenID), slog.String("reason", reason))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(body)
	return false
}

// runStream is the pump plus its two goroutines, and the exit sequence. The
// work is in named helpers below: this function is the order they run in.
func (h *handler) runStream(logCtx context.Context, conn *websocket.Conn, sub *subscriber, tokenID string) {
	write := func(b []byte) error {
		wctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
		defer cancel()
		return conn.Write(wctx, websocket.MessageText, b)
	}

	var connWG sync.WaitGroup
	connWG.Go(func() { readLoop(conn, sub) })
	connWG.Go(func() { pingLoop(conn, sub) })

	if beforeSnapshot != nil {
		beforeSnapshot()
	}
	h.sendSnapshot(logCtx, sub, tokenID, write)
	pump(sub, write)

	cause := causeOf(sub.ctx)
	if cause == causeShutdown && !errors.Is(context.Cause(sub.ctx), causeShutdown) {
		h.deps.Log.LogAttrs(logCtx, slog.LevelWarn, "feed stream cause unexpected",
			slog.String("token_id", tokenID), slog.Any("cause", context.Cause(sub.ctx)))
	}
	h.closeExit(logCtx, conn, cause, tokenID)
	connWG.Wait()

	h.deps.Log.LogAttrs(logCtx, slog.LevelInfo, "feed stream closed",
		slog.String("token_id", tokenID),
		slog.Int("close_code", int(cause.Code)),
		slog.String("reason", closeReason(cause)))
}

// readLoop discards every inbound frame under the read limit; its first
// error — a client close frame, a reset, a read-limit violation — is THE
// disconnect signal. Read takes context.Background() plus no deadline: a
// cancellable context here would make the library hard-close the socket
// before a close frame could be sent (design §5.1).
func readLoop(conn *websocket.Conn, sub *subscriber) {
	for {
		if _, _, err := conn.Read(context.Background()); err != nil {
			sub.cancel(causePeerGone(err))
			return
		}
	}
}

// pingLoop is a free-running ticker; two consecutive failed pings (each under
// pingTimeout, which is Ping's only failure mode short of a closed
// connection) cancel the subscriber. sub.ctx is observed only with select,
// and Ping gets context.Background() plus its own timeout (design §5.1).
func pingLoop(conn *websocket.Conn, sub *subscriber) {
	tick := time.Tick(pingInterval)
	failures := 0
	for {
		select {
		case <-sub.ctx.Done():
			return
		case <-tick:
			pctx, cancel := context.WithTimeout(context.Background(), pingTimeout)
			err := conn.Ping(pctx)
			cancel()
			if err == nil {
				failures = 0
				continue
			}
			failures++
			if failures >= 2 {
				sub.cancel(causePingFailed)
				return
			}
		}
	}
}

// sendSnapshot renders the current feed and writes it as the connection's
// first frame. Every failure cancels sub with the matching cause rather than
// returning an error: the exit sequence belongs to runStream alone.
func (h *handler) sendSnapshot(logCtx context.Context, sub *subscriber, tokenID string, write func([]byte) error) {
	snapCtx, cancelSnap := context.WithTimeout(context.Background(), writeTimeout)
	snap, _, err := h.current(snapCtx)
	cancelSnap()
	if err != nil {
		h.snapshotFailed(logCtx, sub, tokenID, err)
		return
	}
	env, err := json.Marshal(snapshotEnvelope{Version: Version, Type: "feed.snapshot", Feed: json.RawMessage(snap.JSON)})
	if err != nil {
		h.snapshotFailed(logCtx, sub, tokenID, err)
		return
	}
	if err := write(env); err != nil {
		sub.cancel(causePeerGone(err))
	}
}

// snapshotFailed records a snapshot that could not be produced and cuts the
// connection with 1011: a stream that never sends its first frame is worse
// than no stream, because a consumer would treat an empty feed as current.
func (h *handler) snapshotFailed(logCtx context.Context, sub *subscriber, tokenID string, err error) {
	h.deps.Log.LogAttrs(logCtx, slog.LevelError, "feed stream snapshot failed",
		slog.String("token_id", tokenID), slog.Any("error", err))
	sub.cancel(causeInternal)
}

// pump is the writer loop: it drains sub.ch until the subscriber's context is
// cancelled or a write fails. sub.ctx is observed only with select; the write
// itself carries its own background-rooted timeout (design §5.1).
func pump(sub *subscriber, write func([]byte) error) {
	for {
		select {
		case <-sub.ctx.Done():
			return
		case b := <-sub.ch:
			if err := write(b); err != nil {
				sub.cancel(causePeerGone(err)) // the library has already hard-closed the socket
				return
			}
		}
	}
}

// closeExit is the exit sequence, and its order is measured, not stylistic
// (see the divergence recorded in the plan's Task 8): Close first when there
// is a frame to send, then CloseNow unconditionally, and only then does
// runStream wait on the two goroutines. CloseNow before the wait is what
// unblocks a ping loop parked inside Ping on the peer-gone path, where no
// Close runs at all.
func (h *handler) closeExit(logCtx context.Context, conn *websocket.Conn, cause *closeCause, tokenID string) {
	if cause.Code != 0 {
		// With a responsive peer this returns at once; with a silent one the
		// library bounds it at ~5 s because the read loop above holds the
		// library's read lock (design §5.1). That error is routine: Debug only.
		if err := conn.Close(cause.Code, cause.Reason); err != nil {
			h.deps.Log.LogAttrs(logCtx, slog.LevelDebug, "feed stream close",
				slog.String("token_id", tokenID), slog.Any("error", err))
		}
	}
	_ = conn.CloseNow() // unblocks a Read or Ping still parked; never logged
}

// closeReason renders the cause for the close record: the cause's own reason
// string, except on the peer-gone path where it is one of three fixed
// strings derived from the error (design §10) — never the raw error.
func closeReason(c *closeCause) string {
	if c.Code != 0 {
		return c.Reason
	}
	switch {
	case errors.Is(c.Err, websocket.ErrMessageTooBig):
		return "read_limit"
	case websocket.CloseStatus(c.Err) != -1:
		return "peer_closed"
	default:
		return "read_error"
	}
}
