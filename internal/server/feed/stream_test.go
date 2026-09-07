package feed_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/spf13/viper"
	"go.uber.org/goleak"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/config"
	"github.com/jacaudi/diyddns/internal/server"
	"github.com/jacaudi/diyddns/internal/server/feed"
	"github.com/jacaudi/diyddns/internal/store"
)

const testToken = store.FeedTokenPrefix + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// syncBuffer is the log sink for the tests that read the log. The pump writes
// records from the handler's goroutine while the test goroutine reads them, so
// a bare bytes.Buffer here is a data race that -race reports.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// chain builds the real server handler — RequestID → AccessLog → Recover →
// mux — with the feed enabled, one minted token, and one member device, and
// serves it over a real listener. Every test here goes through the real
// chain: a bare feed handler would pass while production 501s if AccessLog's
// recorder ever lost its Unwrap (design §5.1).
//
// Cleanup order is load-bearing. t.Cleanup is LIFO, so registering the store's
// Close FIRST and the server's SECOND makes the server (and every pump it
// owns) shut down BEFORE the database does — and the goleak check each test
// registers as its own first statement therefore runs last of all, with
// nothing of this helper's still open.
func chain(t *testing.T, logBuf *syncBuffer) (*httptest.Server, *feed.Hub, *store.Store) {
	t.Helper()
	v := viper.New()
	v.Set("database.path", ":memory:")
	v.Set("auth.hmac.secret_key", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x24}, 32)))
	v.Set("server.base_url", "https://ddns.example.com")
	v.Set("feed.enabled", true)
	cfg, err := config.Load(v, "")
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	st, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "stream.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	now := store.NowUnix()
	if err := st.FeedTokens().Create(t.Context(), store.FeedToken{
		ID: "tok1", Label: "test", TokenHash: auth.HashToken(testToken), CreatedAt: now,
	}); err != nil {
		t.Fatalf("seed token: %v", err)
	}
	feed.SeedMember(t, st, "dev-a", "203.0.113.9")

	w := io.Discard
	if logBuf != nil {
		w = logBuf
	}
	log := slog.New(slog.NewJSONHandler(w, nil))
	h, hub, err := server.Handler(cfg, st, log)
	if err != nil {
		t.Fatalf("server.Handler: %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = hub.Shutdown(ctx) // idempotent; closes any pump the test left live
		srv.Close()           // also closes srv.Client()'s idle connections
		http.DefaultClient.CloseIdleConnections()
	})
	return srv, hub, st
}

func wsURL(srv *httptest.Server) string {
	return "ws" + strings.TrimPrefix(srv.URL, "http") + "/feed/v1/stream"
}

func dial(t *testing.T, srv *httptest.Server, opts *websocket.DialOptions) *websocket.Conn {
	t.Helper()
	if opts == nil {
		opts = &websocket.DialOptions{}
	}
	if opts.HTTPHeader == nil {
		opts.HTTPHeader = http.Header{}
	}
	opts.HTTPHeader.Set("Authorization", "Bearer "+testToken)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	conn, resp, err := websocket.Dial(ctx, wsURL(srv), opts)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close() // nil on a successful upgrade: the library takes the conn over
	}
	if err != nil {
		t.Fatalf("dial through the real chain: %v (a 501 here means AccessLog's recorder lost Unwrap)", err)
	}
	t.Cleanup(func() { _ = conn.CloseNow() })
	return conn
}

// readFrame returns an error rather than calling t.Fatalf on a decode failure:
// one caller reads from a goroutine that is not the test's own, where Fatalf
// is documented misuse and does not stop the test.
func readFrame(t *testing.T, conn *websocket.Conn, within time.Duration) (map[string]any, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), within)
	defer cancel()
	_, b, err := conn.Read(ctx)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("frame is not JSON: %w (%s)", err, b)
	}
	return m, nil
}

func mustFrame(t *testing.T, conn *websocket.Conn) map[string]any {
	t.Helper()
	m, err := readFrame(t, conn, 5*time.Second)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return m
}

func getJSON(t *testing.T, srv *httptest.Server) []byte {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/feed/v1/devices.json", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("GET devices.json: %d %s", resp.StatusCode, b)
	}
	return b
}

func TestStream_ThroughRealChain_SnapshotFirstAndEqualToJSONRoute(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })
	srv, hub, _ := chain(t, nil)

	conn := dial(t, srv, nil)
	snap := mustFrame(t, conn)
	if snap["type"] != "feed.snapshot" || snap["version"] != float64(1) {
		t.Fatalf("first frame = %v", snap)
	}
	got, _ := json.Marshal(snap["feed"])
	var want, gotDoc any
	_ = json.Unmarshal(getJSON(t, srv), &want)
	_ = json.Unmarshal(got, &gotDoc)
	wb, _ := json.Marshal(want)
	gb, _ := json.Marshal(gotDoc)
	if !bytes.Equal(wb, gb) {
		t.Errorf("snapshot feed %s != JSON route %s", gb, wb)
	}

	_ = conn.Close(websocket.StatusNormalClosure, "")
	hub.WaitPumps()
}

// TestStream_DeltasArriveInBumpOrder_AfterSnapshot: broadcasts placed by the
// beforeSnapshot hook — BEFORE the snapshot read — arrive after it, in order
// (design §5.1: a delta queued before the snapshot is subsumed by it and its
// replay converges).
func TestStream_DeltasArriveInBumpOrder_AfterSnapshot(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })
	srv, hub, st := chain(t, nil)
	t.Cleanup(feed.SetBeforeSnapshot(func() {
		// A real change the snapshot will include, then its delta queued
		// before the snapshot is rendered.
		feed.SeedMember(t, st, "dev-b", "203.0.113.10")
		hub.Broadcast([]byte(`{"version":1,"type":"device.added","id":1,"device":{"id":"dev-b"},"current":{"ipv4":"203.0.113.10","ipv6":null}}`))
		hub.Broadcast([]byte(`{"version":1,"type":"device.ip_changed","id":2}`))
	}))

	conn := dial(t, srv, nil)
	snap := mustFrame(t, conn)
	if snap["type"] != "feed.snapshot" {
		t.Fatalf("first frame = %v, want the snapshot before any queued delta", snap)
	}
	if !strings.Contains(fmt.Sprint(snap["feed"]), "dev-b") {
		t.Errorf("snapshot does not include the change made before it was rendered: %v", snap["feed"])
	}
	first, second := mustFrame(t, conn), mustFrame(t, conn)
	if first["id"] != float64(1) || second["id"] != float64(2) {
		t.Errorf("deltas = %v, %v; want ids 1 then 2", first, second)
	}
	// Replaying the subsumed delta converges: dev-b is present either way.
	_ = conn.Close(websocket.StatusNormalClosure, "")
	hub.WaitPumps()
}

func TestStream_ClientDataFrameUnderLimitIsIgnored_OverLimitCloses1009(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })
	srv, hub, _ := chain(t, nil)

	conn := dial(t, srv, nil)
	mustFrame(t, conn)
	wctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	if err := conn.Write(wctx, websocket.MessageText, []byte("keepalive")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	cancel()
	hub.Broadcast([]byte(`{"type":"still-here"}`))
	if f := mustFrame(t, conn); f["type"] != "still-here" {
		t.Fatalf("after a client data frame the stream must stay up; got %v", f)
	}

	wctx, cancel = context.WithTimeout(t.Context(), 2*time.Second)
	_ = conn.Write(wctx, websocket.MessageText, bytes.Repeat([]byte("x"), 8192))
	cancel()
	_, err := readFrame(t, conn, 5*time.Second)
	if websocket.CloseStatus(err) != websocket.StatusMessageTooBig {
		t.Errorf("after an 8 KiB frame: err = %v, want close status 1009", err)
	}
	hub.WaitPumps()
}

// TestStream_StalledClientIsCutWith1013_ServerSide: 65 broadcasts from the
// beforeSnapshot hook, before the pump has drained anything, overflow the
// 64-slot buffer deterministically; the close is asserted on the server's
// own record because the frame is best-effort under a full window.
//
// The record — not WaitPumps or Live — is the signal. Hub.Broadcast's overflow
// path unsubscribes (and so wg.Done()s) BEFORE the pump exits, by design §5.3,
// so both of those return while the pump is still inside conn.Close waiting
// out its handshake. Poll the log instead, under the existing 10 s deadline.
func TestStream_StalledClientIsCutWith1013_ServerSide(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })
	logBuf := &syncBuffer{}
	srv, hub, _ := chain(t, logBuf)
	t.Cleanup(feed.SetBeforeSnapshot(func() {
		for range 65 {
			hub.Broadcast([]byte(`{"type":"flood"}`))
		}
	}))

	_ = dial(t, srv, nil) // the client deliberately never reads

	deadline := time.Now().Add(10 * time.Second)
	var logged string
	for time.Now().Before(deadline) {
		logged = logBuf.String()
		if strings.Contains(logged, `"msg":"feed stream closed"`) && strings.Contains(logged, `"close_code":1013`) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("log = %s, want feed stream closed with close_code 1013", logged)
}

func TestStream_ConnectionCapAnswers503(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })
	srv, hub, _ := chain(t, nil)
	var conns []*websocket.Conn
	for range 32 {
		c := dial(t, srv, nil)
		mustFrame(t, c)
		conns = append(conns, c)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, resp, err := websocket.Dial(ctx, wsURL(srv), &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": {"Bearer " + testToken}},
	})
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close() // nil on a successful upgrade: the library takes the conn over
	}
	if err == nil || resp == nil || resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("33rd dial: err=%v resp=%v, want 503", err, resp)
	}
	for _, c := range conns {
		_ = c.Close(websocket.StatusNormalClosure, "")
	}
	hub.WaitPumps()
}

func TestStream_RevokeCloses4001(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })
	srv, hub, _ := chain(t, nil)
	conn := dial(t, srv, nil)
	mustFrame(t, conn)

	hub.CloseToken("tok1")
	_, err := readFrame(t, conn, 5*time.Second)
	var ce websocket.CloseError
	if !errors.As(err, &ce) || ce.Code != 4001 || ce.Reason != "token revoked" {
		t.Fatalf("after revoke: err = %v, want close 4001 token revoked", err)
	}
	hub.WaitPumps()
}

// TestStream_ShutdownCloses1001WithinBudget: one peer answers the close
// frame, one never does; Shutdown returns nil within 10 s and the silent
// peer's later read sees 1001.
func TestStream_ShutdownCloses1001WithinBudget(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })
	srv, hub, _ := chain(t, nil)
	responsive := dial(t, srv, nil)
	mustFrame(t, responsive)
	silent := dial(t, srv, nil)
	mustFrame(t, silent)

	// The responsive peer reads (and so answers the close handshake); the
	// silent one does nothing until after Shutdown returns.
	respDone := make(chan error, 1)
	go func() {
		_, err := readFrame(t, responsive, 15*time.Second)
		respDone <- err
	}()

	start := time.Now()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if err := hub.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v after %s", err, time.Since(start))
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("Shutdown took %s, want within 10 s", d)
	}
	if err := <-respDone; websocket.CloseStatus(err) != websocket.StatusGoingAway {
		t.Errorf("responsive peer: err = %v, want 1001", err)
	}
	_, err := readFrame(t, silent, 5*time.Second)
	if websocket.CloseStatus(err) != websocket.StatusGoingAway {
		t.Errorf("silent peer read after Shutdown: err = %v, want 1001", err)
	}
}

// TestStream_ShutdownTimesOutThenPumpsStillExit: a Shutdown given an
// already-expired context returns ctx.Err() while a socket is open; the
// abandoned pump still finishes on its own, so WaitPumps before goleak.
func TestStream_ShutdownTimesOutThenPumpsStillExit(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })
	srv, hub, _ := chain(t, nil)
	conn := dial(t, srv, nil)
	mustFrame(t, conn)

	expired, cancel := context.WithCancel(t.Context())
	cancel()
	if err := hub.Shutdown(expired); !errors.Is(err, context.Canceled) {
		t.Fatalf("Shutdown(expired) = %v, want context.Canceled", err)
	}
	_, _ = readFrame(t, conn, 15*time.Second) // let the close handshake complete
	hub.WaitPumps()
}

// TestStream_PeerThatStopsAnsweringPingsIsClosed1001: with the timings
// shortened through the seams, a client that refuses to pong is cut by the
// second failed ping, within (2 × interval) + timeout.
func TestStream_PeerThatStopsAnsweringPingsIsClosed1001(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })
	t.Cleanup(feed.SetPingInterval(200 * time.Millisecond))
	t.Cleanup(feed.SetPingTimeout(100 * time.Millisecond))
	srv, hub, _ := chain(t, nil)

	conn := dial(t, srv, &websocket.DialOptions{
		OnPingReceived: func(context.Context, []byte) bool { return false },
	})
	mustFrame(t, conn)

	start := time.Now()
	_, err := readFrame(t, conn, 5*time.Second)
	var ce websocket.CloseError
	if !errors.As(err, &ce) || ce.Code != websocket.StatusGoingAway || ce.Reason != "ping failed" {
		t.Fatalf("err = %v, want 1001 ping failed", err)
	}
	if d := time.Since(start); d > 2*200*time.Millisecond+100*time.Millisecond+2*time.Second {
		t.Errorf("closed after %s, want within 2×interval + timeout (plus slack)", d)
	}
	hub.WaitPumps()
}
