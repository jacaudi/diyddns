package feed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/jacaudi/diyddns/internal/store"
)

func dialStream(t *testing.T, srv *httptest.Server, token string) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	// bodyclose is not excluded for _test.go: the handshake response must be
	// closed on every path. Its Body is nil on a SUCCESSFUL upgrade — the
	// library takes the connection over — so the nil check is required, not
	// defensive; without it this line panics.
	conn, resp, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/feed/v1/stream", &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": {"Bearer " + token}},
	})
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close() // nil on a successful upgrade: the library takes the conn over
	}
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.CloseNow() })
	return conn
}

func readText(t *testing.T, conn *websocket.Conn) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	typ, b, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if typ != websocket.MessageText {
		t.Fatalf("message type = %v, want text", typ)
	}
	return b
}

func TestStream_SnapshotThenDeltaThenRevoke(t *testing.T) {
	st := newTestStore(t)
	SeedMember(t, st, "dev-a", "203.0.113.9")
	// The revoke re-check (finding S1) reads the token row from the store, so
	// fakeAuth's answer must be backed by a real row even though fakeAuth
	// itself never touches the store.
	if err := st.FeedTokens().Create(t.Context(), store.FeedToken{
		ID: "tok1", Label: "test", TokenHash: "unused", CreatedAt: store.NowUnix(),
	}); err != nil {
		t.Fatalf("seed token: %v", err)
	}
	auth := fakeAuth{tokens: map[string]store.FeedToken{goodToken: {ID: "tok1"}}}
	hub := New()
	mux := http.NewServeMux()
	Register(mux, Deps{Store: st, Auth: auth, Hub: hub, Log: discardLogger()})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	conn := dialStream(t, srv, goodToken)

	var snap struct {
		Version int             `json:"version"`
		Type    string          `json:"type"`
		Feed    json.RawMessage `json:"feed"`
	}
	if err := json.Unmarshal(readText(t, conn), &snap); err != nil {
		t.Fatalf("snapshot is not JSON: %v", err)
	}
	if snap.Version != 1 || snap.Type != "feed.snapshot" || !strings.Contains(string(snap.Feed), `"cidrs":["203.0.113.9/32"]`) {
		t.Errorf("snapshot = %+v", snap)
	}

	hub.Broadcast([]byte(`{"type":"device.ip_changed","id":7}`))
	if got := readText(t, conn); string(got) != `{"type":"device.ip_changed","id":7}` {
		t.Errorf("delta = %s", got)
	}

	hub.CloseToken("tok1")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, _, err := conn.Read(ctx)
	if websocket.CloseStatus(err) != 4001 {
		t.Fatalf("after revoke: read err = %v, want close status 4001", err)
	}
	if ce, ok := errors.AsType[websocket.CloseError](err); ok && ce.Reason != "token revoked" {
		t.Errorf("close reason = %q, want token revoked", ce.Reason)
	}
	hub.WaitPumps()
}

// revokingAuth answers Authenticate by revoking the token it is handed
// BEFORE returning success: it deletes the row and calls CloseToken, exactly
// the sequence service.FeedService.RevokeToken runs. Because this happens
// before serveStream's subscribe, CloseToken finds no subscriber yet — the
// race finding S1 closes with a re-check after subscribe.
type revokingAuth struct {
	st  *store.Store
	hub *Hub
	tok store.FeedToken
}

func (a revokingAuth) Authenticate(ctx context.Context, _ string) (store.FeedToken, error) {
	if err := a.st.FeedTokens().Delete(ctx, a.tok.ID); err != nil {
		return store.FeedToken{}, err
	}
	a.hub.CloseToken(a.tok.ID)
	return a.tok, nil
}

// TestStream_RevokedBetweenAuthenticateAndSubscribeIsRefused is finding S1:
// a token revoked strictly between Authenticate and subscribe must not leave
// a live stream that never receives 4001. The upgrade must be refused with
// 401, no subscriber must remain in the hub, and the log must carry
// reason=revoked and never the plaintext.
func TestStream_RevokedBetweenAuthenticateAndSubscribeIsRefused(t *testing.T) {
	st := newTestStore(t)
	now := store.NowUnix()
	tok := store.FeedToken{ID: store.NewID(), Label: "t", TokenHash: "h", CreatedAt: now}
	if err := st.FeedTokens().Create(t.Context(), tok); err != nil {
		t.Fatalf("seed token: %v", err)
	}
	hub := New()
	var logBuf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logBuf, nil))
	mux := http.NewServeMux()
	Register(mux, Deps{Store: st, Auth: revokingAuth{st: st, hub: hub, tok: tok}, Hub: hub, Log: log})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	// bodyclose: resp.Body is non-nil only on a FAILED upgrade here (the
	// opposite of dialStream's successful-upgrade case), so it must be closed.
	_, resp, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/feed/v1/stream", &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": {"Bearer " + goodToken}},
	})
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err == nil {
		t.Fatal("dial succeeded despite the token being revoked between Authenticate and subscribe")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("handshake response = %v, want 401", resp)
	}
	if got := hub.Live(); got != 0 {
		t.Errorf("hub.Live() = %d, want 0", got)
	}
	if !strings.Contains(logBuf.String(), `"reason":"revoked"`) {
		t.Errorf("log = %s, want reason revoked", logBuf.String())
	}
	if strings.Contains(logBuf.String(), goodToken) {
		t.Error("the presented token reached the log")
	}
}

func TestStream_UnauthenticatedGets401BeforeUpgrade(t *testing.T) {
	st := newTestStore(t)
	mux := http.NewServeMux()
	Register(mux, Deps{Store: st, Auth: fakeAuth{}, Hub: New(), Log: discardLogger()})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, resp, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/feed/v1/stream", &websocket.DialOptions{})
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close() // nil on a successful upgrade: the library takes the conn over
	}
	if err == nil {
		t.Fatal("dial succeeded without a token")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("handshake response = %v, want 401", resp)
	}
}
