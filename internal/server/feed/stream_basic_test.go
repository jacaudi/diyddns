package feed

import (
	"context"
	"encoding/json"
	"errors"
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
	var ce websocket.CloseError
	if errors.As(err, &ce) && ce.Reason != "token revoked" {
		t.Errorf("close reason = %q, want token revoked", ce.Reason)
	}
	hub.WaitPumps()
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
