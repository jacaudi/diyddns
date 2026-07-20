package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/shared"
	"github.com/jacaudi/diyddns/internal/store"
)

// openTestStore opens an in-memory store for this package's white-box tests.
func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// testKey32 returns a deterministic 32-byte AES-256-GCM key for sealing
// device secrets in tests.
func testKey32() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

// seedDeviceWithSecret creates a user and a device whose secret is sealed
// under key, returning the device and its plaintext HMAC secret so the test
// can sign requests.
func seedDeviceWithSecret(t *testing.T, st *store.Store, key []byte, label, userEmail string) (store.Device, []byte) {
	t.Helper()
	usr, err := st.Users().Create(context.Background(), store.User{Email: userEmail, Role: "user"})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	secret, err := auth.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	sealed, err := auth.SealSecret(key, secret)
	if err != nil {
		t.Fatalf("SealSecret: %v", err)
	}
	dev, err := st.Devices().Create(context.Background(), store.Device{
		UserID: usr.ID, Label: label, SecretHash: sealed,
	})
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	return dev, secret
}

// TestHMACMiddleware_ProbesBodyRestoreAndAuth is the P1/P3 probe: it registers
// a throwaway guarded operation on a real humago API with hmacMiddleware
// attached, and proves (a) a correctly-signed request reaches the handler AND
// the handler can still read the JSON body (huma's body-restore contract
// against v2.38.0), (b) an unsigned request is rejected with 401, and
// (c) an oversize body is rejected with 413 before HMAC verification runs.
func TestHMACMiddleware_ProbesBodyRestoreAndAuth(t *testing.T) {
	st := openTestStore(t)
	key := testKey32()
	dev, secret := seedDeviceWithSecret(t, st, key, "probe-device", "probe@example.com")
	v := auth.NewVerifier(st.Devices(), st.Users(), st.ReplayNonces(), key, 120*time.Second, 120*time.Second)

	const path = "/agent/v1/probe"

	mux := http.NewServeMux()
	probeAPI := humago.New(mux, huma.DefaultConfig("probe", "1"))

	type reqBody struct {
		IPv4 string `json:"ipv4"`
	}
	type in struct {
		Body reqBody
	}
	type respBody struct {
		Echo     string `json:"echo"`
		DeviceID string `json:"deviceId"`
	}
	type out struct {
		Body respBody
	}

	huma.Register(probeAPI, huma.Operation{
		Method:      http.MethodPost,
		Path:        path,
		Middlewares: huma.Middlewares{hmacMiddleware(probeAPI, v, maxAgentBody)},
	}, func(ctx context.Context, i *in) (*out, error) {
		o := &out{}
		o.Body.Echo = i.Body.IPv4
		o.Body.DeviceID = DeviceIDFrom(ctx)
		return o, nil
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	signedRequest := func(t *testing.T, nonce string, body []byte) *http.Request {
		t.Helper()
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		canonical := shared.CanonicalRequest(http.MethodPost, path, ts, nonce, shared.BodyHashHex(body))
		req, err := http.NewRequest(http.MethodPost, srv.URL+path, bytes.NewReader(body))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(shared.HeaderDevice, dev.ID)
		req.Header.Set(shared.HeaderTimestamp, ts)
		req.Header.Set(shared.HeaderNonce, nonce)
		req.Header.Set(shared.HeaderSignature, shared.Sign(secret, canonical))
		return req
	}

	t.Run("signed request reaches handler with restored body and device id", func(t *testing.T) {
		body := []byte(`{"ipv4":"1.2.3.4"}`)
		resp, err := http.DefaultClient.Do(signedRequest(t, "nonce-signed", body))
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		defer resp.Body.Close()

		respBytes, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%s", resp.StatusCode, respBytes)
		}

		var got respBody
		if err := json.Unmarshal(respBytes, &got); err != nil {
			t.Fatalf("decode response: %v, body=%s", err, respBytes)
		}
		if got.Echo != "1.2.3.4" {
			t.Fatalf("Echo = %q, want 1.2.3.4 (handler did not see the signed body: body-restore failed)", got.Echo)
		}
		if got.DeviceID != dev.ID {
			t.Fatalf("DeviceID = %q, want %q", got.DeviceID, dev.ID)
		}
	})

	t.Run("unsigned request is rejected 401", func(t *testing.T) {
		body := []byte(`{"ipv4":"1.2.3.4"}`)
		req, err := http.NewRequest(http.MethodPost, srv.URL+path, bytes.NewReader(body))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", resp.StatusCode)
		}
	})

	t.Run("oversize body is rejected 413 before verification", func(t *testing.T) {
		body := bytes.Repeat([]byte("a"), maxAgentBody+1)
		req, err := http.NewRequest(http.MethodPost, srv.URL+path, bytes.NewReader(body))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want 413", resp.StatusCode)
		}
	})
}

const testCookieName = "diyddns_session"

// registerSessionProbe wires a throwaway guarded op with sessionMiddleware
// (and csrfMiddleware, when withCSRF is true, chained after — the required
// ordering) and returns the server plus the seeded user/session.
func registerSessionProbe(t *testing.T, withCSRF bool) (*httptest.Server, store.User, store.Session) {
	t.Helper()
	st := openTestStore(t)
	usr, err := st.Users().Create(context.Background(), store.User{Email: "session@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	sm := auth.NewSessionManager(st.Sessions(), st.Users(), time.Hour, time.Minute)
	sess, err := sm.Create(context.Background(), usr.ID, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("SessionManager.Create: %v", err)
	}

	const path = "/api/v1/probe"
	mux := http.NewServeMux()
	probeAPI := humago.New(mux, huma.DefaultConfig("session-probe", "1"))

	type out struct {
		Body struct {
			UserID    string `json:"userId"`
			SessionID string `json:"sessionId"`
		}
	}

	mws := huma.Middlewares{sessionMiddleware(probeAPI, sm, testCookieName)}
	if withCSRF {
		mws = append(mws, csrfMiddleware(probeAPI))
	}

	huma.Register(probeAPI, huma.Operation{
		Method:      http.MethodGet,
		Path:        path,
		Middlewares: mws,
	}, func(ctx context.Context, _ *struct{}) (*out, error) {
		o := &out{}
		o.Body.UserID = UserFrom(ctx).ID
		o.Body.SessionID = SessionFrom(ctx).ID
		return o, nil
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, usr, sess
}

func TestSessionMiddleware_CookieAuthForwardsUserAndSession(t *testing.T) {
	srv, usr, sess := registerSessionProbe(t, false)

	t.Run("valid cookie reaches handler with user and session", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/probe", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.AddCookie(&http.Cookie{Name: testCookieName, Value: sess.ID})

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		defer resp.Body.Close()

		respBytes, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%s", resp.StatusCode, respBytes)
		}
		var got struct {
			UserID    string `json:"userId"`
			SessionID string `json:"sessionId"`
		}
		if err := json.Unmarshal(respBytes, &got); err != nil {
			t.Fatalf("decode response: %v, body=%s", err, respBytes)
		}
		if got.UserID != usr.ID {
			t.Fatalf("UserID = %q, want %q", got.UserID, usr.ID)
		}
		if got.SessionID != sess.ID {
			t.Fatalf("SessionID = %q, want %q", got.SessionID, sess.ID)
		}
	})

	t.Run("missing cookie is rejected 401", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "/api/v1/probe")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", resp.StatusCode)
		}
	})

	t.Run("unknown session id is rejected 401", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/probe", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.AddCookie(&http.Cookie{Name: testCookieName, Value: "not-a-real-session"})

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", resp.StatusCode)
		}
	})
}

// registerAdminProbe wires a throwaway guarded op behind sessionMiddleware +
// adminMiddleware (the required ordering) and returns the server plus an
// admin-role session and a non-admin-role session.
func registerAdminProbe(t *testing.T) (srv *httptest.Server, adminSess, userSess store.Session) {
	t.Helper()
	st := openTestStore(t)
	admin, err := st.Users().Create(context.Background(), store.User{Email: "admin@example.com", Role: "admin"})
	if err != nil {
		t.Fatalf("seed admin user: %v", err)
	}
	usr, err := st.Users().Create(context.Background(), store.User{Email: "user@example.com", Role: "user"})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	sm := auth.NewSessionManager(st.Sessions(), st.Users(), time.Hour, time.Minute)
	adminSess, err = sm.Create(context.Background(), admin.ID, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("SessionManager.Create (admin): %v", err)
	}
	userSess, err = sm.Create(context.Background(), usr.ID, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("SessionManager.Create (user): %v", err)
	}

	const path = "/admin/v1/probe"
	mux := http.NewServeMux()
	probeAPI := humago.New(mux, huma.DefaultConfig("admin-probe", "1"))

	type out struct {
		Body struct {
			OK bool `json:"ok"`
		}
	}

	huma.Register(probeAPI, huma.Operation{
		Method: http.MethodGet,
		Path:   path,
		Middlewares: huma.Middlewares{
			sessionMiddleware(probeAPI, sm, testCookieName),
			adminMiddleware(probeAPI),
		},
	}, func(ctx context.Context, _ *struct{}) (*out, error) {
		o := &out{}
		o.Body.OK = true
		return o, nil
	})

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, adminSess, userSess
}

func TestAdminMiddleware_ForbidsNonAdmin(t *testing.T) {
	srv, adminSess, userSess := registerAdminProbe(t)

	t.Run("admin session succeeds", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/admin/v1/probe", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.AddCookie(&http.Cookie{Name: testCookieName, Value: adminSess.ID})

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("status = %d, want 200, body=%s", resp.StatusCode, body)
		}
	})

	t.Run("non-admin session is rejected 403", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/admin/v1/probe", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.AddCookie(&http.Cookie{Name: testCookieName, Value: userSess.ID})

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", resp.StatusCode)
		}
	})
}

func TestCSRFMiddleware_RunsAfterSessionAndComparesConstantTime(t *testing.T) {
	srv, _, sess := registerSessionProbe(t, true)

	t.Run("matching csrf token succeeds", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/probe", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.AddCookie(&http.Cookie{Name: testCookieName, Value: sess.ID})
		req.Header.Set("X-CSRF-Token", sess.CSRFToken)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("status = %d, want 200, body=%s", resp.StatusCode, body)
		}
	})

	t.Run("mismatched csrf token is rejected 403", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/probe", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.AddCookie(&http.Cookie{Name: testCookieName, Value: sess.ID})
		req.Header.Set("X-CSRF-Token", "wrong-token")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", resp.StatusCode)
		}
	})

	t.Run("missing csrf token is rejected 403", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/probe", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.AddCookie(&http.Cookie{Name: testCookieName, Value: sess.ID})

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", resp.StatusCode)
		}
	})
}
