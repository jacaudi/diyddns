package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
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

// captureLogger returns a JSON logger writing into the returned buffer, so a
// probe can assert on the records its middleware emits. api_test.go's
// discardLogger is in package api_test and is unreachable from these
// white-box tests.
func captureLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})), &buf
}

// findRecord returns the first JSON record in buf whose msg matches, or fails.
func findRecord(t *testing.T, buf *bytes.Buffer, msg string) map[string]any {
	t.Helper()
	for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line not JSON: %v (%s)", err, line)
		}
		if rec["msg"] == msg {
			return rec
		}
	}
	t.Fatalf("no record with msg %q in:\n%s", msg, buf.String())
	return nil
}

// hmacProbe wires a throwaway operation behind hmacMiddleware, mirroring
// TestHMACMiddleware_ProbesBodyRestoreAndAuth. It returns a signed-request
// builder, the middleware's log buffer, and the seeded device with its
// plaintext secret so a caller can break exactly one input.
func hmacProbe(t *testing.T) (build func(*testing.T, []byte, string) *http.Request, buf *bytes.Buffer, dev store.Device, secret []byte) {
	t.Helper()
	const path = "/agent/v1/probe"

	st := openTestStore(t)
	key := testKey32()
	dev, secret = seedDeviceWithSecret(t, st, key, "probe", "probe@example.test")
	v := auth.NewVerifier(st.Devices(), st.Users(), st.ReplayNonces(), key, 120*time.Second, 120*time.Second)

	log, buf := captureLogger()

	mux := http.NewServeMux()
	probeAPI := humago.New(mux, huma.DefaultConfig("probe", "1"))
	type out struct {
		Body struct {
			OK bool `json:"ok"`
		}
	}
	huma.Register(probeAPI, huma.Operation{
		Method:      http.MethodPost,
		Path:        path,
		Middlewares: huma.Middlewares{hmacMiddleware(probeAPI, v, maxAgentBody, log)},
	}, func(context.Context, *struct{}) (*out, error) { return &out{}, nil })

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// build signs with the given secret and claims the given device header, so
	// a caller can break exactly one of them.
	build = func(t *testing.T, sec []byte, deviceHeader string) *http.Request {
		t.Helper()
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		nonce := "n-" + deviceHeader
		canonical := shared.CanonicalRequest(http.MethodPost, path, ts, nonce, shared.BodyHashHex(nil))
		req, err := http.NewRequest(http.MethodPost, srv.URL+path, nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set(shared.HeaderDevice, deviceHeader)
		req.Header.Set(shared.HeaderTimestamp, ts)
		req.Header.Set(shared.HeaderNonce, nonce)
		req.Header.Set(shared.HeaderSignature, shared.Sign(sec, canonical))
		return req
	}
	return build, buf, dev, secret
}

// TestHMACMiddleware_LogsRejectionReason is D12 at the agent door: the log
// names which check failed; the response does not.
func TestHMACMiddleware_LogsRejectionReason(t *testing.T) {
	build, buf, _, _ := hmacProbe(t)

	// An unknown device id: the claimed id is attacker-controlled and
	// unauthenticated, which is why the attr is named claimed_device_id.
	resp, err := http.DefaultClient.Do(build(t, []byte("wrong-secret"), "dev_does_not_exist"))
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	rec := findRecord(t, buf, "agent auth rejected")
	if rec["level"] != "WARN" {
		t.Errorf("level = %v, want WARN", rec["level"])
	}
	if rec["reason"] != "unknown_device" {
		t.Errorf("reason = %v, want unknown_device", rec["reason"])
	}
	if rec["claimed_device_id"] != "dev_does_not_exist" {
		t.Errorf("claimed_device_id = %v", rec["claimed_device_id"])
	}
	if rec["route"] != "POST /agent/v1/probe" {
		t.Errorf("route = %v, want the route template", rec["route"])
	}
}

// TestHMACMiddleware_BoundsClaimedDeviceID proves an oversized claimed device
// id is bounded before it reaches the record.
func TestHMACMiddleware_BoundsClaimedDeviceID(t *testing.T) {
	build, buf, _, _ := hmacProbe(t)

	resp, err := http.DefaultClient.Do(build(t, []byte("wrong"), strings.Repeat("d", 129)))
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	rec := findRecord(t, buf, "agent auth rejected")
	if rec["claimed_device_id"] != "" {
		t.Errorf("claimed_device_id = %q, want empty for an over-long value", rec["claimed_device_id"])
	}
}

// TestHMACMiddleware_401BodyIdenticalAcrossReasons is the enumeration guard.
// It asserts the RAW BYTES, not a decoded struct: the failure mode being
// guarded against (passing err to huma.WriteErr) ADDS a field rather than
// changing one, and a struct decode would not notice.
//
// The two cases must take DIFFERENT branches, or this compares a body to
// itself: a nonexistent device id and a real device with a wrong secret hit
// unknown_device and bad_signature respectively. hmacProbe returns the seeded
// device and secret for exactly this reason.
func TestHMACMiddleware_401BodyIdenticalAcrossReasons(t *testing.T) {
	build, buf, dev, secret := hmacProbe(t)

	cases := []struct {
		name, deviceHeader, reason string
		secret                     []byte
	}{
		{"nonexistent device", "dev_does_not_exist", "unknown_device", secret},
		{"wrong secret", dev.ID, "bad_signature", []byte("a-different-secret-entirely-32b!")},
	}

	bodies := make([]string, 0, len(cases))
	for _, c := range cases {
		resp, err := http.DefaultClient.Do(build(t, c.secret, c.deviceHeader))
		if err != nil {
			t.Fatalf("%s: Do: %v", c.name, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s: status = %d, want 401", c.name, resp.StatusCode)
		}
		bodies = append(bodies, string(b))
	}

	// Prove the two cases really took different branches — otherwise the body
	// comparison below is vacuous.
	reasons := map[string]bool{}
	for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) == nil && rec["msg"] == "agent auth rejected" {
			reason, _ := rec["reason"].(string)
			reasons[reason] = true
		}
	}
	for _, c := range cases {
		if !reasons[c.reason] {
			t.Fatalf("%s did not log reason %q; observed %v", c.name, c.reason, reasons)
		}
	}

	if bodies[0] != bodies[1] {
		t.Fatalf("401 body differs:\n  %s: %q\n  %s: %q", cases[0].name, bodies[0], cases[1].name, bodies[1])
	}
	for _, leak := range []string{"device", "signature", "disabled", "unknown"} {
		if strings.Contains(strings.ToLower(bodies[0]), leak) {
			t.Fatalf("401 body names a rejection reason (%q): %s", leak, bodies[0])
		}
	}
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
		Middlewares: huma.Middlewares{hmacMiddleware(probeAPI, v, maxAgentBody, slog.New(slog.NewJSONHandler(io.Discard, nil)))},
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
// ordering) and returns the server, the seeded user/session, and the
// middlewares' log buffer.
func registerSessionProbe(t *testing.T, withCSRF bool) (*httptest.Server, store.User, store.Session, *bytes.Buffer) {
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

	log, buf := captureLogger()
	mws := huma.Middlewares{sessionMiddleware(probeAPI, sm, testCookieName, log)}
	if withCSRF {
		mws = append(mws, csrfMiddleware(probeAPI, log))
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
	return srv, usr, sess, buf
}

func TestSessionMiddleware_CookieAuthForwardsUserAndSession(t *testing.T) {
	srv, usr, sess, _ := registerSessionProbe(t, false)

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
// admin-role session and a non-admin-role session, plus the middlewares' log
// buffer.
func registerAdminProbe(t *testing.T) (srv *httptest.Server, adminSess, userSess store.Session, buf *bytes.Buffer) {
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

	log, buf := captureLogger()
	huma.Register(probeAPI, huma.Operation{
		Method: http.MethodGet,
		Path:   path,
		Middlewares: huma.Middlewares{
			sessionMiddleware(probeAPI, sm, testCookieName, log),
			adminMiddleware(probeAPI, log),
		},
	}, func(ctx context.Context, _ *struct{}) (*out, error) {
		o := &out{}
		o.Body.OK = true
		return o, nil
	})

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, adminSess, userSess, buf
}

func TestAdminMiddleware_ForbidsNonAdmin(t *testing.T) {
	srv, adminSess, userSess, _ := registerAdminProbe(t)

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
	srv, _, sess, _ := registerSessionProbe(t, true)

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

// TestSessionMiddleware_LogsRejectionReason is D12 at the session door. It
// also proves the record names no subject: the request is unauthenticated by
// definition, and the session cookie value must never reach a log record.
func TestSessionMiddleware_LogsRejectionReason(t *testing.T) {
	tests := []struct {
		name, cookie, reason string
	}{
		{"missing cookie", "", "no_cookie"},
		{"unknown session id", "not-a-real-session", "unknown_session"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, _, _, buf := registerSessionProbe(t, false)

			req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/probe", nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			if tc.cookie != "" {
				req.AddCookie(&http.Cookie{Name: testCookieName, Value: tc.cookie})
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", resp.StatusCode)
			}

			rec := findRecord(t, buf, "session auth rejected")
			if rec["level"] != "WARN" {
				t.Errorf("level = %v, want WARN", rec["level"])
			}
			if rec["reason"] != tc.reason {
				t.Errorf("reason = %v, want %s", rec["reason"], tc.reason)
			}
			if rec["route"] != "GET /api/v1/probe" {
				t.Errorf("route = %v, want the route template", rec["route"])
			}
			if tc.cookie != "" && strings.Contains(buf.String(), tc.cookie) {
				t.Errorf("session cookie value reached the log:\n%s", buf.String())
			}
		})
	}
}

// TestCSRFMiddleware_LogsRejection is D13 at the CSRF door. It runs after
// sessionMiddleware, so the subject is a real authenticated user.
func TestCSRFMiddleware_LogsRejection(t *testing.T) {
	srv, usr, sess, buf := registerSessionProbe(t, true)

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

	rec := findRecord(t, buf, "csrf rejected")
	if rec["level"] != "WARN" {
		t.Errorf("level = %v, want WARN", rec["level"])
	}
	if rec["user_id"] != usr.ID {
		t.Errorf("user_id = %v, want %s", rec["user_id"], usr.ID)
	}
	if rec["route"] != "GET /api/v1/probe" {
		t.Errorf("route = %v, want the route template", rec["route"])
	}
}

// TestAdminMiddleware_LogsRejection is D13 at the admin door: the record names
// the user and the role that was insufficient.
func TestAdminMiddleware_LogsRejection(t *testing.T) {
	srv, _, userSess, buf := registerAdminProbe(t)

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

	rec := findRecord(t, buf, "admin role required")
	if rec["level"] != "WARN" {
		t.Errorf("level = %v, want WARN", rec["level"])
	}
	if rec["user_id"] != userSess.UserID {
		t.Errorf("user_id = %v, want %s", rec["user_id"], userSess.UserID)
	}
	if rec["role"] != "user" {
		t.Errorf("role = %v, want user", rec["role"])
	}
	if rec["route"] != "GET /admin/v1/probe" {
		t.Errorf("route = %v, want the route template", rec["route"])
	}
}

// TestAuthMiddleware_SuccessLogsNothing pins the reason logging inside the
// rejection branch. auth.ReasonOf(nil) degrades to "unknown", so a door that
// logged outside its error branch would stamp reason=unknown on every
// successful authentication.
func TestAuthMiddleware_SuccessLogsNothing(t *testing.T) {
	srv, _, sess, buf := registerSessionProbe(t, true)

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

	if buf.Len() != 0 {
		t.Errorf("successful auth wrote log records:\n%s", buf.String())
	}
}
