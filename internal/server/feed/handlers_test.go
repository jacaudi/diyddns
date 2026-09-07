package feed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jacaudi/diyddns/internal/store"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// fakeAuth answers Authenticate from a map of plaintext -> token, or with a
// caller-supplied error, so middleware tests need no FeedService.
type fakeAuth struct {
	tokens map[string]store.FeedToken
	err    error
}

func (f fakeAuth) Authenticate(_ context.Context, plaintext string) (store.FeedToken, error) {
	if f.err != nil {
		return store.FeedToken{}, f.err
	}
	if tok, ok := f.tokens[plaintext]; ok {
		return tok, nil
	}
	return store.FeedToken{}, store.ErrNotFound
}

const goodToken = store.FeedTokenPrefix + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "feed.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// newFeedServer serves the two REST routes through TokenMiddleware over a
// real listener. httptest.NewServer, not NewRecorder: a recorder records the
// body a HEAD handler writes, a real server suppresses it (design §4.6).
func newFeedServer(t *testing.T, st *store.Store, auth Authenticator, logBuf *bytes.Buffer) *httptest.Server {
	t.Helper()
	// w := io.Discard, not `var w io.Writer = io.Discard`: io.Discard is
	// already declared as an io.Writer, so the explicit type is what
	// staticcheck's ST1023 flags.
	w := io.Discard
	if logBuf != nil {
		w = logBuf
	}
	log := slog.New(slog.NewJSONHandler(w, nil))
	mux := http.NewServeMux()
	Register(mux, Deps{Store: st, Auth: auth, Hub: New(), Log: log})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// httpResult is what doReq hands back instead of the *http.Response itself:
// the status, headers and length every assertion here reads, with the body
// already read and closed. Returning the response would make each of the
// thirteen call sites responsible for closing a body doReq has already
// drained — bodyclose flags the CALL, not the helper, and bodyclose is not in
// .golangci.yml's `_test.go` exclusion list. The field names are chosen to
// match *http.Response so no call site changes.
type httpResult struct {
	StatusCode    int
	Header        http.Header
	ContentLength int64
}

func doReq(t *testing.T, method, url string, headers map[string]string) (httpResult, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return httpResult{StatusCode: resp.StatusCode, Header: resp.Header, ContentLength: resp.ContentLength}, body
}

func bearer(tok string) map[string]string { return map[string]string{"Authorization": "Bearer " + tok} }

// TestTokenMiddleware_RejectionsAreUniformAndLogged is the #106 door in the
// #100 style: every rejection returns the same 401 body, and the reason goes
// to the log only, with the route.
func TestTokenMiddleware_RejectionsAreUniformAndLogged(t *testing.T) {
	st := newTestStore(t)
	tests := []struct {
		name       string
		headers    map[string]string
		auth       Authenticator
		wantReason string
	}{
		{"no header", nil, fakeAuth{}, "no_token"},
		{"not bearer", map[string]string{"Authorization": "Basic abc"}, fakeAuth{}, "malformed"},
		{"bearer without prefix", bearer("nope"), fakeAuth{}, "malformed"},
		{"unknown token", bearer(goodToken), fakeAuth{}, "unknown_token"},
		{"store error", bearer(goodToken), fakeAuth{err: errors.New("disk on fire")}, "store_error"},
		{"cancelled", bearer(goodToken), fakeAuth{err: context.Canceled}, "cancelled"},
	}
	var bodies [][]byte
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var logBuf bytes.Buffer
			srv := newFeedServer(t, st, tc.auth, &logBuf)
			resp, body := doReq(t, http.MethodGet, srv.URL+"/feed/v1/devices.txt", tc.headers)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", resp.StatusCode)
			}
			if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", ct)
			}
			bodies = append(bodies, body)
			if !strings.Contains(logBuf.String(), `"msg":"feed auth rejected"`) ||
				!strings.Contains(logBuf.String(), `"reason":"`+tc.wantReason+`"`) ||
				!strings.Contains(logBuf.String(), `"route":"GET /feed/v1/devices.txt"`) {
				t.Errorf("log = %s, want feed auth rejected with reason %s and the route", logBuf.String(), tc.wantReason)
			}
			if strings.Contains(logBuf.String(), goodToken) {
				t.Error("the presented token reached the log")
			}
		})
	}
	for i := 1; i < len(bodies); i++ {
		if !bytes.Equal(bodies[0], bodies[i]) {
			t.Errorf("401 bodies differ across reasons: %q vs %q", bodies[0], bodies[i])
		}
	}
	if !bytes.Equal(bodies[0], []byte(`{"error":"unauthorized"}`)) {
		t.Errorf("401 body = %q, want {\"error\":\"unauthorized\"}", bodies[0])
	}
}

func TestDocuments_TextAndJSON(t *testing.T) {
	st := newTestStore(t)
	SeedMember(t, st, "dev-a", "203.0.113.9")
	SeedMember(t, st, "dev-b", "203.0.113.9")
	auth := fakeAuth{tokens: map[string]store.FeedToken{goodToken: {ID: "tok1"}}}
	srv := newFeedServer(t, st, auth, nil)

	resp, body := doReq(t, http.MethodGet, srv.URL+"/feed/v1/devices.txt", bearer(goodToken))
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Fatalf("text: status %d content-type %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if string(body) != "# diyddns feed v1\n203.0.113.9/32\n" {
		t.Errorf("text body = %q", body)
	}
	if resp.Header.Get("ETag") == "" || resp.Header.Get("Last-Modified") == "" || resp.Header.Get("Cache-Control") != "no-cache" {
		t.Errorf("headers = %v, want ETag, Last-Modified and Cache-Control: no-cache", resp.Header)
	}

	resp, body = doReq(t, http.MethodGet, srv.URL+"/feed/v1/devices.json", bearer(goodToken))
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("json: status %d content-type %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	var doc struct {
		Version int      `json:"version"`
		CIDRs   []string `json:"cidrs"`
		Devices []struct {
			ID     string  `json:"id"`
			Label  string  `json:"label"`
			IPv4   *string `json:"ipv4"`
			UserID *string `json:"user_id"`
		} `json:"devices"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("json body: %v (%s)", err, body)
	}
	if doc.Version != 1 || len(doc.CIDRs) != 1 || doc.CIDRs[0] != "203.0.113.9/32" || len(doc.Devices) != 2 {
		t.Errorf("json doc = %+v", doc)
	}
	if doc.Devices[0].UserID != nil {
		t.Error("user_id must not appear in the feed (D21)")
	}
	if strings.Contains(string(body), "user_id") {
		t.Error("user_id key present in the JSON document")
	}
}

func TestDocuments_ConditionalRequests(t *testing.T) {
	st := newTestStore(t)
	SeedMember(t, st, "dev-a", "203.0.113.9")
	auth := fakeAuth{tokens: map[string]store.FeedToken{goodToken: {ID: "tok1"}}}
	srv := newFeedServer(t, st, auth, nil)

	resp, _ := doReq(t, http.MethodGet, srv.URL+"/feed/v1/devices.txt", bearer(goodToken))
	etag := resp.Header.Get("ETag")
	lastMod := resp.Header.Get("Last-Modified")

	h := bearer(goodToken)
	h["If-None-Match"] = etag
	resp, body := doReq(t, http.MethodGet, srv.URL+"/feed/v1/devices.txt", h)
	if resp.StatusCode != http.StatusNotModified || len(body) != 0 {
		t.Errorf("If-None-Match match: status %d body %q, want 304 and empty", resp.StatusCode, body)
	}
	if resp.Header.Get("ETag") != etag || resp.Header.Get("Last-Modified") != lastMod {
		t.Errorf("304 must carry ETag and Last-Modified; got %v", resp.Header)
	}

	h = bearer(goodToken)
	h["If-None-Match"] = `"stale", ` + etag
	if resp, _ := doReq(t, http.MethodGet, srv.URL+"/feed/v1/devices.txt", h); resp.StatusCode != http.StatusNotModified {
		t.Errorf("If-None-Match list containing the tag: status %d, want 304", resp.StatusCode)
	}
	h = bearer(goodToken)
	h["If-None-Match"] = "*"
	if resp, _ := doReq(t, http.MethodGet, srv.URL+"/feed/v1/devices.txt", h); resp.StatusCode != http.StatusNotModified {
		t.Errorf("If-None-Match *: status %d, want 304", resp.StatusCode)
	}
	h = bearer(goodToken)
	h["If-None-Match"] = `"stale"`
	if resp, _ := doReq(t, http.MethodGet, srv.URL+"/feed/v1/devices.txt", h); resp.StatusCode != 200 {
		t.Errorf("If-None-Match mismatch: status %d, want 200", resp.StatusCode)
	}

	// If-Modified-Since is ignored: Last-Modified is informational only
	// (design §4.6), so a matching value must still get the full document.
	h = bearer(goodToken)
	h["If-Modified-Since"] = lastMod
	if resp, body := doReq(t, http.MethodGet, srv.URL+"/feed/v1/devices.txt", h); resp.StatusCode != 200 || len(body) == 0 {
		t.Errorf("If-Modified-Since: status %d body %q, want 200 with the document", resp.StatusCode, body)
	}
}

// TestDocuments_PerDocumentETags is the route-level half of design D8/§4.5:
// each document's tag is the SHA-256 of ITS OWN body, so a change confined to
// the JSON document (a label edit) must leave the text tag alone AND must not
// let a JSON poller keep a 304 against its old tag.
func TestDocuments_PerDocumentETags(t *testing.T) {
	st := newTestStore(t)
	SeedMember(t, st, "dev-a", "203.0.113.9")
	auth := fakeAuth{tokens: map[string]store.FeedToken{goodToken: {ID: "tok1"}}}
	srv := newFeedServer(t, st, auth, nil)

	txtResp, _ := doReq(t, http.MethodGet, srv.URL+"/feed/v1/devices.txt", bearer(goodToken))
	jsonResp, _ := doReq(t, http.MethodGet, srv.URL+"/feed/v1/devices.json", bearer(goodToken))
	txtTag, jsonTag := txtResp.Header.Get("ETag"), jsonResp.Header.Get("ETag")
	if txtTag == "" || jsonTag == "" || txtTag == jsonTag {
		t.Fatalf("per-document tags: text %s json %s, want two different non-empty tags", txtTag, jsonTag)
	}

	if _, err := st.DB().ExecContext(t.Context(),
		`UPDATE devices SET label = 'renamed' WHERE id = 'dev-a'`); err != nil {
		t.Fatalf("rename device: %v", err)
	}

	h := bearer(goodToken)
	h["If-None-Match"] = txtTag
	if resp, _ := doReq(t, http.MethodGet, srv.URL+"/feed/v1/devices.txt", h); resp.StatusCode != http.StatusNotModified {
		t.Errorf("text after a label-only edit: status %d, want 304 (its body is unchanged)", resp.StatusCode)
	}
	h = bearer(goodToken)
	h["If-None-Match"] = jsonTag
	resp, body := doReq(t, http.MethodGet, srv.URL+"/feed/v1/devices.json", h)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("json after a label-only edit: status %d, want 200 — a stale JSON tag must never 304", resp.StatusCode)
	}
	if !strings.Contains(string(body), `"renamed"`) {
		t.Errorf("json body = %s, want the new label", body)
	}
	if resp.Header.Get("ETag") == jsonTag {
		t.Error("the json tag did not move after a label edit")
	}
}

// TestDocuments_HEAD: headers only, Content-Length preserved — through a real
// server, because httptest.NewRecorder would record the body.
func TestDocuments_HEAD(t *testing.T) {
	st := newTestStore(t)
	SeedMember(t, st, "dev-a", "203.0.113.9")
	auth := fakeAuth{tokens: map[string]store.FeedToken{goodToken: {ID: "tok1"}}}
	srv := newFeedServer(t, st, auth, nil)

	resp, body := doReq(t, http.MethodHead, srv.URL+"/feed/v1/devices.json", bearer(goodToken))
	if resp.StatusCode != 200 || len(body) != 0 {
		t.Fatalf("HEAD: status %d body %q, want 200 and no body", resp.StatusCode, body)
	}
	if resp.Header.Get("ETag") == "" || resp.Header.Get("Last-Modified") == "" || resp.ContentLength <= 0 {
		t.Errorf("HEAD headers = %v content-length %d, want ETag, Last-Modified and a positive Content-Length", resp.Header, resp.ContentLength)
	}
}

// TestDocuments_StoreFailureIs500WithBody: never a 200 with an empty body —
// a consumer must keep its last good copy (design §4.7).
func TestDocuments_StoreFailureIs500WithBody(t *testing.T) {
	st := newTestStore(t)
	auth := fakeAuth{tokens: map[string]store.FeedToken{goodToken: {ID: "tok1"}}}
	srv := newFeedServer(t, st, auth, nil)
	_ = st.Close()

	resp, body := doReq(t, http.MethodGet, srv.URL+"/feed/v1/devices.txt", bearer(goodToken))
	if resp.StatusCode != http.StatusInternalServerError || string(body) != "# diyddns feed unavailable\n" {
		t.Errorf("text: status %d body %q", resp.StatusCode, body)
	}
	resp, body = doReq(t, http.MethodGet, srv.URL+"/feed/v1/devices.json", bearer(goodToken))
	if resp.StatusCode != http.StatusInternalServerError || string(body) != `{"error":"feed unavailable"}` {
		t.Errorf("json: status %d body %q", resp.StatusCode, body)
	}
}

// TestDocuments_PostIsMethodNotAllowed pins the plain-mux behaviour the
// README documents: only GET and HEAD are served.
func TestDocuments_PostIsMethodNotAllowed(t *testing.T) {
	st := newTestStore(t)
	srv := newFeedServer(t, st, fakeAuth{}, nil)
	resp, _ := doReq(t, http.MethodPost, srv.URL+"/feed/v1/devices.txt", bearer(goodToken))
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST status = %d, want 405", resp.StatusCode)
	}
}
