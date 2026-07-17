package checkin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jacaudi/diyddns/internal/shared"
)

// serverCheckinBody mirrors the SERVER's wire tags (internal/server/api/checkin.go)
// so the test guards the D7-duplicated contract against tag drift (SGE I2).
type serverCheckinBody struct {
	IPv4          string `json:"ipv4,omitempty"`
	IPv6          string `json:"ipv6,omitempty"`
	Hostname      string `json:"hostname,omitempty"`
	OS            string `json:"os,omitempty"`
	ClientVersion string `json:"client_version,omitempty"`
}

func TestClient_Checkin_SignsAndParsesFieldParity(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	secretB64 := base64.StdEncoding.EncodeToString(key)
	const deviceID = "dev-123"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		// (a) Verify the client's signature exactly as the server would.
		canonical := shared.CanonicalRequest(r.Method, r.URL.Path,
			r.Header.Get(shared.HeaderTimestamp), r.Header.Get(shared.HeaderNonce), shared.BodyHashHex(body))
		if got, want := r.Header.Get(shared.HeaderSignature), shared.Sign(key, canonical); got != want {
			t.Errorf("signature mismatch: got %s want %s", got, want)
		}
		if r.Header.Get(shared.HeaderDevice) != deviceID {
			t.Errorf("device header = %q", r.Header.Get(shared.HeaderDevice))
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", r.Header.Get("Content-Type"))
		}
		// (b) Tag-parity: body decodes into the SERVER's struct with expected fields.
		var sb serverCheckinBody
		if err := json.Unmarshal(body, &sb); err != nil {
			t.Fatalf("server-side decode: %v", err)
		}
		if sb.IPv4 != "203.0.113.7" || sb.IPv6 != "" {
			t.Errorf("decoded body = %+v, want IPv4 only", sb)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_id": deviceID, "current_ipv4": "203.0.113.7", "current_ipv6": "", "stored": true,
		})
	}))
	defer srv.Close()

	c, err := NewClient(srv.URL, deviceID, secretB64, Options{})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	c.now = func() time.Time { return time.Unix(1_700_000_000, 0) } // white-box seam
	res, err := c.Checkin(context.Background(), Report{IPv4: "203.0.113.7"})
	if err != nil {
		t.Fatalf("Checkin: %v", err)
	}
	if !res.Stored || res.CurrentIPv4 != "203.0.113.7" {
		t.Errorf("Result = %+v", res)
	}
}

func TestNewClient_BadSecret(t *testing.T) {
	if _, err := NewClient("https://x", "d", "!!!not-base64!!!", Options{}); err == nil {
		t.Error("want error for non-base64 secret")
	}
}

func TestClient_Checkin_StatusMapping(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	for _, tt := range []struct {
		code    int
		wantErr error
	}{
		{http.StatusUnauthorized, ErrUnauthorized},
		{http.StatusInternalServerError, ErrServer},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tt.code)
		}))
		c, _ := NewClient(srv.URL, "d", key, Options{})
		_, err := c.Checkin(context.Background(), Report{IPv4: "203.0.113.7"})
		if !errors.Is(err, tt.wantErr) {
			t.Errorf("status %d → err %v, want %v", tt.code, err, tt.wantErr)
		}
		srv.Close()
	}
}
