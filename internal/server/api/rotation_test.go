package api_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/jacaudi/diyddns/internal/auth"
	"github.com/jacaudi/diyddns/internal/server/agenttls"
	"github.com/jacaudi/diyddns/internal/shared"
	"github.com/jacaudi/diyddns/internal/store"
)

func TestCheckin_CapabilityWritesSupportsRotation(t *testing.T) {
	h := newAgentHarness(t)
	id, secret := enrollViaHTTP(t, h, "rot-cap@example.com", "laptop")

	tests := []struct {
		name string
		body map[string]any
		want bool
	}{
		{"advertised", map[string]any{"ipv4": "203.0.113.5", "capabilities": []string{shared.CapabilityRotation}}, true},
		{"omitted clears it", map[string]any{"ipv4": "203.0.113.5"}, false},
		{"unknown entry ignored", map[string]any{"ipv4": "203.0.113.5", "capabilities": []string{"future"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, body := doSigned(t, h, http.MethodPost, "/agent/v1/checkin", id, secret, tt.body)
			if status != http.StatusOK {
				t.Fatalf("status = %d, want 200, body=%s", status, body)
			}
			dev, err := h.st.Devices().GetByID(t.Context(), id)
			if err != nil {
				t.Fatalf("GetByID: %v", err)
			}
			if dev.SupportsRotation != tt.want {
				t.Errorf("SupportsRotation = %v, want %v", dev.SupportsRotation, tt.want)
			}
			if dev.LastCheckinMTLS {
				t.Error("LastCheckinMTLS = true on the main port, want false")
			}
		})
	}
}

func TestCheckin_ResponseRotationFromPrev(t *testing.T) {
	h := newAgentHarness(t)
	id, secret := enrollViaHTTP(t, h, "rot-resp@example.com", "laptop")

	type rotation struct {
		Secret bool `json:"secret"`
		Cert   bool `json:"cert"`
	}
	checkin := func(t *testing.T) rotation {
		t.Helper()
		status, body := doSigned(t, h, http.MethodPost, "/agent/v1/checkin", id, secret, map[string]string{"ipv4": "203.0.113.5"})
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%s", status, body)
		}
		var got struct {
			Rotation *rotation `json:"rotation"`
		}
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.Rotation == nil {
			t.Fatalf("rotation key absent, want always emitted, body=%s", body)
		}
		return *got.Rotation
	}

	if got := checkin(t); got != (rotation{}) {
		t.Errorf("unmarked rotation = %+v, want both false", got)
	}
	if err := h.st.Devices().MarkRotation(t.Context(), id, true, false, 1); err != nil {
		t.Fatalf("MarkRotation: %v", err)
	}
	// The check-in above sent no capability: the flags still ride (P6).
	if got := checkin(t); got != (rotation{Secret: true}) {
		t.Errorf("marked rotation = %+v, want secret only", got)
	}
}

const rotPath = "/agent/v1/rotation/secret"

// rotNewSecret is the 32 bytes 0x01..0x20 the step-3 tests propose.
func rotNewSecret() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i + 1)
	}
	return b
}

// rotBody is the step-3 request body proposing secret.
func rotBody(secret []byte) []byte {
	return []byte(`{"secret":"` + base64.StdEncoding.EncodeToString(secret) + `"}`)
}

// rotMark marks a secret rotation on the device.
func rotMark(t *testing.T, h agentHarness, id string) {
	t.Helper()
	if err := h.st.Devices().MarkRotation(t.Context(), id, true, false, 1); err != nil {
		t.Fatalf("MarkRotation: %v", err)
	}
}

// rotSend signs raw as (id, secret) with a fresh nonce and posts it to rotPath.
func rotSend(t *testing.T, h agentHarness, id string, secret, raw []byte) (int, []byte) {
	t.Helper()
	nonceSeq++
	req := signedRequest(t, http.MethodPost, h.srv.URL, rotPath, id, secret, raw, "rot-nonce-"+strconv.Itoa(nonceSeq))
	return rotDo(t, req)
}

func rotDo(t *testing.T, req *http.Request) (int, []byte) {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, out
}

// rotRow re-reads the device row.
func rotRow(t *testing.T, h agentHarness, id string) store.Device {
	t.Helper()
	dev, err := h.st.Devices().GetByID(t.Context(), id)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	return dev
}

func TestRotationSecret_StoresPending(t *testing.T) {
	h := newAgentHarness(t)
	id, secret := enrollViaHTTP(t, h, "rot-store@example.com", "laptop")
	rotMark(t, h, id)
	newSecret := rotNewSecret()

	status, body := rotSend(t, h, id, secret, rotBody(newSecret))
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", status, body)
	}
	if len(body) != 0 {
		t.Errorf("body = %q, want empty", body)
	}
	got, err := auth.OpenSecret(agentTestKey32(), rotRow(t, h, id).PendingSecretHash)
	if err != nil {
		t.Fatalf("OpenSecret: %v", err)
	}
	if !bytes.Equal(got, newSecret) {
		t.Errorf("stored pending secret differs from the one submitted")
	}
}

func TestRotationSecret_NotMarkedIs409Coded(t *testing.T) {
	h := newAgentHarness(t)
	id, secret := enrollViaHTTP(t, h, "rot-unmarked@example.com", "laptop")

	status, body := rotSend(t, h, id, secret, rotBody(rotNewSecret()))
	if status != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body=%s", status, body)
	}
	if !strings.Contains(string(body), `"code":"no_secret_rotation_pending"`) {
		t.Errorf("body = %s, want code no_secret_rotation_pending", body)
	}
}

func TestRotationSecret_BadInputIs400NoEcho(t *testing.T) {
	b31 := base64.StdEncoding.EncodeToString(make([]byte, 31))
	b33 := base64.StdEncoding.EncodeToString(make([]byte, 33))
	urlAlpha := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, 32))
	tests := []struct {
		name, body, leak string
	}{
		{"not base64", `{"secret":"!!notbase64!!"}`, "notbase64"},
		{"31 bytes", `{"secret":"` + b31 + `"}`, b31},
		{"33 bytes", `{"secret":"` + b33 + `"}`, b33},
		{"url alphabet", `{"secret":"` + urlAlpha + `"}`, urlAlpha},
		{"not a string", `{"secret":123}`, "123"},
		{"not json", `not json`, "not json"},
	}
	h := newAgentHarness(t)
	id, secret := enrollViaHTTP(t, h, "rot-bad@example.com", "laptop")
	rotMark(t, h, id)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, body := rotSend(t, h, id, secret, []byte(tt.body))
			if status != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400, body=%s", status, body)
			}
			if strings.Contains(string(body), tt.leak) {
				t.Errorf("body %s echoes the submitted value %q", body, tt.leak)
			}
		})
	}
	if row := rotRow(t, h, id); row.PendingSecretHash != "" {
		t.Errorf("PendingSecretHash = %q after rejected input, want empty", row.PendingSecretHash)
	}
}

func TestRotationSecret_EqualToCurrentIsNoOp(t *testing.T) {
	h := newAgentHarness(t)
	id, secret := enrollViaHTTP(t, h, "rot-same@example.com", "laptop")
	rotMark(t, h, id)

	status, body := rotSend(t, h, id, secret, rotBody(secret))
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", status, body)
	}
	if row := rotRow(t, h, id); row.PendingSecretHash != "" {
		t.Errorf("PendingSecretHash = %q, want empty", row.PendingSecretHash)
	}
}

func TestRotationSecret_ReplayIs401(t *testing.T) {
	h := newAgentHarness(t)
	id, secret := enrollViaHTTP(t, h, "rot-replay@example.com", "laptop")
	rotMark(t, h, id)
	raw := rotBody(rotNewSecret())
	first := signedRequest(t, http.MethodPost, h.srv.URL, rotPath, id, secret, raw, "rot-replay-nonce")
	hdr := first.Header.Clone()

	if status, body := rotDo(t, first); status != http.StatusOK {
		t.Fatalf("first status = %d, want 200, body=%s", status, body)
	}
	second, err := http.NewRequestWithContext(t.Context(), http.MethodPost, h.srv.URL+rotPath, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	second.Header = hdr
	if status, body := rotDo(t, second); status != http.StatusUnauthorized {
		t.Errorf("replay status = %d, want 401, body=%s", status, body)
	}
}

func TestRotationSecret_FullFlow(t *testing.T) {
	h := newAgentHarness(t)
	id, secret := enrollViaHTTP(t, h, "rot-flow@example.com", "laptop")
	rotMark(t, h, id)
	newSecret := rotNewSecret()

	if status, body := rotSend(t, h, id, secret, rotBody(newSecret)); status != http.StatusOK {
		t.Fatalf("step 3 status = %d, want 200, body=%s", status, body)
	}
	checkin := map[string]string{"ipv4": "203.0.113.5"}
	if status, body := doSigned(t, h, http.MethodPost, "/agent/v1/checkin", id, newSecret, checkin); status != http.StatusOK {
		t.Fatalf("check-in with the new secret status = %d, want 200, body=%s", status, body)
	}
	row := rotRow(t, h, id)
	got, err := auth.OpenSecret(agentTestKey32(), row.SecretHash)
	if err != nil {
		t.Fatalf("OpenSecret: %v", err)
	}
	if !bytes.Equal(got, newSecret) {
		t.Error("current secret is not the promoted one")
	}
	if row.PendingSecretHash != "" || row.RotateSecretAt != 0 {
		t.Errorf("PendingSecretHash = %q, RotateSecretAt = %d, want both cleared", row.PendingSecretHash, row.RotateSecretAt)
	}
	if status, body := doSigned(t, h, http.MethodPost, "/agent/v1/checkin", id, secret, checkin); status != http.StatusUnauthorized {
		t.Errorf("check-in with the old secret status = %d, want 401, body=%s", status, body)
	}
	page, err := h.st.AuditLog().ListPaginated(t.Context(), store.AuditFilter{EventType: "device.rotation.completed"}, "", 10)
	if err != nil {
		t.Fatalf("ListPaginated: %v", err)
	}
	if len(page.Rows) != 1 {
		t.Errorf("device.rotation.completed rows = %d, want 1", len(page.Rows))
	}
}

func TestRotationSecret_MainPortRequireMTLSIs403(t *testing.T) {
	var ca *agenttls.CA
	h := newAgentHarnessWith(t, withAgentMTLS(t, true, &ca))
	id, secret := enrollViaHTTP(t, h, "rot-mtls@example.com", "laptop")
	rotMark(t, h, id)

	status, body := rotSend(t, h, id, secret, rotBody(rotNewSecret()))
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body=%s", status, body)
	}
	if got := problemCode(t, body); got != shared.CodeMTLSRequired {
		t.Errorf("code = %q, want %q", got, shared.CodeMTLSRequired)
	}
}
