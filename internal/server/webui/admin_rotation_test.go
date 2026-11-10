package webui

import (
	"bytes"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/jacaudi/diyddns/internal/server/service"
	"github.com/jacaudi/diyddns/internal/store"
)

func TestRotationNotes(t *testing.T) {
	const since = 1_800_000_000
	x := absTime(since)
	tests := []struct {
		name string
		in   service.RotationState
		want []string
	}{
		{"nothing pending", service.RotationState{}, nil},
		{
			"secret pending",
			service.RotationState{Secret: service.TrackState{Since: since, Status: service.StatusPending}},
			[]string{"Secret rotation pending since " + x},
		},
		{
			"cert pending",
			service.RotationState{Cert: service.TrackState{Since: since, Status: service.StatusPending}},
			[]string{"Certificate rotation pending since " + x},
		},
		{
			"secret then cert, each with a reason",
			service.RotationState{
				Secret: service.TrackState{Since: since, Status: service.StatusAwaitingUpgrade},
				Cert:   service.TrackState{Since: since, Status: service.StatusAwaitingMTLS},
			},
			[]string{
				"Secret rotation pending since " + x + ", waiting for client upgrade",
				"Certificate rotation pending since " + x + ", waiting for mTLS",
			},
		},
		{
			"cert awaiting upgrade",
			service.RotationState{Cert: service.TrackState{Since: since, Status: service.StatusAwaitingUpgrade}},
			[]string{"Certificate rotation pending since " + x + ", waiting for client upgrade"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rotationNotes(tt.in); !slices.Equal(got, tt.want) {
				t.Errorf("rotationNotes = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAdminDevice_RotateMarksAndRedirects(t *testing.T) {
	deps, st, cookie, sess, _, dev := adminDeviceFixture(t)
	h, _ := New(deps)

	rec := postForm(t, h, cookie, "/admin/devices/"+dev.ID+"/rotation", url.Values{"csrf": {sess.CSRFToken}, "target": {"secret"}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/devices/"+dev.ID {
		t.Fatalf("rotate = %d → %q, want 303 → /admin/devices/%s", rec.Code, rec.Header().Get("Location"), dev.ID)
	}
	got, err := st.Devices().GetByID(t.Context(), dev.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.RotateSecretAt == 0 {
		t.Error("RotateSecretAt = 0, want the rotation marked")
	}
	if got.RotateCertAt != 0 {
		t.Error("RotateCertAt set for a secret-only request")
	}

	body := getPage(t, h, cookie, "/admin/devices/"+dev.ID).Body.String()
	for _, want := range []string{"Secret rotation pending since", "Cancel rotation"} {
		if !strings.Contains(body, want) {
			t.Errorf("admin page missing %q", want)
		}
	}
}

func TestAdminDevice_RotateGuards(t *testing.T) {
	deps, st, cookie, sess, _, dev := adminDeviceFixture(t)
	plain := seedUser(t, st, "plain@example.com", "user")
	plainCookie := signIn(t, deps, plain)
	plainSess := sessionFor(t, deps, plainCookie)

	certOff := deps
	certOff.Rotation = service.NewRotationService(st, bytes.Repeat([]byte{0x24}, 32), service.NewAuditWriter(st), false)

	disabled := seedDevice(t, st, dev.UserID, "off-pi")
	if err := st.Devices().SetDisabled(t.Context(), disabled.ID, true); err != nil {
		t.Fatalf("disable: %v", err)
	}

	tests := []struct {
		name    string
		deps    Deps
		cookie  *http.Cookie
		csrf    string
		id      string
		target  string
		want    int
		wantMsg string
	}{
		{"non-admin", deps, plainCookie, plainSess.CSRFToken, dev.ID, "secret", http.StatusForbidden, ""},
		{"unknown device", deps, cookie, sess.CSRFToken, "no-such-device", "secret", http.StatusNotFound, "That device does not exist."},
		{"bogus target", deps, cookie, sess.CSRFToken, dev.ID, "bogus", http.StatusBadRequest, "Choose secret, certificate or both."},
		{"cert without the listener", certOff, cookie, sess.CSRFToken, dev.ID, "cert", http.StatusConflict, "Certificate rotation needs the agent listener (agent.listen)."},
		{"disabled device", deps, cookie, sess.CSRFToken, disabled.ID, "secret", http.StatusConflict, "A disabled device, or a device whose account is disabled, cannot be rotated."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, _ := New(tt.deps)
			rec := postForm(t, h, tt.cookie, "/admin/devices/"+tt.id+"/rotation", url.Values{"csrf": {tt.csrf}, "target": {tt.target}})
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tt.want, rec.Body.String())
			}
			if tt.wantMsg != "" && !strings.Contains(rec.Body.String(), tt.wantMsg) {
				t.Errorf("body missing %q", tt.wantMsg)
			}
		})
	}
	for _, id := range []string{dev.ID, disabled.ID} {
		got, err := st.Devices().GetByID(t.Context(), id)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if got.RotateSecretAt != 0 || got.RotateCertAt != 0 {
			t.Errorf("device %s was marked by a refused request: %+v", id, got)
		}
	}
}

func TestAdminDevice_CancelRotation(t *testing.T) {
	deps, st, cookie, sess, _, dev := adminDeviceFixture(t)
	h, _ := New(deps)
	form := url.Values{"csrf": {sess.CSRFToken}, "target": {"secret"}}
	if rec := postForm(t, h, cookie, "/admin/devices/"+dev.ID+"/rotation", form); rec.Code != http.StatusSeeOther {
		t.Fatalf("rotate = %d, want 303", rec.Code)
	}

	rec := postForm(t, h, cookie, "/admin/devices/"+dev.ID+"/rotation/cancel", url.Values{"csrf": {sess.CSRFToken}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/devices/"+dev.ID {
		t.Fatalf("cancel = %d → %q, want 303 → /admin/devices/%s", rec.Code, rec.Header().Get("Location"), dev.ID)
	}
	got, err := st.Devices().GetByID(t.Context(), dev.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.RotateSecretAt != 0 {
		t.Error("RotateSecretAt still set after cancel")
	}
	if body := getPage(t, h, cookie, "/admin/devices/"+dev.ID).Body.String(); strings.Contains(body, "Cancel rotation") {
		t.Error("admin page still offers Cancel rotation with nothing pending")
	}

	rec = postForm(t, h, cookie, "/admin/devices/no-such-device/rotation/cancel", url.Values{"csrf": {sess.CSRFToken}})
	if rec.Code != http.StatusNotFound {
		t.Errorf("cancel on an unknown device = %d, want 404", rec.Code)
	}
}

func TestDeviceDetail_OwnerSeesRotationReadOnly(t *testing.T) {
	deps, st, _, _, owner, dev := adminDeviceFixture(t)
	if err := st.Devices().MarkRotation(t.Context(), dev.ID, true, false, store.NowUnix()); err != nil {
		t.Fatalf("MarkRotation: %v", err)
	}
	h, _ := New(deps)
	body := getPage(t, h, signIn(t, deps, owner), "/devices/"+dev.ID).Body.String()
	if !strings.Contains(body, "waiting for client upgrade") {
		t.Error("owner page missing the rotation note")
	}
	if strings.Contains(body, `action="/admin/devices/`+dev.ID+`/rotation"`) {
		t.Error("owner page renders an admin rotation form")
	}
}

func TestAdminDevices_PendingRotationTile(t *testing.T) {
	deps, st, cookie, _, owner, dev := adminDeviceFixture(t)
	seedDevice(t, st, owner.ID, "second-pi")
	if err := st.Devices().MarkRotation(t.Context(), dev.ID, true, false, store.NowUnix()); err != nil {
		t.Fatalf("MarkRotation: %v", err)
	}
	h, _ := New(deps)
	body := getPage(t, h, cookie, "/admin/devices").Body.String()
	if want := `Devices pending rotation</div><div class="value">1<`; !strings.Contains(body, want) {
		t.Errorf("body missing %q", want)
	}
}

func TestKnownEventTypes_IncludesRotation(t *testing.T) {
	for _, name := range []string{"device.rotation.cancelled", "device.rotation.completed", "device.rotation.requested"} {
		if !slices.Contains(knownEventTypes, name) {
			t.Errorf("knownEventTypes missing %q", name)
		}
	}
}
