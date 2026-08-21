//go:build smoke

package smoke

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
)

// TestAdminInviteIsEmailed drives the REAL admin invite endpoint against a real
// SMTP listener and asserts the message actually arrived carrying a usable,
// ABSOLUTE link. Unit tests prove the service calls Send; only this proves an
// operator with SMTP configured receives mail they can act on.
func TestAdminInviteIsEmailed(t *testing.T) {
	root := repoRoot(t)
	binDir := t.TempDir()
	serverBin := build(t, root, binDir, "diyddns-server")

	host, port, envelopes := startCaptureSMTP(t)

	addr := freeAddr(t)
	baseURL := browserBaseURL(t, addr)

	// email.tls defaults to "starttls" (config.go:157) but the capture server
	// advertises neither STARTTLS nor AUTH, so force "none" and leave username
	// empty. startServer already sets DIYDDNS_SERVER_BASE_URL, which
	// email.enabled now requires — without it the server refuses to boot.
	srv := startServer(t, root, serverBin, addr,
		"DIYDDNS_EMAIL_ENABLED=true",
		"DIYDDNS_EMAIL_HOST="+host,
		"DIYDDNS_EMAIL_PORT="+strconv.Itoa(port),
		"DIYDDNS_EMAIL_FROM=diyddns@x.test",
		"DIYDDNS_EMAIL_TLS=none",
	)
	waitHealthy(t, baseURL)

	// --- bootstrap the first admin, mirroring TestSmoke ---
	token := scrapeToken(t, srv)

	// The cookie jar is mandatory: the WebAuthn ceremony carries its sealed
	// challenge between begin and finish in a cookie, and that cookie is Secure
	// under the shipped defaults — see newBrowserJar.
	client := &http.Client{Jar: newBrowserJar(t), Timeout: 30 * time.Second}

	rp := virtualwebauthn.RelyingParty{Name: "DIYDDNS", ID: rpIDFor(t, addr), Origin: baseURL}
	attOpts := beginClaim(t, client, baseURL, token)
	authr := virtualwebauthn.NewAuthenticatorWithOptions(
		virtualwebauthn.AuthenticatorOptions{UserHandle: []byte(attOpts.UserID)})
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	authr.AddCredential(cred)
	finishClaim(t, client, baseURL, virtualwebauthn.CreateAttestationResponse(rp, authr, cred, *attOpts))
	passkeyLogin(t, client, baseURL, rp, authr, cred)
	csrf := fetchCSRF(t, client, baseURL)

	// --- invite a user through the real JSON API ---
	status, body := postJSON(t, client, baseURL+"/api/v1/admin/users",
		map[string]string{"email": "invitee@x.test", "role": "user"}, csrf)
	if status != http.StatusOK {
		t.Fatalf("create user: status = %d, want 200, body=%s", status, body)
	}

	select {
	case env := <-envelopes:
		if !strings.Contains(env.to, "invitee@x.test") {
			t.Errorf("envelope To = %q, want invitee@x.test", env.to)
		}
		// The link must be ABSOLUTE. A bare path is unusable in a mailbox, and
		// preventing exactly that is why email.enabled requires base_url.
		if !strings.Contains(env.data, baseURL+"/register?token=") {
			t.Errorf("email body carries no absolute registration link:\n%s", env.data)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("no email arrived within 30s\n--- server log ---\n%s", srv.log())
	}
}
