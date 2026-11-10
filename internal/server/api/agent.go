package api

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"

	"github.com/jacaudi/diyddns/internal/server/agenttls"
	"github.com/jacaudi/diyddns/internal/server/clientip"
	"github.com/jacaudi/diyddns/internal/server/service"
	"github.com/jacaudi/diyddns/internal/shared"
	"github.com/jacaudi/diyddns/internal/store"
)

// BuildAgent registers the agent mTLS listener's API onto mux: check-in, self
// and cert, and nothing else. It is a separate huma instance from Build's, with
// no OpenAPI document, docs page or schemas route, so the listener answers 404
// for every other path. Each route is HMAC-authenticated and then bound to the
// client certificate; the certificate itself is verified by ClientCertMiddleware
// wrapped around the whole mux. Cert is renewal-only here.
func BuildAgent(mux *http.ServeMux, deps ServerDeps) {
	cfg := huma.DefaultConfig("DIYDDNS Agent mTLS API", deps.Info.Version)
	cfg.OpenAPIPath, cfg.DocsPath, cfg.SchemasPath = "", "", ""
	a := humago.New(mux, cfg)

	// The peer is the origin here: the listener sits behind a PROXY protocol
	// wrap (or none), never behind X-Forwarded-For, so a header a client sends is
	// not read.
	mws := huma.Middlewares{observeMW(clientip.ObservedFromPeer, deps.TrustedProxies), hmacMW(a, deps), certBindingMW(a, deps)}
	registerCheckinOps(a, deps, mws, true)
	registerCertOps(a, deps, true, mws)
}

// ClientCertMiddleware verifies the TLS client certificate on every request to
// the agent listener, so no route can skip it. The listener requests any client
// certificate without verifying it (the handshake cannot name the active CA
// alone), so this does the real check: the leaf chains to the active CA and is
// usable only for client authentication, it names a device through its URI SAN,
// and this certificate's serial is the device's current one or its pending one
// (#175). A pending serial is promoted to current on its first use, on proof
// of TLS key possession alone and before the HMAC check (M-8): the renewal
// response that carried the certificate was evidently delivered. Anything else
// is the coded 401 client_cert_rejected. A failing device lookup or promote is
// a 500 instead, so a database outage never reads as a rejected certificate and
// the client never drops a certificate it still needs.
//
// It hands r to next untouched (no WithContext or Clone): AccessLog reads
// r.Pattern off the same request once the mux has routed it.
func ClientCertMiddleware(ca *agenttls.CA, devices *store.DeviceRepo, rot *service.RotationService, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reason, claimed, err := checkClientCert(r, ca, devices, rot)
			if err != nil {
				log.LogAttrs(r.Context(), slog.LevelError, "agent client certificate lookup failed",
					slog.String("claimed_device_id", claimedDeviceID(claimed)), slog.Any("error", err))
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			if reason != "" {
				rejectClientCert(r.Context(), w, log, reason, claimed)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Rejection reasons logged by rejectClientCert; never sent to the client.
const (
	reasonNoCert            = "no_cert"
	reasonChain             = "chain"
	reasonNoDeviceURI       = "no_device_uri"
	reasonUnknownDevice     = "unknown_device"
	reasonSerialMismatch    = "serial_mismatch"
	reasonPendingSuperseded = "pending_superseded"
	reasonDeviceMismatch    = "device_mismatch"
)

// checkClientCert returns the reason r's client certificate is refused ("" when
// accepted) and the device id the certificate claims, if it names one. A
// non-nil error is a failed device lookup, not a verdict on the certificate.
func checkClientCert(r *http.Request, ca *agenttls.CA, devices *store.DeviceRepo, rot *service.RotationService) (reason, claimed string, err error) {
	leaf := peerLeaf(r)
	if leaf == nil {
		return reasonNoCert, "", nil
	}
	id, hasURI := agenttls.DeviceIDFromCert(leaf)
	if ca.VerifyClient(leaf, time.Now()) != nil || !isClientLeaf(leaf) {
		return reasonChain, id, nil
	}
	if !hasURI {
		return reasonNoDeviceURI, "", nil
	}
	dev, err := devices.GetByID(r.Context(), id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return reasonUnknownDevice, id, nil
	case err != nil:
		return "", id, err
	}
	serial := agenttls.SerialHex(leaf.SerialNumber)
	switch {
	case dev.CertSerial == serial:
		return "", id, nil
	case dev.PendingCertSerial == serial: // serial is never empty, so no "no pending" match
		accepted, err := rot.PromoteCert(r.Context(), id, serial, leaf.NotAfter.Unix(), dev.RotateCertAt != 0)
		if err != nil {
			return "", id, err
		}
		if !accepted {
			return reasonPendingSuperseded, id, nil
		}
		return "", id, nil
	}
	return reasonSerialMismatch, id, nil
}

// isClientLeaf is the defense in depth over VerifyClient: x509.Verify accepts a
// leaf with no ExtKeyUsage for any usage, and does not look at whether a leaf
// is itself a CA. A device certificate is neither.
func isClientLeaf(leaf *x509.Certificate) bool {
	return !leaf.IsCA && slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
}

// peerLeaf returns the client's leaf certificate, or nil when it sent none.
func peerLeaf(r *http.Request) *x509.Certificate {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil
	}
	return r.TLS.PeerCertificates[0]
}

// certBindingMW requires the device the HMAC authenticated to be the device the
// client certificate names, so one device's certificate cannot carry another's
// signed requests. It must run after hmacMW.
func certBindingMW(_ huma.API, deps ServerDeps) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		r, w := humago.Unwrap(ctx)
		var certID string
		if leaf := peerLeaf(r); leaf != nil {
			certID, _ = agenttls.DeviceIDFromCert(leaf)
		}
		if certID == "" || certID != DeviceIDFrom(ctx.Context()) {
			rejectClientCert(ctx.Context(), w, deps.Log, reasonDeviceMismatch, certID)
			return
		}
		next(ctx)
	}
}

// rejectClientCert logs the reason at WARN and answers the uniform coded 401.
// claimed comes from the certificate and is attacker-controlled, so it goes
// through claimedDeviceID before it reaches the log.
func rejectClientCert(ctx context.Context, w http.ResponseWriter, log *slog.Logger, reason, claimed string) {
	log.LogAttrs(ctx, slog.LevelWarn, "agent client certificate rejected",
		slog.String("reason", reason),
		slog.String("claimed_device_id", claimedDeviceID(claimed)))
	w.Header().Set(shared.HeaderWWWAuthenticate, shared.ChallengeHMAC) // #191: every 401 carries a challenge
	writeCodedError(w, newCodedError(http.StatusUnauthorized, shared.CodeClientCertRejected, "client certificate rejected"))
}
