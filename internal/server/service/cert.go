package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jacaudi/diyddns/internal/server/agenttls"
	"github.com/jacaudi/diyddns/internal/store"
)

// ErrCertAlreadyIssued is returned for a main-listener request when the device
// already has a live certificate. Mapped to HTTP 409 by the API layer.
var ErrCertAlreadyIssued = errors.New("service: device already has a live certificate")

// IssuedCert is the response to a successful issuance.
type IssuedCert struct {
	CertificatePEM string
	CABundlePEM    string
	AgentURL       string
}

// CertService issues device certificates and records them on the device row.
type CertService struct {
	st       *store.Store
	ca       *agenttls.CA
	agentURL string
	audit    AuditSink
	now      func() time.Time
}

// NewCertService constructs a CertService. agentURL is the agent.public_url
// clients are told to use once they hold a certificate.
func NewCertService(st *store.Store, ca *agenttls.CA, agentURL string, audit AuditSink) *CertService {
	return &CertService{st: st, ca: ca, agentURL: agentURL, audit: audit, now: time.Now}
}

// Issue signs a certificate for deviceID over csrPEM's public key and records
// it on the device row. renewal is true on the agent listener, where the caller
// already proved it holds the current certificate, so Issue always issues and
// records only the serial as pending: the current certificate stays valid until
// the new one is first used (ClientCertMiddleware promotes it), so a response
// lost in transit cannot lock the device out (#175). On the main listener
// (renewal false) it issues only when the device has no live certificate, and
// records the serial and expiry as current (#173).
//
// The crypto runs before the database write, so the store's single connection
// is never held across it. On the main listener the write is a
// compare-and-set (SetCertIfNoLive): of two racing requests exactly one wins
// and the other gets ErrCertAlreadyIssued. A cheap read first rejects the
// common case before any signing. Returns agenttls.ErrBadCSR for an unusable
// CSR and store.ErrNotFound for an unknown device.
func (s *CertService) Issue(ctx context.Context, deviceID string, csrPEM []byte, renewal bool) (IssuedCert, error) {
	now := s.now()
	if !renewal {
		dev, err := s.st.Devices().GetByID(ctx, deviceID)
		if err != nil {
			return IssuedCert{}, fmt.Errorf("service.CertService.Issue: %w", err)
		}
		if dev.CertSerial != "" && dev.CertNotAfter > now.Unix() {
			return IssuedCert{}, fmt.Errorf("service.CertService.Issue: %w", ErrCertAlreadyIssued)
		}
	}
	issued, err := s.ca.IssueDevice(csrPEM, deviceID, now)
	if err != nil {
		return IssuedCert{}, fmt.Errorf("service.CertService.Issue: %w", err)
	}
	notAfter := issued.NotAfter.Unix()
	if !renewal {
		err = s.st.Devices().SetCertIfNoLive(ctx, deviceID, issued.Serial, notAfter, now.Unix())
		if errors.Is(err, store.ErrConflict) {
			return IssuedCert{}, fmt.Errorf("service.CertService.Issue: %w", ErrCertAlreadyIssued)
		}
	} else {
		err = s.st.Devices().SetPendingCert(ctx, deviceID, issued.Serial)
	}
	if err != nil {
		return IssuedCert{}, fmt.Errorf("service.CertService.Issue: %w", err)
	}
	listener := "main"
	if renewal {
		listener = "agent"
	}
	details, _ := json.Marshal(struct {
		Listener string `json:"listener"`
		Serial   string `json:"serial"`
		NotAfter int64  `json:"not_after"`
	}{listener, issued.Serial, notAfter})
	s.audit.Log(ctx, store.AuditEntry{
		EventType: "device.cert_issued", TargetType: "device", TargetID: deviceID,
		DetailsJSON: string(details),
	})
	return IssuedCert{
		CertificatePEM: string(issued.CertPEM),
		CABundlePEM:    string(s.ca.Bundle()),
		AgentURL:       s.agentURL,
	}, nil
}
