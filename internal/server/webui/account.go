package webui

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jacaudi/diyddns/internal/store"
)

// accountData is account.html's template data. Exactly one of the email card's
// four states renders: managed-by-IdP, email-disabled, pending, or the form.
type accountData struct {
	appData
	OIDCLinked   bool
	EmailEnabled bool
	// PendingEmail is set only while a change is pending AND not expired; an
	// expired one reads as absent (the pruner clears it, design D17).
	PendingEmail string
	// PendingNotice is the pending card's sentence, rendered through the
	// noticeBanner partial. Built here so the template holds one spelling.
	PendingNotice string
	Error         string
}

func (h *handler) accountData(usr store.User, sess store.Session, errMsg string) accountData {
	data := accountData{
		appData:      h.newAppData(usr, sess, "Account", "account"),
		OIDCLinked:   usr.OIDCSubject != "",
		EmailEnabled: h.deps.Cfg.Email.Enabled, // the same source handleLogin's ShowRecover reads
		Error:        errMsg,
	}
	now := time.Now()
	if usr.PendingEmail != "" && usr.PendingEmailExpiresAt > now.Unix() {
		data.PendingEmail = usr.PendingEmail
		data.PendingNotice = fmt.Sprintf(
			"A change to %s is waiting for confirmation. Open the link sent to that address; you need to be signed in here when you do. It expires in %s. Did not get it? Cancel and request the change again.",
			usr.PendingEmail, relExpiry(usr.PendingEmailExpiresAt, now))
	}
	return data
}

// handleAccount renders /account. requireSession has already guaranteed a
// valid session (usr, sess) by the time this runs. Since #106 the page has no
// notification card: endpoints are admin-only and live under /admin.
func (h *handler) handleAccount(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	h.render(w, r, "account", h.accountData(usr, sess, ""))
}

// renderAccountError re-renders /account with a banner at the status the
// failure deserves. usr is the row as of request start: for a rejected request
// that is accurate (nothing was written), and for the one branch where it is
// not (design §5.1 step 9's failed rollback) the copy describes the state after
// the retry, not this page.
func (h *handler) renderAccountError(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session, status int, msg string) {
	h.renderStatus(w, r, status, "account", h.accountData(usr, sess, msg))
}

// handleAccountEmailRequest stages a self-service address change (design §5.1).
func (h *handler) handleAccountEmailRequest(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	if err := h.deps.EmailChange.Request(r.Context(), usr, strings.TrimSpace(r.PostFormValue("email"))); err != nil {
		if msg, status, ok := adminGuardMessage(err); ok {
			h.renderAccountError(w, r, usr, sess, status, msg)
			return
		}
		h.logAndFail(w, r, usr, "request email change", err)
		return
	}
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}

// handleAccountEmailCancel discards a pending change. With nothing pending it
// is a harmless no-op.
func (h *handler) handleAccountEmailCancel(w http.ResponseWriter, r *http.Request, usr store.User, _ store.Session) {
	if err := h.deps.EmailChange.Cancel(r.Context(), usr); err != nil {
		h.logAndFail(w, r, usr, "cancel email change", err)
		return
	}
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}

// accountEmailConfirmData is account-email-confirm.html's template data.
type accountEmailConfirmData struct {
	appData
	PendingEmail string
	Token        string
}

// handleAccountEmailConfirmPage is the page the emailed link opens (design
// §5.2). It verifies nothing about the token and consumes nothing: a scanner
// or prefetch that follows the link changes no state. The token is reflected
// into a hidden field for the POST, which is where it is checked. A missing
// token, nothing pending, or an expired pending change is a 422.
func (h *handler) handleAccountEmailConfirmPage(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	token := r.URL.Query().Get("token")
	if token == "" || usr.PendingEmail == "" || usr.PendingEmailExpiresAt <= time.Now().Unix() {
		h.renderErrorLink(w, r, usr, http.StatusUnprocessableEntity,
			"This confirmation link is invalid or has expired. Request the change again from your account page.",
			"Back to account", "/account")
		return
	}
	h.render(w, r, "account-email-confirm", accountEmailConfirmData{
		appData:      h.newAppData(usr, sess, "Confirm email address", "account"),
		PendingEmail: usr.PendingEmail,
		Token:        token,
	})
}

// handleAccountEmailConfirm applies the change. Errors re-render /account (the
// confirm page has nothing left to offer once the token is spent or rejected).
func (h *handler) handleAccountEmailConfirm(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	if err := h.deps.EmailChange.Confirm(r.Context(), usr, r.PostFormValue("token")); err != nil {
		if msg, status, ok := adminGuardMessage(err); ok {
			h.renderAccountError(w, r, usr, sess, status, msg)
			return
		}
		h.logAndFail(w, r, usr, "confirm email change", err)
		return
	}
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}
