package webui

import (
	"errors"
	"net/http"
	"strings"

	"github.com/jacaudi/diyddns/internal/server/service"
	"github.com/jacaudi/diyddns/internal/store"
)

// apiKeyRow is one row of the account page's API Keys list.
type apiKeyRow struct {
	ID          string
	Label       string
	CreatedAbs  string
	LastUsedAbs string // "" when never used
}

// apiKeysSectionData is the API Keys section's own template data, folded
// into accountData (design D9: a SECTION on /account, not a separate page --
// unlike feed.go's admin-only /admin/feed page). Label/FieldErr carry a
// failed mint form's re-render; NewLabel/Secret carry the once-only reveal.
type apiKeysSectionData struct {
	Keys []apiKeyRow

	Label    string
	FieldErr string

	NewLabel string
	Secret   string
}

// newAPIKeysSectionData loads userID's own keys only -- design D9's
// correction from feed.go's precedent, which has no ownership scope at all
// (correct there, since every feed token is global).
func (h *handler) newAPIKeysSectionData(r *http.Request, userID string) (apiKeysSectionData, error) {
	keys, err := h.deps.APIKeys.ListKeys(r.Context(), userID)
	if err != nil {
		return apiKeysSectionData{}, err
	}
	rows := make([]apiKeyRow, 0, len(keys))
	for _, k := range keys {
		rows = append(rows, apiKeyRow{
			ID: k.ID, Label: k.Label,
			CreatedAbs: absTime(k.CreatedAt), LastUsedAbs: absTime(k.LastUsedAt),
		})
	}
	return apiKeysSectionData{Keys: rows}, nil
}

// handleAPIKeyMint mints a key and reveals it in this response -- never a
// redirect, since the plaintext is shown exactly once (mirrors
// handleFeedTokenMint). Ownership is implicit: usr.ID IS the owner, unlike
// feed's admin-minted-for-the-server model. Uses accountPageData (added in
// account.go by this same task) rather than accountData directly, because
// accountData itself has no error return -- the API Keys section is the one
// piece of /account's data that CAN fail to load, and accountPageData is the
// single place that composes the two and reports the failure, so no render
// call site here or in account.go can silently carry a stale/empty API Keys
// section.
func (h *handler) handleAPIKeyMint(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	label := strings.TrimSpace(r.PostFormValue("label"))
	data, err := h.accountPageData(r, usr, sess, "")
	if err != nil {
		h.logAndFail(w, r, usr, "load account page", err)
		return
	}
	data.APIKeys.Label = label

	key, plaintext, err := h.deps.APIKeys.MintKey(r.Context(), usr.ID, label)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidKeyLabel):
			data.APIKeys.FieldErr = "Give the key a label."
			h.renderStatus(w, r, http.StatusUnprocessableEntity, "account", data)
			return
		case errors.Is(err, store.ErrConflict):
			data.APIKeys.FieldErr = "You already have a key with that label."
			h.renderStatus(w, r, http.StatusUnprocessableEntity, "account", data)
			return
		default:
			h.logAndFail(w, r, usr, "mint api key", err)
			return
		}
	}

	refreshed, err := h.accountPageData(r, usr, sess, "")
	if err != nil {
		// The key has ALREADY been minted; only the page re-read failed.
		h.logAndFailMessage(w, r, usr, "load account page", err,
			"The key was minted, but the page listing it could not be built. Revoke it and mint another.")
		return
	}
	refreshed.APIKeys.NewLabel = key.Label
	refreshed.APIKeys.Secret = plaintext
	h.render(w, r, "account", refreshed)
}

// handleAPIKeyRevoke revokes a key owned by usr and redirects to /account.
// Ownership-as-404 (design D8/D9): RevokeKey itself enforces it, this
// handler just passes usr.ID through -- it never trusts the path id alone.
func (h *handler) handleAPIKeyRevoke(w http.ResponseWriter, r *http.Request, usr store.User, _ store.Session) {
	if err := h.deps.APIKeys.RevokeKey(r.Context(), usr.ID, r.PathValue("id")); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			h.renderError(w, r, usr, http.StatusNotFound, "That API key does not exist.")
			return
		}
		h.logAndFail(w, r, usr, "revoke api key", err)
		return
	}
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}
