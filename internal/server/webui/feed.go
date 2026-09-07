package webui

import (
	"errors"
	"net/http"
	"strings"

	"github.com/jacaudi/diyddns/internal/store"
)

// feedTokenRow is one row of the admin feed-token list.
type feedTokenRow struct {
	ID          string
	Label       string
	CreatedBy   string // the minting admin's email, "" once that user is gone
	CreatedAbs  string
	LastUsedAbs string // "" when never used
}

// adminFeedData is admin-feed.html's template data. Label/FieldErr carry a
// failed mint form's re-render; NewLabel/Secret carry the once-only reveal.
type adminFeedData struct {
	appData
	Tokens []feedTokenRow
	Total  int

	Label    string
	FieldErr string

	NewLabel string
	Secret   string
}

// newAdminFeedData loads every token and resolves each creator's email.
func (h *handler) newAdminFeedData(r *http.Request, usr store.User, sess store.Session) (adminFeedData, error) {
	toks, err := h.deps.Feed.ListTokens(r.Context())
	if err != nil {
		return adminFeedData{}, err
	}
	users, err := h.deps.Admin.ListUsers(r.Context())
	if err != nil {
		return adminFeedData{}, err
	}
	rows := make([]feedTokenRow, 0, len(toks))
	for _, t := range toks {
		var by string
		if t.CreatedBy != "" {
			if u, ok := findUser(users, t.CreatedBy); ok {
				by = u.Email
			} else {
				by = t.CreatedBy
			}
		}
		rows = append(rows, feedTokenRow{
			ID: t.ID, Label: t.Label, CreatedBy: by,
			CreatedAbs: absTime(t.CreatedAt), LastUsedAbs: absTime(t.LastUsedAt),
		})
	}
	return adminFeedData{
		appData: h.newAppData(usr, sess, "Feed tokens", "admin-feed"),
		Tokens:  rows,
		Total:   len(rows),
	}, nil
}

// handleAdminFeed renders the feed-token list and mint form.
func (h *handler) handleAdminFeed(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	data, err := h.newAdminFeedData(r, usr, sess)
	if err != nil {
		h.logAndFail(w, r, usr, "list feed tokens", err)
		return
	}
	h.render(w, r, "admin-feed", data)
}

// handleFeedTokenMint mints a token and reveals it in this response — never a
// redirect, since the plaintext is shown exactly once.
func (h *handler) handleFeedTokenMint(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	label := strings.TrimSpace(r.PostFormValue("label"))
	data, err := h.newAdminFeedData(r, usr, sess)
	if err != nil {
		h.logAndFail(w, r, usr, "list feed tokens", err)
		return
	}
	data.Label = label
	if label == "" {
		data.FieldErr = "Give the token a label."
		h.renderStatus(w, r, http.StatusUnprocessableEntity, "admin-feed", data)
		return
	}

	tok, plaintext, err := h.deps.Feed.MintToken(r.Context(), usr.ID, label)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			data.FieldErr = "A token with that label already exists."
			h.renderStatus(w, r, http.StatusUnprocessableEntity, "admin-feed", data)
			return
		}
		h.logAndFail(w, r, usr, "mint feed token", err)
		return
	}

	refreshed, err := h.newAdminFeedData(r, usr, sess)
	if err != nil {
		// The token has ALREADY been minted; only the list re-read failed.
		h.logAndFailMessage(w, r, usr, "list feed tokens", err,
			"The token was minted, but the page listing it could not be built. Revoke it and mint another.")
		return
	}
	refreshed.NewLabel = tok.Label
	refreshed.Secret = plaintext
	h.render(w, r, "admin-feed", refreshed)
}

// handleFeedTokenRevoke revokes a token: the row goes, its live streams are
// closed with 4001, and the list is shown again.
func (h *handler) handleFeedTokenRevoke(w http.ResponseWriter, r *http.Request, usr store.User, sess store.Session) {
	if err := h.deps.Feed.RevokeToken(r.Context(), usr.ID, r.PathValue("id")); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			h.renderError(w, r, usr, http.StatusNotFound, "That feed token does not exist.")
			return
		}
		h.logAndFail(w, r, usr, "revoke feed token", err)
		return
	}
	http.Redirect(w, r, "/admin/feed", http.StatusSeeOther)
}
