package feed

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jacaudi/diyddns/internal/store"
)

// Deps are the dependencies the feed routes need. Store is read for the
// member list and feed_state; Auth authenticates tokens; Log follows #100.
type Deps struct {
	Store *store.Store
	Auth  Authenticator
	Log   *slog.Logger
}

// Routes lists every pattern Register serves, so the outer mux can forward
// exactly these (the same single-source discipline webui.New uses).
var Routes = []string{
	"GET /feed/v1/devices.txt",
	"GET /feed/v1/devices.json",
}

// Register mounts the feed routes on mux behind TokenMiddleware. Called only
// when feed.enabled is true — the route group is absent, not guarded, when
// it is off. GET patterns also serve HEAD (net/http suppresses the body and
// keeps Content-Length).
func Register(mux *http.ServeMux, deps Deps) {
	h := &handler{deps: deps}
	mw := TokenMiddleware(deps.Auth, deps.Log)
	mux.Handle("GET /feed/v1/devices.txt", mw(http.HandlerFunc(h.serveText)))
	mux.Handle("GET /feed/v1/devices.json", mw(http.HandlerFunc(h.serveJSON)))
}

type handler struct {
	deps Deps
}

// current reads the member list and feed_state and renders both documents.
// One bounded read for the members plus one single-row read: the whole
// per-request cost of the feed (design §4.2). It takes a context rather than
// the request because the stream handler calls it after the upgrade, when
// the request context must no longer be used (design §5.1).
func (h *handler) current(ctx context.Context) (Snapshot, time.Time, error) {
	devices, err := h.deps.Store.Devices().ListFeed(ctx)
	if err != nil {
		return Snapshot{}, time.Time{}, err
	}
	snap, err := Render(devices)
	if err != nil {
		return Snapshot{}, time.Time{}, err
	}
	st, err := h.deps.Store.FeedState().Get(ctx)
	if err != nil {
		return Snapshot{}, time.Time{}, err
	}
	return snap, time.Unix(st.ChangedAt, 0).UTC(), nil
}

func (h *handler) serveText(w http.ResponseWriter, r *http.Request) {
	h.serve(w, r, "text/plain; charset=utf-8",
		func(s Snapshot) ([]byte, string) { return s.Text, s.TextETag },
		"# diyddns feed unavailable\n")
}

func (h *handler) serveJSON(w http.ResponseWriter, r *http.Request) {
	h.serve(w, r, "application/json",
		func(s Snapshot) ([]byte, string) { return s.JSON, s.JSONETag },
		`{"error":"feed unavailable"}`)
}

// serve answers one document with the validators of design §4.5–4.6: a
// strong ETag over THIS document's exact body bytes, 304 ONLY to a matching
// If-None-Match, Last-Modified informational (If-Modified-Since is ignored:
// a wrong match would serve a stale allow-list), and a 500 WITH a body on
// failure — never an empty 200, which pfSense-class consumers would install.
// pick returns the body and the tag together so the two can never diverge.
func (h *handler) serve(w http.ResponseWriter, r *http.Request, contentType string, pick func(Snapshot) ([]byte, string), failBody string) {
	snap, changedAt, err := h.current(r.Context())
	if err != nil {
		h.deps.Log.LogAttrs(r.Context(), slog.LevelError, "feed render failed", slog.Any("error", err))
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(failBody))
		return
	}
	body, etag := pick(snap)

	w.Header().Set("ETag", etag)
	w.Header().Set("Last-Modified", changedAt.Format(http.TimeFormat))
	w.Header().Set("Cache-Control", "no-cache")
	if etagMatches(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// etagMatches implements the If-None-Match comparison: "*" matches anything;
// otherwise the comma-separated list is searched for the strong tag.
// A weak tag (W/"…") never matches a strong one.
func etagMatches(header, etag string) bool {
	header = strings.TrimSpace(header)
	if header == "" {
		return false
	}
	if header == "*" {
		return true
	}
	for candidate := range strings.SplitSeq(header, ",") {
		if strings.TrimSpace(candidate) == etag {
			return true
		}
	}
	return false
}
