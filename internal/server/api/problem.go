package api

import (
	"encoding/json"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
)

// codedError is a huma problem+json error that also carries a stable,
// machine-readable `code` (shared.Code*, #173). Clients branch on code, not on
// the human-readable detail or the status alone. The embedded ErrorModel
// supplies Error, GetStatus and the problem+json content type, so a handler can
// return a *codedError like any other huma error.
type codedError struct {
	huma.ErrorModel
	Code string `json:"code"`
}

// newCodedError builds a codedError with the standard title for status.
func newCodedError(status int, code, detail string) *codedError {
	return &codedError{Status: status, Title: http.StatusText(status), Detail: detail, Code: code}
}

// writeCodedError writes e as problem+json straight to w, for middleware that
// answers before huma binds a response: huma.WriteErr would drop the code field.
func writeCodedError(w http.ResponseWriter, e *codedError) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(e.Status)
	_ = json.NewEncoder(w).Encode(e)
}
