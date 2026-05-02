// Package version exposes build-time identity for diyddns binaries.
//
// Variables Version, Commit, and Date are intended to be overridden via
// -ldflags "-X github.com/jacaudi/diyddns/internal/version.Version=... ..."
// at build time. Defaults make development builds identifiable.
package version

import (
	"fmt"
	"strings"
)

var (
	// Version is the semver tag, e.g. "1.2.3", or "v0.0.0-dev" for development.
	Version = "v0.0.0-dev"
	// Commit is the short git SHA. Empty in development.
	Commit = ""
	// Date is the build date in RFC 3339. Empty in development.
	Date = ""
)

// Info is a snapshot of the build identity.
type Info struct {
	Version string
	Commit  string
	Date    string
}

// Current returns the build's identity from package-level vars.
func Current() Info {
	return Info{Version: Version, Commit: Commit, Date: Date}
}

// String renders an Info for human display. Empty fields are omitted from the
// suffix; if Version itself is empty, the result is "unknown" regardless of
// the other fields (a build with no version tag is treated as unidentified).
//
//   - Version + Commit + Date all set:  "VERSION (COMMIT, DATE)"
//   - Version + Commit only:            "VERSION (COMMIT)"
//   - Version + Date only:              "VERSION (DATE)"
//   - Version only:                     "VERSION"
//   - Version empty (any other state):  "unknown"
func (i Info) String() string {
	if i.Version == "" {
		return "unknown"
	}
	var suffix []string
	if i.Commit != "" {
		suffix = append(suffix, i.Commit)
	}
	if i.Date != "" {
		suffix = append(suffix, i.Date)
	}
	if len(suffix) == 0 {
		return i.Version
	}
	return fmt.Sprintf("%s (%s)", i.Version, strings.Join(suffix, ", "))
}
