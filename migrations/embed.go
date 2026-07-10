// Package migrations exposes the embedded SQL migration files as an
// io/fs.FS for goose to consume at runtime.
package migrations

import "embed"

// FS contains every *.sql migration in this directory, applied by
// internal/store at server startup.
//
//go:embed *.sql
var FS embed.FS
