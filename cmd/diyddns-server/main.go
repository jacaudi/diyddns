// Command diyddns-server is the DIYDDNS HTTP server.
//
// This file is a Plan 01 scaffold: it exposes only --version and a no-op run
// path. Plan 03 (Server skeleton & OpenAPI) replaces the run path with the
// real HTTP server.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/jacaudi/diyddns/internal/version"
)

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("diyddns-server", version.Current().String())
		return
	}

	fmt.Fprintln(os.Stderr, "diyddns-server: not yet implemented (Plan 01 scaffold)")
	os.Exit(2)
}
