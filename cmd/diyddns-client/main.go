// Command diyddns-client is the DIYDDNS reporting agent.
//
// This file is a Plan 01 scaffold: it exposes only --version. Plan 06
// (Client) replaces the run path with the real polling loop and enrollment.
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
		fmt.Println("diyddns-client", version.Current().String())
		return
	}

	fmt.Fprintln(os.Stderr, "diyddns-client: not yet implemented (Plan 01 scaffold)")
	os.Exit(2)
}
