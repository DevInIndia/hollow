// Command hollow is a DNS toolkit: an iterative resolver, a caching server, and
// wire-level inspection, built on the Go standard library alone.
package main

import (
	"fmt"
	"io"
	"os"
)

// Exit codes are part of the command-line contract, so callers can branch on a
// name that does not resolve without parsing output.
const (
	exitOK       = 0
	exitNXDomain = 1
	exitFailure  = 2
)

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(exitFailure)
	}

	switch verb := os.Args[1]; verb {
	case "help", "-h", "--help":
		usage(os.Stdout)
	case "resolve", "serve":
		fmt.Fprintf(os.Stderr, "hollow: %s is not implemented yet\n", verb)
		os.Exit(exitFailure)
	default:
		fmt.Fprintf(os.Stderr, "hollow: unknown command %q\n", verb)
		usage(os.Stderr)
		os.Exit(exitFailure)
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `hollow is a DNS toolkit built on the Go standard library alone.

usage:

	hollow resolve <name> [type]   resolve a name iteratively from the root
	hollow serve                   run a caching DNS server

Run "hollow <command> -h" for the flags a command accepts.
`)
}
