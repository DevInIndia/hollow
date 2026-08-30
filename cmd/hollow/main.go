// Command hollow is a DNS toolkit: an iterative resolver, a caching server, and
// wire-level inspection, built on the Go standard library alone.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/DevInIndia/hollow/internal/cli"
)

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(cli.ExitFailure)
	}

	switch verb := os.Args[1]; verb {
	case "help", "-h", "--help":
		usage(os.Stdout)
	case "resolve":
		os.Exit(cli.Resolve(os.Args[2:], os.Stdout, os.Stderr))
	case "trace":
		os.Exit(cli.Trace(os.Args[2:], os.Stdout, os.Stderr))
	case "inspect":
		os.Exit(cli.Inspect(os.Args[2:], os.Stdout, os.Stderr))
	case "serve":
		os.Exit(cli.Serve(os.Args[2:], os.Stdout, os.Stderr))
	default:
		fmt.Fprintf(os.Stderr, "hollow: unknown command %q\n", verb)
		usage(os.Stderr)
		os.Exit(cli.ExitFailure)
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `hollow is a DNS toolkit built on the Go standard library alone.

usage:

	hollow resolve <name> [type]   resolve a name from the root servers
	hollow trace <name> [type]     draw the delegation path the resolver walked
	hollow inspect <name> [type]   dump the reply octet by octet, annotated
	hollow serve                   answer DNS on 127.0.0.1:15353, udp and tcp

Run "hollow <command> -h" for the flags a command accepts.
`)
}
