// Package cli implements the hollow command verbs. Everything here is
// presentation: parsing flags, choosing an exit code, and rendering what the
// packages below it return. No protocol decision is made in this package.
package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/DevInIndia/hollow/internal/resolver"
	"github.com/DevInIndia/hollow/internal/wire"
)

// Exit codes are part of the command-line contract, so a script can tell a name
// that does not exist from a resolver that could not answer without parsing
// output meant for a person.
const (
	ExitOK       = 0
	ExitNXDomain = 1
	ExitFailure  = 2
)

// Resolve runs the resolve verb and returns the process exit code.
func Resolve(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("hollow resolve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		server  = fs.String("server", "", "ask this server directly instead of resolving from the root")
		port    = fs.Uint("port", 53, "port to query")
		useTCP  = fs.Bool("tcp", false, "query over TCP instead of falling back to it")
		timeout = fs.Duration("timeout", resolver.DefaultTimeout, "deadline for one exchange with one server")
	)
	fs.Usage = func() {
		fmt.Fprint(stderr, "usage: hollow resolve [flags] <name> [type]\n\nflags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return ExitFailure // flag has already explained itself
	}

	if fs.NArg() < 1 || fs.NArg() > 2 {
		fs.Usage()
		return ExitFailure
	}
	name, err := wire.ParseName(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "hollow: %v\n", err)
		return ExitFailure
	}
	qtype := wire.TypeA
	if fs.NArg() == 2 {
		if qtype, err = wire.ParseType(fs.Arg(1)); err != nil {
			fmt.Fprintf(stderr, "hollow: %v\n", err)
			return ExitFailure
		}
	}

	if *server == "" {
		fmt.Fprint(stderr, "hollow: iterative resolution is not implemented yet; name a server with --server\n")
		return ExitFailure
	}
	addr, err := netip.ParseAddr(*server)
	if err != nil {
		fmt.Fprintf(stderr, "hollow: --server takes an IP address, not a name: %v\n", err)
		return ExitFailure
	}
	if *port == 0 || *port > 65535 {
		fmt.Fprintf(stderr, "hollow: --port %d is not a port\n", *port)
		return ExitFailure
	}

	// Ctrl-C during a query should end the process, not be swallowed by a
	// three-second deadline the person waiting cannot see.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	tr := &resolver.Transport{
		Timeout: *timeout,
		// A server named on the command line is being asked to do the work, so
		// it needs RD. The iterative loop will run its own Transport with RD
		// clear, because an authoritative server asked to recurse either
		// refuses or, worse, does not.
		RecursionDesired: true,
		ForceTCP:         *useTCP,
	}
	q := wire.Question{Name: name, Type: qtype, Class: wire.ClassIN}

	reply, err := tr.Exchange(ctx, netip.AddrPortFrom(addr, uint16(*port)), q)
	if err != nil {
		fmt.Fprintf(stderr, "hollow: %v\n", err)
		return ExitFailure
	}
	if err := writeDig(stdout, reply, q); err != nil {
		fmt.Fprintf(stderr, "hollow: writing the reply: %v\n", err)
		return ExitFailure
	}

	switch reply.Msg.Header.Rcode {
	case wire.RcodeSuccess:
		return ExitOK
	case wire.RcodeNXDomain:
		return ExitNXDomain
	default:
		return ExitFailure
	}
}
