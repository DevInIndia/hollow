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
		asJSON  = fs.Bool("json", false, "output reply as JSON")
		hints   = fs.String("hints", "", "root hints in named.root format; default is the compiled-in list")
		trace   = fs.Bool("trace", false, "show the delegation path as it is walked")
		mixed   = fs.Bool("dns0x20", true, "randomise the case of the query name, and refuse a reply that does not echo it")
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

	if *port == 0 || *port > 65535 {
		fmt.Fprintf(stderr, "hollow: --port %d is not a port\n", *port)
		return ExitFailure
	}
	if *server != "" && *hints != "" {
		fmt.Fprint(stderr, "hollow: --hints applies to resolution from the root, so it cannot be used with --server\n")
		return ExitFailure
	}

	// Ctrl-C during a query should end the process, not be swallowed by a
	// three-second deadline the person waiting cannot see.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	tr := resolver.Transport{
		Timeout:  *timeout,
		ForceTCP: *useTCP,
	}
	if *mixed {
		tr.Case = resolver.NewCasing()
	}
	q := wire.Question{Name: name, Type: qtype, Class: wire.ClassIN}

	var reply *resolver.Reply
	if *server != "" {
		// A server named on the command line is being asked to do the work, so
		// it gets RD. The iterative path below clears it, because an
		// authoritative server asked to recurse either refuses or, worse, does
		// not.
		tr.RecursionDesired = true
		addr, err := netip.ParseAddr(*server)
		if err != nil {
			fmt.Fprintf(stderr, "hollow: --server takes an IP address, not a name: %v\n", err)
			return ExitFailure
		}
		if reply, err = tr.Exchange(ctx, netip.AddrPortFrom(addr, uint16(*port)), q); err != nil {
			fmt.Fprintf(stderr, "hollow: %v\n", err)
			return ExitFailure
		}
	} else {
		res, err := iterate(ctx, tr, q, *hints, uint16(*port), traceWriter(*trace, stderr))
		if err != nil {
			fmt.Fprintf(stderr, "hollow: %v\n", err)
			return ExitFailure
		}
		reply = res.Reply
		// The CNAME links were collected across separate exchanges, so they are
		// not in the final message. Put them back at the front of the answer,
		// which is where they would be had one server resolved the chain, and
		// where a reader expects to find them.
		reply.Msg.Answers = append(append([]wire.RR{}, res.CNAMEs...), reply.Msg.Answers...)
	}

	if *asJSON {
		if err := writeJSON(stdout, reply, q); err != nil {
			fmt.Fprintf(stderr, "hollow: writing the JSON reply: %v\n", err)
			return ExitFailure
		}
	} else if err := writeDig(stdout, reply, q); err != nil {
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
