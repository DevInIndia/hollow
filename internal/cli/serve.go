package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/DevInIndia/hollow/internal/resolver"
	"github.com/DevInIndia/hollow/internal/server"
	"github.com/DevInIndia/hollow/internal/wire"
)

// DefaultAddr is where the server listens unless told otherwise.
//
// Loopback, not every interface, so a first run does not raise a Windows
// firewall prompt. Port 15353 rather than 53 so it needs no privileges, and not
// 5353, which avahi-daemon holds on most desktop Linux and mDNSResponder holds
// unconditionally on macOS.
const DefaultAddr = "127.0.0.1:15353"

// Serve runs the serve verb and returns the process exit code.
func Serve(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("hollow serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		addr    = fs.String("addr", DefaultAddr, "address to listen on, UDP and TCP")
		timeout = fs.Duration("timeout", server.DefaultTimeout, "deadline for answering one query")
		workers = fs.Int("workers", server.DefaultWorkers, "size of the UDP worker pool")
		hints   = fs.String("hints", "", "root hints in named.root format; default is the compiled-in list")
		verbose = fs.Bool("verbose", false, "log every query answered")
	)
	fs.Usage = func() {
		fmt.Fprint(stderr, "usage: hollow serve [flags]\n\nflags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return ExitFailure
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return ExitFailure
	}
	if *workers < 1 {
		fmt.Fprintf(stderr, "hollow: --workers %d, want at least one\n", *workers)
		return ExitFailure
	}

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level}))

	// The resolver is built once and shared. It holds no per-query state, so
	// every worker uses the same one rather than re-reading the hints file and
	// re-shuffling a fresh copy of the roots on every packet.
	r, err := newResolver(resolver.Transport{Timeout: resolver.DefaultTimeout}, *hints, 53, nil)
	if err != nil {
		fmt.Fprintf(stderr, "hollow: %v\n", err)
		return ExitFailure
	}

	s := &server.Server{
		Handler: &recursor{resolver: r, log: log},
		Workers: *workers,
		Timeout: *timeout,
		Log:     log,
	}

	// Bound before the signal handler is installed, so a bind failure reports
	// itself and exits rather than waiting for a Ctrl-C that will never come.
	conns, err := server.Listen(*addr)
	if err != nil {
		fmt.Fprintf(stderr, "hollow: %v\n", err)
		return ExitFailure
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(stdout, "hollow listening on %s, udp and tcp\n", conns.Addr())
	if err := s.Serve(ctx, conns); err != nil {
		fmt.Fprintf(stderr, "hollow: %v\n", err)
		return ExitFailure
	}
	fmt.Fprintln(stdout, "hollow stopped")
	return ExitOK
}

// recursor answers a query by resolving it from the root.
type recursor struct {
	resolver *resolver.Resolver
	log      *slog.Logger
}

// ServeDNS resolves one query. It is called from many goroutines at once;
// resolver.Resolver keeps no state across calls, which is what makes that safe.
func (rc *recursor) ServeDNS(ctx context.Context, query *wire.Message) *wire.Message {
	if query.Header.Opcode != 0 {
		// UPDATE, NOTIFY and the rest. We are a resolver, and pretending
		// otherwise by returning success would be worse than saying so.
		return refuse(query, wire.RcodeNotImp)
	}
	if len(query.Questions) != 1 {
		// RFC 1035 allows QDCOUNT above one and no implementation has ever
		// agreed on what it would mean.
		return refuse(query, wire.RcodeFormErr)
	}

	q := query.Questions[0]
	if q.Class != wire.ClassIN {
		return refuse(query, wire.RcodeRefused)
	}

	start := time.Now()
	res, err := rc.resolver.Resolve(ctx, q)
	if err != nil {
		rc.log.Debug("resolution failed", "name", q.Name.String(), "type", q.Type.String(), "err", err)
		return refuse(query, wire.RcodeServFail)
	}
	rc.log.Debug("answered",
		"name", q.Name.String(), "type", q.Type.String(),
		"rcode", res.Reply.Msg.Header.Rcode, "queries", res.Queries,
		"took", time.Since(start).Round(time.Millisecond).String())

	return rc.reply(query, res)
}

// reply turns a resolution into the message the client gets.
func (rc *recursor) reply(query *wire.Message, res *resolver.Result) *wire.Message {
	upstream := res.Reply.Msg

	out := &wire.Message{
		Header: wire.Header{
			ID:               query.Header.ID,
			Response:         true,
			RecursionDesired: query.Header.RecursionDesired,

			// We do recurse, whether or not the client asked. Advertising it is
			// what stops a client deciding we are a stub and giving up.
			RecursionAvailable: true,

			// Not authoritative. The records came from a server that is, and
			// this one is repeating them.
			Authoritative: false,

			Rcode: upstream.Header.Rcode,
		},
		Questions: query.Questions,
	}

	// The links followed across earlier exchanges come first, in the order they
	// were walked, then whatever the last server said. That is the shape a
	// client expects from a recursive server that did the chain itself.
	out.Answers = append(append(out.Answers, res.CNAMEs...), upstream.Answers...)
	out.Authority = upstream.Authority

	// The upstream additional section is not passed on. It is mostly glue for a
	// delegation the client is not walking, and unlike the glue used during
	// resolution it was never bailiwick-checked, since nothing downstream of the
	// answer needs it. Forwarding unchecked records to a client is how a
	// resolver launders someone else's data. The cost is that an MX or SRV
	// answer arrives without its addresses attached and the client looks them up
	// itself.
	out.SetEDNS(wire.EDNS{UDPSize: wire.DefaultUDPSize})
	return out
}

// refuse builds a reply carrying nothing but an rcode.
func refuse(query *wire.Message, rcode uint8) *wire.Message {
	out := &wire.Message{
		Header: wire.Header{
			ID:                 query.Header.ID,
			Response:           true,
			Opcode:             query.Header.Opcode,
			RecursionDesired:   query.Header.RecursionDesired,
			RecursionAvailable: true,
			Rcode:              rcode,
		},
		Questions: query.Questions,
	}
	out.SetEDNS(wire.EDNS{UDPSize: wire.DefaultUDPSize})
	return out
}
