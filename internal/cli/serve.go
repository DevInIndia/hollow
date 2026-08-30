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

	"github.com/DevInIndia/hollow/internal/cache"
	"github.com/DevInIndia/hollow/internal/resolver"
	"github.com/DevInIndia/hollow/internal/server"
	"github.com/DevInIndia/hollow/internal/single"
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
		size    = fs.Int("cache-size", cache.DefaultEntries, "answers to hold in the cache; 0 disables caching")
		stale   = fs.Duration("serve-stale", 0, "how long past expiry an answer may still be served when resolution fails; 0 disables")
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
	if *size < 0 {
		fmt.Fprintf(stderr, "hollow: --cache-size %d, want zero or more\n", *size)
		return ExitFailure
	}
	if *stale > 0 && *size == 0 {
		// Serving stale answers out of a cache that holds none is not a
		// configuration with a sensible reading, and silently ignoring one of
		// two flags the operator set is worse than refusing both.
		fmt.Fprintln(stderr, "hollow: --serve-stale needs a cache, but --cache-size is 0")
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

	// One cache for the whole process, hanging off the shared resolver, so that
	// what one client's query learned is there for the next client's. A cache
	// per worker would divide the hit rate by the size of the pool and hold
	// sixty-four copies of the same answers.
	if *size > 0 {
		r.Cache = cache.New(cache.Config{Entries: *size, StaleFor: *stale})
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
	switch {
	case r.Cache == nil:
		fmt.Fprintln(stdout, "cache disabled, every query walks from the root")
	case *stale > 0:
		fmt.Fprintf(stdout, "cache holding %d answers, serving stale for up to %v\n", *size, *stale)
	default:
		fmt.Fprintf(stdout, "cache holding %d answers\n", *size)
	}

	if err := s.Serve(ctx, conns); err != nil {
		fmt.Fprintf(stderr, "hollow: %v\n", err)
		return ExitFailure
	}
	if r.Cache != nil {
		// Reported at the end for the same reason the server reports dropped
		// packets there: a number nobody can see is a number nobody checks, and
		// the hit rate is the whole claim this feature is making.
		st := r.Cache.Stats()
		fmt.Fprintf(stdout, "cache: %d hits, %d misses, %d served stale, %d entries, %d evicted\n",
			st.Hits, st.Misses, st.Stale, st.Entries, st.Evictions)
	}
	fmt.Fprintln(stdout, "hollow stopped")
	return ExitOK
}

// recursor answers a query by resolving it from the root.
//
// It must not be copied: inflight holds a mutex, and every use of a recursor is
// through the pointer stored in the server's Handler field.
type recursor struct {
	resolver *resolver.Resolver
	log      *slog.Logger

	// inflight collapses concurrent identical queries into one resolution.
	//
	// The cache answers the second query for a name. This answers the second
	// query that arrives while the first is still walking, which is the case
	// the cache cannot help with and which a DNS server sees constantly: a
	// page load fires a dozen lookups for one host at once, and a cold name
	// under a sixty-four wide pool would otherwise start sixty-four identical
	// walks from the root, each ending by storing the answer the others were
	// about to store.
	inflight single.Group[wire.Question, *resolver.Result]
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

	// Keyed on the folded name, so two clients spelling one name differently
	// share a walk rather than starting two. The reply each client gets echoes
	// its own question, which is built below from that client's message.
	//
	// The context belongs to whichever query arrived first, and the others
	// inherit its deadline. That is sound here because the server gives every
	// query the same timeout, so the leader's deadline is representative rather
	// than arbitrary.
	key := wire.Question{Name: q.Name.Fold(), Type: q.Type, Class: q.Class}
	res, err, shared := rc.inflight.Do(key, func() (*resolver.Result, error) {
		return rc.resolver.Resolve(ctx, q)
	})
	if err != nil {
		rc.log.Debug("resolution failed", "name", q.Name.String(), "type", q.Type.String(), "err", err)
		return refuse(query, wire.RcodeServFail)
	}
	if res.Stale {
		// Upstream failed and the client is getting an answer that expired.
		// That is a deliberate trade and not a detail to bury at debug level:
		// the answer may be wrong, and the operator is the one who can find out
		// why resolution is failing.
		rc.log.Warn("served a stale answer, resolution failed",
			"name", q.Name.String(), "type", q.Type.String())
	}
	rc.log.Debug("answered",
		"name", q.Name.String(), "type", q.Type.String(),
		"rcode", res.Reply.Msg.Header.Rcode, "queries", res.Queries,
		"cached", res.CacheHit, "shared", shared,
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
