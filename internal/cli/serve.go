package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/DevInIndia/hollow/internal/blocklist"
	"github.com/DevInIndia/hollow/internal/cache"
	"github.com/DevInIndia/hollow/internal/resolver"
	"github.com/DevInIndia/hollow/internal/rrl"
	"github.com/DevInIndia/hollow/internal/server"
	"github.com/DevInIndia/hollow/internal/single"
	"github.com/DevInIndia/hollow/internal/stats"
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
		mode    = fs.String("block-mode", "nxdomain", "how a blocked name is answered: nxdomain, null or nodata")
		mixed   = fs.Bool("dns0x20", true, "randomise the case of each outgoing query name, and refuse a reply that does not echo it")
		rate    = fs.Int("rrl", rrl.DefaultPerSecond, "responses per second to one client network before rate limiting starts; 0 disables")
		slip    = fs.Int("rrl-slip", rrl.DefaultSlip, "answer every Nth rate-limited response truncated instead of dropping it; 0 drops them all")
	)
	var forward, block, allow stringList
	fs.Var(&forward, "forward", "resolve by asking this server instead of walking from the root; repeatable, tried in order")
	fs.Var(&block, "block", "blocklist file in hosts, domain-per-line or adblock format; repeatable")
	fs.Var(&allow, "allow", "allowlist file in the same formats, overriding every block; repeatable")
	var trusted stringList
	fs.Var(&trusted, "rrl-trusted", "network exempt from rate limiting; repeatable, and replaces the loopback default")
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
	if len(forward) > 0 && *hints != "" {
		// --hints names the roots to start a walk from, and forwarding does not
		// walk. Same reasoning as the resolve verb refusing --hints with
		// --server: honouring one and dropping the other silently would leave
		// the operator believing they got something they did not.
		fmt.Fprintln(stderr, "hollow: --hints applies to resolution from the root, so it cannot be used with --forward")
		return ExitFailure
	}
	forwarders, err := parseServers(forward)
	if err != nil {
		fmt.Fprintf(stderr, "hollow: %v\n", err)
		return ExitFailure
	}
	if *rate < 0 {
		fmt.Fprintf(stderr, "hollow: --rrl %d, want zero or more\n", *rate)
		return ExitFailure
	}
	if *slip < 0 {
		fmt.Fprintf(stderr, "hollow: --rrl-slip %d, want zero or more\n", *slip)
		return ExitFailure
	}
	exempt, err := parsePrefixes(trusted)
	if err != nil {
		fmt.Fprintf(stderr, "hollow: %v\n", err)
		return ExitFailure
	}
	if len(trusted) > 0 && *rate == 0 {
		fmt.Fprintln(stderr, "hollow: --rrl-trusted exempts networks from rate limiting, but --rrl is 0")
		return ExitFailure
	}
	blockMode, err := blocklist.ParseMode(*mode)
	if err != nil {
		fmt.Fprintf(stderr, "hollow: %v\n", err)
		return ExitFailure
	}
	if len(allow) > 0 && len(block) == 0 {
		// An allowlist with nothing to override does nothing. Saying so beats
		// starting a server that quietly ignores a flag the operator set.
		fmt.Fprintln(stderr, "hollow: --allow needs something to allow past, but no --block was given")
		return ExitFailure
	}

	// Loaded before anything binds a socket, so a bad path is a message and an
	// exit rather than a running server that is not filtering.
	var blocks *blocklist.List
	if len(block) > 0 {
		blocks, err = blocklist.Load(block, allow)
		if err != nil {
			fmt.Fprintf(stderr, "hollow: %v\n", err)
			return ExitFailure
		}
	}

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level}))

	// One cache for the whole process, so that what one client's query learned
	// is there for the next client's. A cache per worker would divide the hit
	// rate by the size of the pool and hold sixty-four copies of the same
	// answers. It is shared by both resolution modes: an answer is an answer
	// whether it was walked to or asked for.
	var store *cache.Cache
	if *size > 0 {
		store = cache.New(cache.Config{Entries: *size, StaleFor: *stale})
	}

	// Built once and shared. Neither implementation holds per-query state, so
	// every worker uses the same one rather than re-reading the hints file and
	// re-shuffling a fresh copy of the roots on every packet.
	var answer answerer
	transport := resolver.Transport{Timeout: resolver.DefaultTimeout}
	if *mixed {
		// One Casing for the process. Which servers do not preserve case is
		// learned once and shared by every worker, rather than each of them
		// paying the timeout to find out for itself.
		transport.Case = resolver.NewCasing()
	}
	if len(forwarders) > 0 {
		answer = &resolver.Forwarder{Transport: transport, Servers: forwarders, Cache: store}
	} else {
		r, err := newResolver(transport, *hints, 53, nil)
		if err != nil {
			fmt.Fprintf(stderr, "hollow: %v\n", err)
			return ExitFailure
		}
		r.Cache = store
		answer = r
	}

	// Statistics are always collected. There is no flag to turn them off
	// because there is no cost worth a flag: three atomic adds, a sharded map
	// update and a send that cannot block, against a query that may spend half
	// a second on the network. A knob here would only be a knob to get wrong.
	col := stats.New()
	if store != nil {
		// The one number that cannot be accumulated from events, because it is
		// a level rather than a total.
		col.CacheEntries = store.Len
	}

	// Off is a nil limiter rather than a limiter that permits everything, so
	// the whole mechanism costs one nil check per query when it is not in use.
	var limiter *rrl.Limiter
	if *rate > 0 {
		limiter = rrl.New(rrl.Config{PerSecond: *rate, Slip: *slip, Trusted: exempt})
	}

	s := &server.Server{
		Handler: &recursor{resolver: answer, log: log, stats: col, blocks: blocks, blockMode: blockMode},
		Workers: *workers,
		Timeout: *timeout,
		Log:     log,
		Limiter: limiter,
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
	reportMode(stdout, forwarders, *mixed)
	switch {
	case store == nil && len(forwarders) > 0:
		fmt.Fprintln(stdout, "cache disabled, every query is forwarded")
	case store == nil:
		fmt.Fprintln(stdout, "cache disabled, every query walks from the root")
	case *stale > 0:
		fmt.Fprintf(stdout, "cache holding %d answers, serving stale for up to %v\n", *size, *stale)
	default:
		fmt.Fprintf(stdout, "cache holding %d answers\n", *size)
	}
	reportBlocklist(stdout, blocks, blockMode)
	reportLimiter(stdout, *rate, *slip, exempt)

	if err := s.Serve(ctx, conns); err != nil {
		fmt.Fprintf(stderr, "hollow: %v\n", err)
		return ExitFailure
	}
	if store != nil {
		// Reported at the end for the same reason the server reports dropped
		// packets there: a number nobody can see is a number nobody checks, and
		// the hit rate is the whole claim this feature is making.
		st := store.Stats()
		fmt.Fprintf(stdout, "cache: %d hits, %d misses, %d served stale, %d entries, %d evicted\n",
			st.Hits, st.Misses, st.Stale, st.Entries, st.Evictions)
	}
	if limited, dropped, slipped, _, _, tracked := limiter.Stats(); limited > 0 {
		fmt.Fprintf(stdout, "rate limiting: %d responses held back, %d dropped, %d answered truncated, %s tracked\n",
			limited, dropped, slipped, plural(tracked, "network", "networks"))
	}
	report(stdout, col.Snapshot())
	fmt.Fprintln(stdout, "hollow stopped")
	return ExitOK
}

// loopback is exempt from rate limiting unless the operator names other
// networks instead.
//
// The default listen address is 127.0.0.1, so without this the first thing rate
// limiting would ever limit is the operator testing their own server, and the
// first impression of the feature would be that it is broken. A client that can
// reach a loopback listener is already on the machine.
var loopback = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
}

// parsePrefixes reads the --rrl-trusted networks. A bare address is taken as
// itself, so an operator can name one host without working out the mask.
func parsePrefixes(list []string) ([]netip.Prefix, error) {
	if len(list) == 0 {
		return loopback, nil
	}
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("--rrl-trusted %q is neither a network nor an address", s)
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// reportLimiter says whether responses are being rate limited, and to whom they
// are not.
func reportLimiter(w io.Writer, rate, slip int, trusted []netip.Prefix) {
	if rate == 0 {
		fmt.Fprintln(w, "response rate limiting off, every query that resolves is answered")
		return
	}
	how := fmt.Sprintf("%d dropped", slip)
	if slip > 0 {
		how = fmt.Sprintf("every %s answered truncated so a real client retries over tcp", ordinal(slip))
	}
	names := make([]string, len(trusted))
	for i, p := range trusted {
		names[i] = p.String()
	}
	fmt.Fprintf(w, "rate limiting responses past %d a second to one client network, %s; %s exempt\n",
		rate, how, strings.Join(names, ", "))
}

func ordinal(n int) string {
	switch n {
	case 1:
		return "one"
	case 2:
		return "second one"
	case 3:
		return "third one"
	}
	return fmt.Sprintf("%dth one", n)
}

// stringList collects a flag given more than once, which is how --block and
// --allow take several files. flag has no built-in for it.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(v string) error {
	if v == "" {
		return errors.New("empty path")
	}
	*s = append(*s, v)
	return nil
}

// parseServers reads the --forward addresses.
//
// A bare address gets port 53, and an address with a port keeps it, which means
// "1.1.1.1" and "127.0.0.1:5353" both work. ParseAddrPort is tried first
// because ParseAddr accepts "2606:4700:4700::1111" and would happily read a
// bracketed IPv6 address with a port as neither.
//
// An address, never a name. Resolving the name of the server that resolves
// names needs a resolver, and the one in this process is the one being
// configured.
func parseServers(list []string) ([]netip.AddrPort, error) {
	var out []netip.AddrPort
	for _, s := range list {
		if ap, err := netip.ParseAddrPort(s); err == nil {
			out = append(out, ap)
			continue
		}
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("--forward %q takes an IP address, optionally with a port, not a name", s)
		}
		out = append(out, netip.AddrPortFrom(addr, 53))
	}
	return out, nil
}

// reportMode says where answers are going to come from.
//
// Worth a line of its own because it is the one thing about a running hollow
// that a person cannot infer from watching it answer. Both modes return the
// same answers to the same queries; only the trust model differs, and that is
// exactly the sort of thing that should not be silent.
func reportMode(w io.Writer, forwarders []netip.AddrPort, mixedCase bool) {
	defer func() {
		if mixedCase {
			fmt.Fprintln(w, "query names go out with randomised case, and a reply that does not echo it is refused")
		}
	}()
	if len(forwarders) == 0 {
		fmt.Fprintln(w, "resolving iteratively from the root")
		return
	}
	names := make([]string, len(forwarders))
	for i, f := range forwarders {
		names[i] = f.String()
	}
	fmt.Fprintf(w, "forwarding to %s, tried in order; the delegation path is not walked\n", strings.Join(names, ", "))
}

// reportBlocklist says what was loaded, at startup, where an operator is still
// watching.
//
// The skipped count is the part that matters. Lines that do not parse are
// counted and dropped rather than being fatal, which is only defensible if the
// number is put in front of somebody: a list that half-loads in silence looks
// exactly like one that loaded whole, and the names that went missing are the
// ones that stop being blocked.
func reportBlocklist(w io.Writer, l *blocklist.List, mode blocklist.Mode) {
	if l == nil {
		return
	}
	exact, wildcard, allowed, skipped := l.Counts()
	fmt.Fprintf(w, "blocking %d names and %d domains with everything under them, %d allowed past, answering %s\n",
		exact, wildcard, allowed, mode)
	if skipped > 0 {
		fmt.Fprintf(w, "blocklist: %d lines skipped, not in any format hollow reads\n", skipped)
	}
}

// report prints what the server did. Until the control socket exists this is
// the only way the collected statistics are visible, and a library nobody can
// see the output of is indistinguishable from one that does not work.
func report(w io.Writer, s stats.Snapshot) {
	if s.QueriesTotal == 0 {
		fmt.Fprintln(w, "queries: none")
		return
	}
	fmt.Fprintf(w, "queries: %d in %v, %d blocked, %d upstream failures\n",
		s.QueriesTotal, s.Uptime.Round(time.Second), s.QueriesBlocked, s.UpstreamErrors)
	fmt.Fprintf(w, "latency: p50 %v, p99 %v\n",
		s.LatencyP50.Round(time.Millisecond), s.LatencyP99.Round(time.Millisecond))
	if len(s.TopDomains) > 0 {
		fmt.Fprintln(w, "top names:")
		for _, item := range s.TopDomains {
			fmt.Fprintf(w, "  %6d  %s\n", item.Count, item.Name)
		}
	}
	// Both of these are zero in ordinary operation. Printed only when they are
	// not, because a line reading "0 dropped" every time trains an operator to
	// stop reading it, which is the opposite of why it is here.
	if s.EventsDropped > 0 {
		fmt.Fprintf(w, "events: %d dropped, a consumer could not keep up\n", s.EventsDropped)
	}
	if s.NamesDropped > 0 {
		fmt.Fprintf(w, "names: %d sightings left out of the lists above, the counters are full\n", s.NamesDropped)
	}
}

// Named for the call sites in ServeDNS. A bare true or false as the last
// argument of record would be six places where the reader has to go and look at
// the signature to find out what it means.
const (
	notBlocked = false
	wasBlocked = true
)

// answerer is the one thing the handler needs from whatever does the resolving:
// a question in, a result out.
//
// An interface here rather than a concrete type because there are two
// implementations and the handler is genuinely indifferent between them.
// resolver.Resolver walks the delegation path from the root; resolver.Forwarder
// asks a server the operator named. Everything around it, the blocklist, the
// coalescing map, the statistics and the reply construction, is identical for
// both and would be duplicated line for line by a second Handler.
type answerer interface {
	Resolve(ctx context.Context, q wire.Question) (*resolver.Result, error)
}

// recursor answers a query by resolving it.
//
// Still the right name in forwarding mode. What the client is talking to is a
// recursive resolver either way: it sets RA, it does the whole job, and it
// returns a final answer rather than a referral. Where that answer comes from
// is this server's business and not the client's.
//
// It must not be copied: inflight holds a mutex, and every use of a recursor is
// through the pointer stored in the server's Handler field.
type recursor struct {
	resolver answerer
	log      *slog.Logger

	// stats records what was answered. Nil disables it, which is what the
	// handler tests use, and is the same shape as the resolver's nil cache: a
	// concrete type rather than an interface, because there is one
	// implementation and one consumer.
	stats *stats.Collector

	// blocks names the client is refused, and blockMode is what it is refused
	// with. A nil List blocks nothing, which is how the whole feature stays
	// optional without a check here.
	blocks    *blocklist.List
	blockMode blocklist.Mode

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
func (rc *recursor) ServeDNS(ctx context.Context, query *wire.Message, from netip.Addr) *wire.Message {
	start := time.Now()

	if query.Header.Opcode != 0 {
		// UPDATE, NOTIFY and the rest. We are a resolver, and pretending
		// otherwise by returning success would be worse than saying so.
		return rc.record(start, from, wire.Question{}, refuse(query, wire.RcodeNotImp), nil, notBlocked)
	}
	if len(query.Questions) != 1 {
		// RFC 1035 allows QDCOUNT above one and no implementation has ever
		// agreed on what it would mean.
		return rc.record(start, from, wire.Question{}, refuse(query, wire.RcodeFormErr), nil, notBlocked)
	}

	q := query.Questions[0]
	if q.Class != wire.ClassIN {
		return rc.record(start, from, q, refuse(query, wire.RcodeRefused), nil, notBlocked)
	}

	// Before the cache and before the coalescing map. A blocked name must not
	// reach the network at all, and answering it here means a blocked query
	// costs one map lookup rather than a walk from the root.
	if rc.blocks.Blocked(q.Name) {
		rc.log.Debug("blocked", "name", q.Name.String(), "type", q.Type.String())
		return rc.record(start, from, q, blocklist.Reply(query, rc.blockMode), nil, wasBlocked)
	}

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
		return rc.record(start, from, q, refuse(query, wire.RcodeServFail), nil, notBlocked)
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

	return rc.record(start, from, q, rc.reply(query, res), res, notBlocked)
}

// record accounts for one answered query and returns the reply unchanged, so
// that every path out of ServeDNS is counted by wrapping its return rather than
// by remembering to add a line above it. A refusal is a query too: a client
// sending malformed messages is exactly what an operator wants to see in the
// statistics, and leaving those paths out would put the total quietly below the
// number of packets the server actually answered.
//
// res is nil on every path that did not reach a resolution.
//
// blocked is the one thing that cannot be read back off the reply: a blocked
// name and a name that genuinely does not exist both come back NXDOMAIN, which
// is the point of the mode, and inferring one from the other would put every
// real NXDOMAIN in the blocked count.
func (rc *recursor) record(start time.Time, from netip.Addr, q wire.Question, reply *wire.Message, res *resolver.Result, blocked bool) *wire.Message {
	if rc.stats == nil {
		return reply
	}
	e := stats.Event{
		At:       start,
		Client:   from,
		Type:     uint16(q.Type),
		Rcode:    reply.Header.Rcode,
		Blocked:  blocked,
		Duration: time.Since(start),
	}
	if q.Name != "" {
		// Folded, so that two clients spelling one name differently are one row
		// of a top-domains list rather than two.
		e.Name = q.Name.Fold().String()
	}
	if res != nil {
		// CacheHit here means this client's query was answered from the cache
		// without asking anyone. It is deliberately not the same quantity the
		// cache reports at shutdown, which counts every lookup including the
		// ones a walk makes internally while resolving nameserver addresses.
		// Two different questions, so two different numbers: this one is how
		// often a client was spared a walk, and the cache's is how often the
		// cache was useful to anybody.
		e.CacheHit, e.Stale = res.CacheHit, res.Stale
	}
	rc.stats.Record(e)
	return reply
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
