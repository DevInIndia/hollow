package resolver

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"strings"

	"github.com/DevInIndia/hollow/internal/wire"
)

// Failures that end a resolution rather than one exchange within it. Transport
// errors from Exchange are not among these: a single server refusing to answer
// moves to the next server, and only running out of servers is fatal.
var (
	ErrResolutionLimit = errors.New("resolver: resolution exceeded its budget")
	ErrNoNameserver    = errors.New("resolver: no nameserver answered")
	ErrBadReferral     = errors.New("resolver: referral does not descend toward the name")
	ErrCNAMELoop       = errors.New("resolver: CNAME chain loops or runs too long")
	ErrNoHints         = errors.New("resolver: no root hints to start from")
)

// Budgets. These bound the work one call can cause, which matters because the
// zones being walked are controlled by whoever owns the name, not by us. A
// delegation chain can be made arbitrarily deep and nameserver names can be
// made to require their own resolution, so an unbounded loop here is a denial
// of service that anyone can aim at us by publishing a zone.
const (
	DefaultMaxDepth   = 16
	DefaultMaxQueries = 64
	DefaultMaxCNAME   = 8
)

// Kind is what a reply turned out to be.
type Kind int

const (
	KindFailure  Kind = iota // no reply, or one whose RCODE says to ask elsewhere
	KindAnswer               // records for the question, possibly a CNAME
	KindReferral             // NS records pointing further down
	KindNXDomain             // the name does not exist
	KindNoData               // the name exists, this type does not
)

func (k Kind) String() string {
	switch k {
	case KindAnswer:
		return "answer"
	case KindReferral:
		return "referral"
	case KindNXDomain:
		return "nxdomain"
	case KindNoData:
		return "nodata"
	default:
		return "failure"
	}
}

// Step is one exchange, reported to Resolver.Trace as it happens.
type Step struct {
	Zone   wire.Name // the zone whose servers were asked
	Server netip.AddrPort
	Query  wire.Question
	Kind   Kind
	Err    error // set when Kind is KindFailure
	Reply  *Reply
}

// Result is a completed resolution.
type Result struct {
	// Reply is the exchange that ended the walk, carrying the message along
	// with who sent it, over which protocol and how long it took. When a CNAME
	// chain was followed it is the reply for the last name in the chain, not
	// the first, which is why CNAMEs below exists.
	Reply *Reply

	// CNAMEs holds the links followed on the way here that Reply does not
	// already show: the ones that arrived in earlier messages, which were
	// discarded once the chain moved on. Links carried by the final message
	// stay where they are, in its answer section.
	//
	// Prepending these to Reply's answers reconstructs the whole chain in the
	// order it was walked, which is what a server resolving it in one go would
	// have returned.
	CNAMEs []wire.RR

	// Queries is how many exchanges the whole resolution cost, including any
	// spent resolving nameserver names that had no glue.
	Queries int
}

// Resolver walks the delegation chain from the root, asking one server at a
// time, and never asks anyone to recurse on its behalf.
//
// The zero value is not usable: Hints must name somewhere to start. That is
// deliberate. Compiling the root servers in here would put a policy decision,
// and thirteen addresses that go stale, inside the loop that uses them.
type Resolver struct {
	// Transport carries each exchange. Resolve works on a copy of it with
	// RecursionDesired cleared, so setting that field here has no effect.
	Transport Transport

	// Hints are the addresses of the root servers, each carrying its own port.
	Hints []netip.AddrPort

	// Port is where to reach nameservers learned from glue, which arrives as
	// bare addresses with no port. Zero means 53. Anything else is a private
	// root, which is what the tests stand up and what an internal deployment
	// would point at.
	Port uint16

	// Limits. Zero means the Default above.
	MaxDepth   int
	MaxQueries int
	MaxCNAME   int

	// Shuffle permutes the candidate servers for one step. Nil means
	// math/rand/v2.Shuffle. Tests replace it to make an order deterministic.
	Shuffle func(n int, swap func(i, j int))

	// Trace, when set, is called once per exchange. It must not block.
	Trace func(Step)
}

// Resolve answers a question by walking down from the root, following CNAMEs.
func (r *Resolver) Resolve(ctx context.Context, q wire.Question) (*Result, error) {
	if q.Class == 0 {
		q.Class = wire.ClassIN
	}
	if len(r.Hints) == 0 {
		return nil, ErrNoHints
	}
	// Copy the transport and clear RD rather than mutating the caller's
	// Resolver, which may be shared across goroutines by the server.
	t := r.Transport
	t.RecursionDesired = false
	s := &session{r: r, transport: t, resolving: make(map[wire.Name]bool)}

	// Names already visited in this chain. A CNAME pointing back at one of them
	// is a loop, and a loop that the hop count alone would take eight queries
	// to notice.
	seen := map[wire.Name]bool{fold(q.Name): true}
	var chain []wire.RR

	cur := q
	for hop := 0; ; hop++ {
		if hop > r.maxCNAME() {
			return nil, fmt.Errorf("resolver: resolving %q: %w", q.Name, ErrCNAMELoop)
		}
		rep, err := s.iterate(ctx, cur)
		if err != nil {
			return nil, err
		}

		end, links, found := chase(rep.Msg, cur.Name, cur.Type)

		// Done when the type was found, when nothing redirected us, or when
		// the CNAME was itself what was asked for.
		//
		// Note what is not accumulated here: any links this last message
		// carried are already in its own answer section, so adding them to the
		// chain would report them twice to a caller that renders both.
		if found || len(links) == 0 || cur.Type == wire.TypeCNAME {
			return &Result{Reply: rep, CNAMEs: chain, Queries: s.queries}, nil
		}

		// These links came from a message that is about to be discarded, so
		// this is the only record of them.
		chain = append(chain, links...)
		if seen[fold(end)] {
			return nil, fmt.Errorf("resolver: resolving %q: %w", q.Name, ErrCNAMELoop)
		}
		seen[fold(end)] = true
		cur.Name = end
	}
}

// session carries the budgets and cycle guards that are shared across a whole
// resolution, including any nested one started to find a nameserver's address.
// They are shared precisely so that a nested resolution cannot restart the
// budget and turn one call into unbounded work.
type session struct {
	r *Resolver

	// transport is the caller's, with RecursionDesired cleared. Asking an
	// authoritative server to recurse is what a resolver does instead of
	// resolving, and a server that honoured it would hand back an answer this
	// code never verified the delegation path for.
	transport Transport

	queries   int
	resolving map[wire.Name]bool
}

// iterate walks delegations for one question until something that is not a
// referral comes back.
func (s *session) iterate(ctx context.Context, q wire.Question) (*Reply, error) {
	zone := wire.Root
	servers := s.r.candidates(s.r.Hints)

	for depth := 0; depth <= s.r.maxDepth(); depth++ {
		rep, err := s.ask(ctx, servers, zone, q)
		if err != nil {
			return nil, err
		}
		if classify(rep.Msg, q) != KindReferral {
			return rep, nil
		}
		next, child, err := s.delegation(ctx, rep.Msg, zone, q, rep.Server)
		if err != nil {
			return nil, err
		}
		zone, servers = child, next
	}
	return nil, fmt.Errorf("resolver: resolving %q: %d delegations deep: %w", q.Name, s.r.maxDepth(), ErrResolutionLimit)
}

// ask puts one question to each server in turn and returns the first usable
// reply. A server that times out or answers SERVFAIL is not retried, since the
// next one in the list is a better use of the budget than the same one again.
func (s *session) ask(ctx context.Context, servers []netip.AddrPort, zone wire.Name, q wire.Question) (*Reply, error) {
	if len(servers) == 0 {
		return nil, fmt.Errorf("resolver: zone %q has no reachable servers: %w", zone, ErrNoNameserver)
	}

	var last error
	for _, server := range servers {
		if s.queries >= s.r.maxQueries() {
			return nil, fmt.Errorf("resolver: resolving %q: %d queries: %w", q.Name, s.queries, ErrResolutionLimit)
		}
		s.queries++

		reply, err := s.transport.Exchange(ctx, server, q)
		if err != nil {
			// A cancelled or expired context is the caller leaving, not this
			// server failing. Trying the next one would ignore the deadline and
			// report the wrong cause for the wrong reason.
			if ctx.Err() != nil {
				return nil, err
			}
			last = err
			s.trace(Step{Zone: zone, Server: server, Query: q, Kind: KindFailure, Err: err})
			continue
		}

		kind := classify(reply.Msg, q)
		s.trace(Step{Zone: zone, Server: server, Query: q, Kind: kind, Reply: reply})
		if kind == KindFailure {
			last = fmt.Errorf("%v answered rcode %d", server, reply.Msg.Header.Rcode)
			continue
		}
		return reply, nil
	}
	return nil, fmt.Errorf("resolver: zone %q, %d servers tried, last: %v: %w", zone, len(servers), last, ErrNoNameserver)
}

// classify decides what a reply is. The order matters: an RCODE outranks the
// sections, and an SOA in the authority section outranks NS records there.
func classify(m *wire.Message, q wire.Question) Kind {
	switch m.Header.Rcode {
	case wire.RcodeNXDomain:
		return KindNXDomain
	case wire.RcodeSuccess:
		// fall through to the sections
	default:
		// SERVFAIL, REFUSED, FORMERR, NOTIMP. All mean ask someone else.
		return KindFailure
	}

	for _, rr := range m.Answers {
		if rr.Name.EqualFold(q.Name) && (rr.Type == q.Type || rr.Type == wire.TypeCNAME) {
			return KindAnswer
		}
	}

	// An SOA in the authority section is a zone speaking for itself: the name
	// is mine and there is no record of that type. That is NODATA, and it is
	// checked before NS records because a negative answer may carry both.
	for _, rr := range m.Authority {
		if rr.Type == wire.TypeSOA {
			return KindNoData
		}
	}
	for _, rr := range m.Authority {
		if rr.Type == wire.TypeNS {
			return KindReferral
		}
	}
	return KindNoData
}

// delegation reads the nameservers out of a referral and works out where to ask
// next. It is the security-sensitive half of the loop: everything here arrives
// from a server that has an interest in where we go.
func (s *session) delegation(ctx context.Context, msg *wire.Message, zone wire.Name, q wire.Question, from netip.AddrPort) ([]netip.AddrPort, wire.Name, error) {
	// All the NS records in a referral name one zone. Take the first as the
	// child and ignore any that disagree, rather than merging two delegations
	// into one server list.
	var child wire.Name
	var hosts []wire.Name
	for _, rr := range msg.Authority {
		ns, ok := rr.Data.(wire.NS)
		if !ok {
			continue
		}
		if child == "" {
			child = rr.Name
		}
		if rr.Name.EqualFold(child) {
			hosts = append(hosts, ns.Host)
		}
	}

	// The referral has to make progress toward the name being resolved. It must
	// descend strictly below the zone just asked, and the name must lie inside
	// it. Without this a server can point sideways or back upward and the walk
	// runs until the depth limit stops it, which is a loop anyone can trigger
	// by publishing a zone.
	switch {
	case child == "":
		return nil, "", fmt.Errorf("resolver: %v sent a referral with no NS records: %w", from, ErrBadReferral)
	case !child.Within(zone) || child.EqualFold(zone):
		return nil, "", fmt.Errorf("resolver: %v in zone %q referred to %q, which is not below it: %w", from, zone, child, ErrBadReferral)
	case !q.Name.Within(child):
		return nil, "", fmt.Errorf("resolver: %v referred %q to %q, which does not contain it: %w", from, q.Name, child, ErrBadReferral)
	}

	// Glue, filtered by bailiwick: a server may only tell us about names inside
	// the zone it answers for. An A record for bank.example.org attached to a
	// com referral is an attempt to make us believe someone else's address, and
	// it is dropped.
	//
	// The test is against the zone just asked, not the zone being delegated,
	// and the difference is what makes it usable. The root delegates com to
	// a.gtld-servers.net, whose address is not inside com at all. Requiring
	// glue to sit inside the child would reject the real root's own referral
	// and leave every resolution stranded at the first step.
	glue := make(map[wire.Name][]netip.Addr)
	for _, rr := range msg.Additional {
		var addr netip.Addr
		switch d := rr.Data.(type) {
		case wire.A:
			addr = d.Addr
		case wire.AAAA:
			addr = d.Addr
		default:
			continue
		}
		if !rr.Name.Within(zone) {
			continue
		}
		glue[fold(rr.Name)] = append(glue[fold(rr.Name)], addr)
	}

	var missing []wire.Name
	var v4, v6 []netip.AddrPort
	for _, host := range hosts {
		addrs := glue[fold(host)]
		if len(addrs) == 0 {
			missing = append(missing, host)
			continue
		}
		v4, v6 = split(addrs, s.r.port(), v4, v6)
	}

	// Only chase missing addresses when the referral left us with nothing at
	// all. Glue exists so that this does not have to happen, and spending the
	// budget on a second resolution while holding a working address is how a
	// resolver turns one query into many.
	if len(v4)+len(v6) == 0 {
		for _, host := range missing {
			// A nameserver inside the zone it serves cannot be looked up:
			// finding it would mean asking it. That is what glue is for, and
			// its absence means the delegation is broken, not that there is
			// something to chase.
			if host.Within(child) || s.resolving[fold(host)] {
				continue
			}
			s.resolving[fold(host)] = true
			addrs, err := s.addresses(ctx, host)
			delete(s.resolving, fold(host))
			if err != nil {
				if ctx.Err() != nil {
					return nil, "", err
				}
				continue
			}
			v4, v6 = split(addrs, s.r.port(), v4, v6)
		}
	}

	if len(v4)+len(v6) == 0 {
		return nil, "", fmt.Errorf("resolver: zone %q delegated to %d nameservers, none with a usable address: %w", child, len(hosts), ErrNoNameserver)
	}
	// IPv4 ahead of IPv6 for the same reason the root hints are ordered that
	// way: it is measurably faster from a typical host, and v6 is a fallback.
	return s.r.candidates(append(v4, v6...)), child, nil
}

// addresses resolves a nameserver's name, sharing the budget of the resolution
// that needs it.
func (s *session) addresses(ctx context.Context, host wire.Name) ([]netip.Addr, error) {
	rep, err := s.iterate(ctx, wire.Question{Name: host, Type: wire.TypeA, Class: wire.ClassIN})
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, rr := range rep.Msg.Answers {
		if a, ok := rr.Data.(wire.A); ok && rr.Name.Within(host) {
			out = append(out, a.Addr)
		}
	}
	return out, nil
}

// chase walks the answer section from name, following CNAMEs, and reports where
// the chain ended and whether a record of the wanted type was found there.
//
// Servers usually resolve the chain for us and return every link plus the final
// records in one answer, so this is what avoids re-querying for something
// already in hand.
func chase(msg *wire.Message, name wire.Name, typ wire.Type) (end wire.Name, chain []wire.RR, found bool) {
	cur := name
	// A malicious answer section can hold a cycle, so the number of records is
	// the natural bound: each step must consume a distinct CNAME.
	for range len(msg.Answers) + 1 {
		for _, rr := range msg.Answers {
			if rr.Type == typ && rr.Name.EqualFold(cur) {
				return cur, chain, true
			}
		}
		var next wire.Name
		for _, rr := range msg.Answers {
			if c, ok := rr.Data.(wire.CNAME); ok && rr.Name.EqualFold(cur) {
				chain = append(chain, rr)
				next = c.Target
				break
			}
		}
		if next == "" {
			return cur, chain, false
		}
		cur = next
	}
	return cur, chain, false
}

// split sorts addresses into the v4 and v6 buckets, on the resolver's port.
func split(addrs []netip.Addr, port uint16, v4, v6 []netip.AddrPort) ([]netip.AddrPort, []netip.AddrPort) {
	for _, a := range addrs {
		if !a.IsValid() {
			continue
		}
		if a.Is4() {
			v4 = append(v4, netip.AddrPortFrom(a, port))
		} else {
			v6 = append(v6, netip.AddrPortFrom(a, port))
		}
	}
	return v4, v6
}

// fold lowercases a name for use as a map key. Names match case-insensitively
// per RFC 4343, so keying on the wire spelling would file NS1.EXAMPLE.COM and
// ns1.example.com separately and lose the glue for one of them.
func fold(n wire.Name) wire.Name { return wire.Name(strings.ToLower(string(n))) }

func (s *session) trace(st Step) {
	if s.r.Trace != nil {
		s.r.Trace(st)
	}
}

// candidates copies the servers and shuffles the copy.
//
// Shuffling matters more than it looks: TIER1 measured k-root at 15 ms and
// a-root at 221 ms from this machine. Always starting at the head of a fixed
// list would pay the worst case on every cold resolution, and would also send
// every resolver that copied the same list to the same server.
func (r *Resolver) candidates(in []netip.AddrPort) []netip.AddrPort {
	out := make([]netip.AddrPort, len(in))
	copy(out, in)
	shuffle := r.Shuffle
	if shuffle == nil {
		shuffle = rand.Shuffle
	}
	shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

func (r *Resolver) port() uint16 {
	if r.Port > 0 {
		return r.Port
	}
	return 53
}

func (r *Resolver) maxDepth() int {
	if r.MaxDepth > 0 {
		return r.MaxDepth
	}
	return DefaultMaxDepth
}

func (r *Resolver) maxQueries() int {
	if r.MaxQueries > 0 {
		return r.MaxQueries
	}
	return DefaultMaxQueries
}

func (r *Resolver) maxCNAME() int {
	if r.MaxCNAME > 0 {
		return r.MaxCNAME
	}
	return DefaultMaxCNAME
}
