package resolver

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/DevInIndia/hollow/internal/wire"
)

// A miniature internet on loopback.
//
// Each fake nameserver gets its own 127.0.0.x address, and all of them share
// one port. That shape is not incidental: glue records carry a bare address
// with no port, so a resolver reaching a delegated server has to supply one.
// Giving every server a distinct address on a common port is how the real
// thing works, and it is what makes the glue path testable at all without
// binding port 53.

type zoneFunc func(q wire.Question) *wire.Message

// startNet binds one UDP listener per address and serves each with its own
// handler, returning the port they all share.
func startNet(t *testing.T, zones map[netip.Addr]zoneFunc) uint16 {
	t.Helper()
	for attempt := 0; attempt < 20; attempt++ {
		port := freePort(t)
		conns := make(map[netip.Addr]net.PacketConn, len(zones))
		ok := true
		for addr := range zones {
			c, err := net.ListenPacket("udp", netip.AddrPortFrom(addr, port).String())
			if err != nil {
				ok = false
				break
			}
			conns[addr] = c
		}
		if !ok {
			for _, c := range conns {
				c.Close()
			}
			continue
		}
		for addr, c := range conns {
			t.Cleanup(func() { c.Close() })
			go serveZone(c, zones[addr])
		}
		return port
	}
	t.Fatal("could not bind every fake nameserver on one shared port")
	return 0
}

// freePort asks the kernel for a port and immediately gives it back. The window
// between here and the binds above is why startNet retries.
func freePort(t *testing.T) uint16 {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer c.Close()
	return uint16(c.LocalAddr().(*net.UDPAddr).Port)
}

func serveZone(conn net.PacketConn, h zoneFunc) {
	buf := make([]byte, 4096)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		query, err := wire.Unpack(buf[:n])
		if err != nil || len(query.Questions) != 1 {
			continue
		}
		reply := h(query.Questions[0])
		if reply == nil {
			continue // a server that hears the question and says nothing
		}
		reply.Header.ID = query.Header.ID
		reply.Header.Response = true
		if len(reply.Questions) == 0 {
			reply.Questions = query.Questions
		}
		out, err := reply.Pack()
		if err != nil {
			continue
		}
		conn.WriteTo(out, from)
	}
}

// Record constructors. Names are written with the trailing dot they carry on
// the wire, so the tests read the way a zone file does.

func nsRR(zone, host string) wire.RR {
	return wire.RR{Name: wire.Name(zone), Type: wire.TypeNS, Class: wire.ClassIN, TTL: 3600, Data: wire.NS{Host: wire.Name(host)}}
}

func aRR(name, ip string) wire.RR {
	return wire.RR{Name: wire.Name(name), Type: wire.TypeA, Class: wire.ClassIN, TTL: 3600, Data: wire.A{Addr: netip.MustParseAddr(ip)}}
}

func cnameRR(name, target string) wire.RR {
	return wire.RR{Name: wire.Name(name), Type: wire.TypeCNAME, Class: wire.ClassIN, TTL: 3600, Data: wire.CNAME{Target: wire.Name(target)}}
}

func soaRR(zone string) wire.RR {
	return wire.RR{Name: wire.Name(zone), Type: wire.TypeSOA, Class: wire.ClassIN, TTL: 3600, Data: wire.SOA{
		Primary: wire.Name("ns1." + zone), Mailbox: wire.Name("hostmaster." + zone), Serial: 1, Minimum: 300,
	}}
}

// referral is what a parent zone sends: NS records in authority, glue in
// additional, nothing in the answer section.
func referral(child, host, glue string) *wire.Message {
	m := &wire.Message{Authority: []wire.RR{nsRR(child, host)}}
	if glue != "" {
		m.Additional = []wire.RR{aRR(host, glue)}
	}
	return m
}

func answerMsg(rrs ...wire.RR) *wire.Message {
	return &wire.Message{Header: wire.Header{Authoritative: true}, Answers: rrs}
}

// testResolver wires a Resolver to the fake net: root hints point at 127.0.0.1,
// glue is reached on the shared port, and the server order is left alone so
// that assertions on which server was asked are stable.
func testResolver(t *testing.T, zones map[netip.Addr]zoneFunc) *Resolver {
	t.Helper()
	port := startNet(t, zones)
	return &Resolver{
		Transport: Transport{Timeout: 2 * time.Second},
		Hints:     []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)},
		Port:      port,
		Shuffle:   func(n int, swap func(i, j int)) {},
	}
}

func mustResolve(t *testing.T, r *Resolver, name string, typ wire.Type) *Result {
	t.Helper()
	res, err := r.Resolve(context.Background(), wire.Question{Name: wire.Name(name), Type: typ, Class: wire.ClassIN})
	if err != nil {
		t.Fatalf("Resolve(%s) error = %v", name, err)
	}
	return res
}

// The happy path: root delegates com, com delegates example.com, and
// example.com answers. Three servers, three queries, no recursion asked of
// anyone.
func threeZones() map[netip.Addr]zoneFunc {
	return map[netip.Addr]zoneFunc{
		netip.MustParseAddr("127.0.0.1"): func(q wire.Question) *wire.Message {
			return referral("com.", "a.gtld-servers.test.", "127.0.0.2")
		},
		netip.MustParseAddr("127.0.0.2"): func(q wire.Question) *wire.Message {
			return referral("example.com.", "ns1.example.com.", "127.0.0.3")
		},
		netip.MustParseAddr("127.0.0.3"): func(q wire.Question) *wire.Message {
			return answerMsg(aRR("example.com.", "93.184.216.34"))
		},
	}
}

func TestResolveWalksFromRoot(t *testing.T) {
	r := testResolver(t, threeZones())
	var steps []Step
	r.Trace = func(s Step) { steps = append(steps, s) }

	res := mustResolve(t, r, "example.com.", wire.TypeA)

	if len(res.Reply.Msg.Answers) != 1 {
		t.Fatalf("answers = %d, want 1", len(res.Reply.Msg.Answers))
	}
	if got := res.Reply.Msg.Answers[0].Data.(wire.A).Addr; got != netip.MustParseAddr("93.184.216.34") {
		t.Errorf("address = %v, want 93.184.216.34", got)
	}
	if res.Queries != 3 {
		t.Errorf("Queries = %d, want 3, one per zone", res.Queries)
	}
	if res.Reply.Server.Addr() != netip.MustParseAddr("127.0.0.3") {
		t.Errorf("answering server = %v, want the example.com server", res.Reply.Server)
	}

	// The trace is the delegation path, and it is the thing that shows the walk
	// actually happened rather than one server answering everything.
	want := []struct {
		zone wire.Name
		kind Kind
	}{
		{".", KindReferral},
		{"com.", KindReferral},
		{"example.com.", KindAnswer},
	}
	if len(steps) != len(want) {
		t.Fatalf("trace has %d steps, want %d", len(steps), len(want))
	}
	for i, w := range want {
		if steps[i].Zone != w.zone || steps[i].Kind != w.kind {
			t.Errorf("step %d = %q/%v, want %q/%v", i, steps[i].Zone, steps[i].Kind, w.zone, w.kind)
		}
	}
}

// RD must be clear on every query, even when the caller set it on the
// Transport. A resolver that sets it is asking someone else to do the work it
// claims to be doing, and would return an answer whose delegation path it never
// checked. This reads the flag off the wire rather than trusting the field.
func TestResolveNeverAsksForRecursion(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	rd := make(chan bool, 4)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			query, err := wire.Unpack(buf[:n])
			if err != nil || len(query.Questions) != 1 {
				continue
			}
			rd <- query.Header.RecursionDesired

			reply := answerMsg(aRR("example.com.", "93.184.216.34"))
			reply.Header.ID = query.Header.ID
			reply.Header.Response = true
			reply.Questions = query.Questions
			if out, err := reply.Pack(); err == nil {
				conn.WriteTo(out, from)
			}
		}
	}()

	port := uint16(conn.LocalAddr().(*net.UDPAddr).Port)
	r := &Resolver{
		// The caller asks for recursion. The resolver must override it.
		Transport: Transport{Timeout: 2 * time.Second, RecursionDesired: true},
		Hints:     []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)},
		Port:      port,
		Shuffle:   func(n int, swap func(i, j int)) {},
	}
	if _, err := r.Resolve(context.Background(), wire.Question{Name: "example.com.", Type: wire.TypeA, Class: wire.ClassIN}); err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}

	select {
	case got := <-rd:
		if got {
			t.Error("the query arrived with RD set, want it cleared for iterative resolution")
		}
	case <-time.After(time.Second):
		t.Fatal("no query reached the server")
	}

	// Clearing RD must not reach back into the caller's Resolver, which the
	// server shares across goroutines.
	if !r.Transport.RecursionDesired {
		t.Error("Resolve mutated the caller's Transport")
	}
}

func TestResolveNXDomain(t *testing.T) {
	zones := threeZones()
	zones[netip.MustParseAddr("127.0.0.3")] = func(q wire.Question) *wire.Message {
		return &wire.Message{
			Header:    wire.Header{Authoritative: true, Rcode: wire.RcodeNXDomain},
			Authority: []wire.RR{soaRR("example.com.")},
		}
	}
	res := mustResolve(t, testResolver(t, zones), "nope.example.com.", wire.TypeA)
	if res.Reply.Msg.Header.Rcode != wire.RcodeNXDomain {
		t.Errorf("rcode = %d, want NXDOMAIN", res.Reply.Msg.Header.Rcode)
	}
}

// NODATA is not NXDOMAIN: the name exists and this type does not. RCODE 0 with
// an empty answer and an SOA in authority is the only thing that says so.
func TestResolveNoData(t *testing.T) {
	zones := threeZones()
	zones[netip.MustParseAddr("127.0.0.3")] = func(q wire.Question) *wire.Message {
		return &wire.Message{
			Header:    wire.Header{Authoritative: true},
			Authority: []wire.RR{soaRR("example.com.")},
		}
	}
	res := mustResolve(t, testResolver(t, zones), "example.com.", wire.TypeMX)
	if res.Reply.Msg.Header.Rcode != wire.RcodeSuccess || len(res.Reply.Msg.Answers) != 0 {
		t.Fatalf("want RCODE 0 with no answers, got rcode %d with %d", res.Reply.Msg.Header.Rcode, len(res.Reply.Msg.Answers))
	}
	if got := classify(res.Reply.Msg, wire.Question{Name: "example.com.", Type: wire.TypeMX}); got != KindNoData {
		t.Errorf("classify() = %v, want %v", got, KindNoData)
	}
}

// An SOA beside NS records in the authority section is a zone speaking for
// itself, not a delegation. Reading it as a referral would send the walk back
// down into a zone that just said there is nothing here.
func TestClassifyPrefersSOAOverNS(t *testing.T) {
	m := &wire.Message{Authority: []wire.RR{
		nsRR("example.com.", "ns1.example.com."),
		soaRR("example.com."),
	}}
	if got := classify(m, wire.Question{Name: "example.com.", Type: wire.TypeMX}); got != KindNoData {
		t.Errorf("classify() = %v, want %v", got, KindNoData)
	}
}

func TestClassifyRcodes(t *testing.T) {
	q := wire.Question{Name: "example.com.", Type: wire.TypeA}
	for _, tc := range []struct {
		rcode uint8
		want  Kind
	}{
		{wire.RcodeNXDomain, KindNXDomain},
		{wire.RcodeServFail, KindFailure},
		{wire.RcodeRefused, KindFailure},
		{wire.RcodeFormErr, KindFailure},
		{wire.RcodeNotImp, KindFailure},
	} {
		m := &wire.Message{Header: wire.Header{Rcode: tc.rcode}}
		if got := classify(m, q); got != tc.want {
			t.Errorf("rcode %d classified %v, want %v", tc.rcode, got, tc.want)
		}
	}
}

// A CNAME that leaves the zone has to be chased from the root again, because
// the server holding the target is somewhere else entirely.
func TestResolveFollowsCNAMEAcrossZones(t *testing.T) {
	zones := map[netip.Addr]zoneFunc{
		netip.MustParseAddr("127.0.0.1"): func(q wire.Question) *wire.Message {
			if q.Name.Within("net.") {
				return referral("net.", "a.gtld-servers.test.", "127.0.0.4")
			}
			return referral("com.", "a.gtld-servers.test.", "127.0.0.2")
		},
		netip.MustParseAddr("127.0.0.2"): func(q wire.Question) *wire.Message {
			return referral("example.com.", "ns1.example.com.", "127.0.0.3")
		},
		netip.MustParseAddr("127.0.0.3"): func(q wire.Question) *wire.Message {
			return answerMsg(cnameRR("www.example.com.", "target.example.net."))
		},
		netip.MustParseAddr("127.0.0.4"): func(q wire.Question) *wire.Message {
			return answerMsg(aRR("target.example.net.", "203.0.113.7"))
		},
	}
	res := mustResolve(t, testResolver(t, zones), "www.example.com.", wire.TypeA)

	if len(res.CNAMEs) != 1 {
		t.Fatalf("CNAMEs = %d, want the one link that was followed", len(res.CNAMEs))
	}
	if got := res.CNAMEs[0].Data.(wire.CNAME).Target; got != "target.example.net." {
		t.Errorf("CNAME target = %q, want target.example.net.", got)
	}
	if len(res.Reply.Msg.Answers) != 1 || res.Reply.Msg.Answers[0].Data.(wire.A).Addr != netip.MustParseAddr("203.0.113.7") {
		t.Fatalf("final answer = %+v, want the A record from the net zone", res.Reply.Msg.Answers)
	}
}

// When the server resolves the chain itself and returns every link plus the
// final record, there is nothing left to chase and no second walk to pay for.
func TestResolveUsesCNAMEChainAlreadyInTheAnswer(t *testing.T) {
	zones := threeZones()
	zones[netip.MustParseAddr("127.0.0.3")] = func(q wire.Question) *wire.Message {
		return answerMsg(
			cnameRR("www.example.com.", "cdn.example.com."),
			aRR("cdn.example.com.", "198.51.100.9"),
		)
	}
	res := mustResolve(t, testResolver(t, zones), "www.example.com.", wire.TypeA)
	if res.Queries != 3 {
		t.Errorf("Queries = %d, want 3: the chain was already in hand", res.Queries)
	}
	// The link is in the final message's own answer section, so reporting it
	// in CNAMEs as well would show the reader the same record twice.
	if len(res.CNAMEs) != 0 {
		t.Errorf("CNAMEs = %d, want 0: the link is already in Reply.Msg.Answers", len(res.CNAMEs))
	}
	if len(res.Reply.Msg.Answers) != 2 {
		t.Errorf("answers = %d, want the CNAME and the A record", len(res.Reply.Msg.Answers))
	}
}

// Asking for the CNAME itself must return it rather than following it.
func TestResolveDoesNotChaseWhenCNAMEIsTheQuestion(t *testing.T) {
	zones := threeZones()
	zones[netip.MustParseAddr("127.0.0.3")] = func(q wire.Question) *wire.Message {
		return answerMsg(cnameRR("www.example.com.", "elsewhere.example.org."))
	}
	res := mustResolve(t, testResolver(t, zones), "www.example.com.", wire.TypeCNAME)
	if res.Queries != 3 {
		t.Errorf("Queries = %d, want the walk to stop at the CNAME", res.Queries)
	}
}

func TestResolveDetectsCNAMELoop(t *testing.T) {
	zones := threeZones()
	zones[netip.MustParseAddr("127.0.0.3")] = func(q wire.Question) *wire.Message {
		// a points at b, b points back at a, and neither is ever an address.
		switch q.Name {
		case "a.example.com.":
			return answerMsg(cnameRR("a.example.com.", "b.example.com."))
		default:
			return answerMsg(cnameRR("b.example.com.", "a.example.com."))
		}
	}
	r := testResolver(t, zones)
	_, err := r.Resolve(context.Background(), wire.Question{Name: "a.example.com.", Type: wire.TypeA, Class: wire.ClassIN})
	if !errors.Is(err, ErrCNAMELoop) {
		t.Fatalf("Resolve() error = %v, want %v", err, ErrCNAMELoop)
	}
}

// Glue outside the zone being delegated is the classic cache-poisoning shape: a
// com server answering with an address for a name it has no authority over.
// It must be dropped, which here leaves the delegation with no usable address.
func TestDelegationDropsOutOfBailiwickGlue(t *testing.T) {
	zones := threeZones()
	zones[netip.MustParseAddr("127.0.0.2")] = func(q wire.Question) *wire.Message {
		m := referral("example.com.", "ns1.example.com.", "")
		// The com server hands back an address for a name in another zone.
		m.Additional = []wire.RR{aRR("bank.example.org.", "127.0.0.3")}
		return m
	}
	r := testResolver(t, zones)
	_, err := r.Resolve(context.Background(), wire.Question{Name: "example.com.", Type: wire.TypeA, Class: wire.ClassIN})
	if !errors.Is(err, ErrNoNameserver) {
		t.Fatalf("Resolve() error = %v, want the poisoned glue ignored and %v", err, ErrNoNameserver)
	}
}

// The escaped-dot case, at the level that matters. "ns1.evil\.com" is a name in
// the zone "evil\.com", which is a sibling of com, not a child of it. Glue for
// it in a com referral is out of bailiwick even though the bytes end in "com.".
func TestDelegationBailiwickIsLabelWise(t *testing.T) {
	zones := threeZones()
	zones[netip.MustParseAddr("127.0.0.2")] = func(q wire.Question) *wire.Message {
		m := referral("example.com.", "ns1.example.com.", "")
		m.Additional = []wire.RR{aRR(`ns1.evil\.com.`, "127.0.0.3")}
		return m
	}
	r := testResolver(t, zones)
	_, err := r.Resolve(context.Background(), wire.Question{Name: "example.com.", Type: wire.TypeA, Class: wire.ClassIN})
	if !errors.Is(err, ErrNoNameserver) {
		t.Fatalf("Resolve() error = %v, want %v", err, ErrNoNameserver)
	}
}

// A referral must descend. Pointing sideways or back upward would otherwise
// spin the walk until the depth limit caught it, which anyone could trigger.
func TestDelegationRejectsReferralsThatDoNotDescend(t *testing.T) {
	for _, tc := range []struct {
		name  string
		child string
		query string
	}{
		{"sideways", "org.", "example.com."},
		{"back to the same zone", ".", "example.com."},
		{"does not contain the name", "other.com.", "example.com."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			zones := map[netip.Addr]zoneFunc{
				netip.MustParseAddr("127.0.0.1"): func(q wire.Question) *wire.Message {
					return referral(tc.child, "ns1."+tc.child, "127.0.0.2")
				},
				netip.MustParseAddr("127.0.0.2"): func(q wire.Question) *wire.Message {
					return answerMsg(aRR(tc.query, "93.184.216.34"))
				},
			}
			r := testResolver(t, zones)
			_, err := r.Resolve(context.Background(), wire.Question{Name: wire.Name(tc.query), Type: wire.TypeA, Class: wire.ClassIN})
			if !errors.Is(err, ErrBadReferral) {
				t.Fatalf("Resolve() error = %v, want %v", err, ErrBadReferral)
			}
		})
	}
}

// A referral whose nameserver lives outside the delegated zone comes with no
// glue, and the address has to be resolved separately, out of the same budget.
func TestDelegationResolvesMissingGlue(t *testing.T) {
	zones := map[netip.Addr]zoneFunc{
		netip.MustParseAddr("127.0.0.1"): func(q wire.Question) *wire.Message {
			if q.Name.Within("net.") {
				return referral("net.", "b.gtld-servers.test.", "127.0.0.4")
			}
			return referral("com.", "a.gtld-servers.test.", "127.0.0.2")
		},
		netip.MustParseAddr("127.0.0.2"): func(q wire.Question) *wire.Message {
			// example.com is served by a name in another zone, so no glue.
			return referral("example.com.", "ns.hoster.net.", "")
		},
		netip.MustParseAddr("127.0.0.4"): func(q wire.Question) *wire.Message {
			return answerMsg(aRR("ns.hoster.net.", "127.0.0.3"))
		},
		netip.MustParseAddr("127.0.0.3"): func(q wire.Question) *wire.Message {
			return answerMsg(aRR("example.com.", "93.184.216.34"))
		},
	}
	res := mustResolve(t, testResolver(t, zones), "example.com.", wire.TypeA)
	if len(res.Reply.Msg.Answers) != 1 {
		t.Fatalf("answers = %d, want 1", len(res.Reply.Msg.Answers))
	}
	// Two for the main walk, two for the nested one, one for the final answer.
	if res.Queries != 5 {
		t.Errorf("Queries = %d, want 5 including the nested lookup", res.Queries)
	}
}

// A nameserver inside the zone it serves, with no glue, is a broken delegation:
// finding its address would mean asking it. There is nothing to chase, and the
// resolver must say so rather than recursing until the budget runs out.
func TestDelegationDoesNotChaseInBailiwickNameserver(t *testing.T) {
	zones := threeZones()
	zones[netip.MustParseAddr("127.0.0.2")] = func(q wire.Question) *wire.Message {
		return referral("example.com.", "ns1.example.com.", "")
	}
	r := testResolver(t, zones)
	_, err := r.Resolve(context.Background(), wire.Question{Name: "example.com.", Type: wire.TypeA, Class: wire.ClassIN})
	if !errors.Is(err, ErrNoNameserver) {
		t.Fatalf("Resolve() error = %v, want %v", err, ErrNoNameserver)
	}
}

// A server that fails is skipped for the next one in the list rather than
// ending the resolution.
func TestAskFallsThroughToTheNextServer(t *testing.T) {
	zones := map[netip.Addr]zoneFunc{
		netip.MustParseAddr("127.0.0.1"): func(q wire.Question) *wire.Message {
			return referral("com.", "a.gtld-servers.test.", "127.0.0.2")
		},
		// The first com server SERVFAILs, the second answers. The referral
		// below lists both, in that order.
		netip.MustParseAddr("127.0.0.2"): func(q wire.Question) *wire.Message {
			m := &wire.Message{Authority: []wire.RR{
				nsRR("example.com.", "ns1.example.com."),
				nsRR("example.com.", "ns2.example.com."),
			}, Additional: []wire.RR{
				aRR("ns1.example.com.", "127.0.0.5"),
				aRR("ns2.example.com.", "127.0.0.3"),
			}}
			return m
		},
		netip.MustParseAddr("127.0.0.5"): func(q wire.Question) *wire.Message {
			return &wire.Message{Header: wire.Header{Rcode: wire.RcodeServFail}}
		},
		netip.MustParseAddr("127.0.0.3"): func(q wire.Question) *wire.Message {
			return answerMsg(aRR("example.com.", "93.184.216.34"))
		},
	}
	res := mustResolve(t, testResolver(t, zones), "example.com.", wire.TypeA)
	if res.Reply.Server.Addr() != netip.MustParseAddr("127.0.0.3") {
		t.Errorf("answered by %v, want the second nameserver", res.Reply.Server)
	}
	if res.Queries != 4 {
		t.Errorf("Queries = %d, want 4 including the SERVFAIL", res.Queries)
	}
}

// A server that hears the question and says nothing must cost the timeout once
// and then be abandoned, not retried.
func TestAskGivesUpOnASilentServer(t *testing.T) {
	zones := map[netip.Addr]zoneFunc{
		netip.MustParseAddr("127.0.0.1"): func(q wire.Question) *wire.Message { return nil },
	}
	port := startNet(t, zones)
	r := &Resolver{
		Transport: Transport{Timeout: 150 * time.Millisecond},
		Hints:     []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)},
		Port:      port,
		Shuffle:   func(n int, swap func(i, j int)) {},
	}
	_, err := r.Resolve(context.Background(), wire.Question{Name: "example.com.", Type: wire.TypeA, Class: wire.ClassIN})
	if !errors.Is(err, ErrNoNameserver) {
		t.Fatalf("Resolve() error = %v, want %v", err, ErrNoNameserver)
	}
}

// An endless chain of referrals is stopped by the depth limit rather than by
// running forever. Each referral descends properly, so nothing else catches it.
func TestResolveStopsAtTheDepthLimit(t *testing.T) {
	var depth int
	zones := map[netip.Addr]zoneFunc{
		netip.MustParseAddr("127.0.0.1"): func(q wire.Question) *wire.Message {
			depth++
			// Hand back a zone one label deeper every time, always still
			// containing the name being asked for.
			child := q.Name
			for i := 0; i < depth; i++ {
				if k := indexDot(string(child)); k >= 0 && k+1 < len(child) {
					child = child[k+1:]
				}
			}
			return referral(string(child), "ns."+string(child), "127.0.0.1")
		},
	}
	r := testResolver(t, zones)
	r.MaxDepth = 4
	_, err := r.Resolve(context.Background(), wire.Question{
		Name: "a.b.c.d.e.f.g.example.com.", Type: wire.TypeA, Class: wire.ClassIN,
	})
	if !errors.Is(err, ErrResolutionLimit) && !errors.Is(err, ErrBadReferral) {
		t.Fatalf("Resolve() error = %v, want a limit to stop the walk", err)
	}
}

func indexDot(s string) int {
	for i := range len(s) {
		if s[i] == '.' {
			return i
		}
	}
	return -1
}

// The query budget bounds total work even when each individual step looks
// reasonable, which is what a deep chain of one-server zones produces.
func TestResolveStopsAtTheQueryBudget(t *testing.T) {
	zones := map[netip.Addr]zoneFunc{
		netip.MustParseAddr("127.0.0.1"): func(q wire.Question) *wire.Message {
			return &wire.Message{Header: wire.Header{Rcode: wire.RcodeServFail}}
		},
	}
	port := startNet(t, zones)
	hints := make([]netip.AddrPort, 20)
	for i := range hints {
		hints[i] = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)
	}
	r := &Resolver{
		Transport:  Transport{Timeout: time.Second},
		Hints:      hints,
		Port:       port,
		MaxQueries: 5,
		Shuffle:    func(n int, swap func(i, j int)) {},
	}
	_, err := r.Resolve(context.Background(), wire.Question{Name: "example.com.", Type: wire.TypeA, Class: wire.ClassIN})
	if !errors.Is(err, ErrResolutionLimit) {
		t.Fatalf("Resolve() error = %v, want %v", err, ErrResolutionLimit)
	}
}

func TestResolveWithoutHints(t *testing.T) {
	var r Resolver
	if _, err := r.Resolve(context.Background(), wire.Question{Name: "example.com.", Type: wire.TypeA}); !errors.Is(err, ErrNoHints) {
		t.Fatalf("Resolve() error = %v, want %v", err, ErrNoHints)
	}
}

func TestResolveHonoursCancellation(t *testing.T) {
	zones := map[netip.Addr]zoneFunc{
		netip.MustParseAddr("127.0.0.1"): func(q wire.Question) *wire.Message { return nil },
	}
	port := startNet(t, zones)
	r := &Resolver{
		Transport: Transport{Timeout: 10 * time.Second},
		Hints:     []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)},
		Port:      port,
		Shuffle:   func(n int, swap func(i, j int)) {},
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	_, err := r.Resolve(ctx, wire.Question{Name: "example.com.", Type: wire.TypeA, Class: wire.ClassIN})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Resolve() error = %v, want it to surface the cancellation", err)
	}
	// A cancelled context must end the whole resolution, not just one exchange.
	// Moving to the next server would have taken the full ten seconds.
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("Resolve() took %v after a 50ms cancel, want it to stop promptly", elapsed)
	}
}

func TestChaseStopsOnACycleInOneAnswer(t *testing.T) {
	// A single answer section that loops. chase must terminate on its own,
	// because the caller's hop counter never sees these.
	msg := &wire.Message{Answers: []wire.RR{
		cnameRR("a.example.com.", "b.example.com."),
		cnameRR("b.example.com.", "a.example.com."),
	}}
	_, _, found := chase(msg, "a.example.com.", wire.TypeA)
	if found {
		t.Error("chase() found an A record in a section that holds only CNAMEs")
	}
}

func TestKindString(t *testing.T) {
	for k, want := range map[Kind]string{
		KindAnswer: "answer", KindReferral: "referral", KindNXDomain: "nxdomain",
		KindNoData: "nodata", KindFailure: "failure", Kind(99): "failure",
	} {
		if got := k.String(); got != want {
			t.Errorf("Kind(%d).String() = %q, want %q", int(k), got, want)
		}
	}
}

func TestCandidatesCopiesAndShuffles(t *testing.T) {
	in := []netip.AddrPort{
		netip.MustParseAddrPort("127.0.0.1:53"),
		netip.MustParseAddrPort("127.0.0.2:53"),
	}
	r := &Resolver{Shuffle: func(n int, swap func(i, j int)) { swap(0, 1) }}
	out := r.candidates(in)
	if in[0] != netip.MustParseAddrPort("127.0.0.1:53") {
		t.Error("candidates() shuffled the caller's slice in place")
	}
	if out[0] != in[1] || out[1] != in[0] {
		t.Errorf("candidates() = %v, want the swap applied to the copy", out)
	}
}

func TestResolverDefaults(t *testing.T) {
	var r Resolver
	if r.maxDepth() != DefaultMaxDepth || r.maxQueries() != DefaultMaxQueries || r.maxCNAME() != DefaultMaxCNAME {
		t.Error("zero-valued limits did not fall back to the defaults")
	}
	if r.port() != 53 {
		t.Errorf("port() = %d, want 53", r.port())
	}
	set := Resolver{MaxDepth: 1, MaxQueries: 2, MaxCNAME: 3, Port: 5353}
	if set.maxDepth() != 1 || set.maxQueries() != 2 || set.maxCNAME() != 3 || set.port() != 5353 {
		t.Error("explicit limits were overridden by the defaults")
	}
}
