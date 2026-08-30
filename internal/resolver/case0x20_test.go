package resolver

import (
	"context"
	"math"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/DevInIndia/hollow/internal/wire"
)

// caseServer answers on loopback and reports the question of every query it
// received. echo decides what case the reply echoes back, which is how a
// non-conforming server is simulated.
type caseServer struct {
	addr      netip.AddrPort
	questions chan wire.Name
}

func startCaseServer(t *testing.T, echo func(wire.Name) wire.Name) *caseServer {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	s := &caseServer{
		addr:      netip.MustParseAddrPort(conn.LocalAddr().String()),
		questions: make(chan wire.Name, 8),
	}
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
			asked := query.Questions[0].Name
			select {
			case s.questions <- asked:
			default:
			}

			reply := answerMsg(aRR(string(asked), "93.184.216.34"))
			reply.Header.ID = query.Header.ID
			reply.Header.Response = true
			reply.Questions = []wire.Question{{
				Name:  echo(asked),
				Type:  query.Questions[0].Type,
				Class: query.Questions[0].Class,
			}}
			if out, err := reply.Pack(); err == nil {
				conn.WriteTo(out, from)
			}
		}
	}()
	return s
}

func (s *caseServer) asked(t *testing.T) wire.Name {
	t.Helper()
	select {
	case n := <-s.questions:
		return n
	case <-time.After(2 * time.Second):
		t.Fatal("no query reached the server")
		return ""
	}
}

func verbatim(n wire.Name) wire.Name { return n }
func lowered(n wire.Name) wire.Name  { return n.Fold() }

// The defence, working: the name goes out with its case scrambled, the server
// echoes it, and the answer is accepted.
func TestQueriesGoOutWithRandomisedCase(t *testing.T) {
	s := startCaseServer(t, verbatim)
	tr := Transport{Timeout: 2 * time.Second, Case: NewCasing()}

	q := wire.Question{Name: "www.example.com.", Type: wire.TypeA, Class: wire.ClassIN}
	rep, err := tr.Exchange(context.Background(), s.addr, q)
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}

	sent := s.asked(t)
	if sent == q.Name {
		t.Errorf("the query went out as %q, unchanged", sent)
	}
	if !sent.EqualFold(q.Name) {
		t.Fatalf("the query went out as %q, which is not %q with the case changed", sent, q.Name)
	}
	if rep.Sent != sent {
		t.Errorf("Reply.Sent = %q, want the name that was actually sent, %q", rep.Sent, sent)
	}
}

// Only letters move. A digit, a hyphen or a dot that changed would make the
// question section fail to match on the way back, and the server that echoed it
// faithfully would be blamed for it.
func TestRandomCaseTouchesOnlyLetters(t *testing.T) {
	const name = wire.Name("www.example-1.co.uk.")
	for range 200 {
		got := randomCase(name)
		if len(got) != len(name) {
			t.Fatalf("randomCase(%q) = %q, a different length", name, got)
		}
		for i := range len(name) {
			switch {
			case isASCIILetter(name[i]):
				if got[i]|0x20 != name[i]|0x20 {
					t.Fatalf("octet %d changed from %q to %q, which is not a case flip", i, name[i], got[i])
				}
			case got[i] != name[i]:
				t.Fatalf("octet %d is %q, not the %q it was, and it is not a letter", i, got[i], name[i])
			}
		}
	}
}

// The distribution is asserted against the birthday bound rather than the
// number of draws. A ten-letter name has 1024 possible patterns, so 2000 draws
// yield about 879 distinct ones, and a test that demanded 2000 would fail
// against a perfectly correct crypto/rand.
func TestRandomCaseIsSpreadAcrossThePatterns(t *testing.T) {
	const (
		name    = wire.Name("example.com.") // ten letters
		letters = 10
		draws   = 2000
	)
	seen := make(map[wire.Name]bool, draws)
	for range draws {
		seen[randomCase(name)] = true
	}

	space := math.Pow(2, letters)
	expect := space * (1 - math.Pow(1-1/space, draws))
	if float64(len(seen)) < 0.9*expect {
		t.Errorf("distinct patterns = %d, want at least 90%% of the %.0f the birthday bound predicts",
			len(seen), expect)
	}
}

// A name with no letters carries no nonce. Randomising it is a no-op, and the
// reply must not be refused for echoing what it was sent.
func TestANameWithNoLettersIsUnchangedAndStillAccepted(t *testing.T) {
	const name = wire.Name("1.0.0.127.")
	if got := randomCase(name); got != name {
		t.Errorf("randomCase(%q) = %q, want it unchanged", name, got)
	}

	s := startCaseServer(t, lowered)
	tr := Transport{Timeout: 2 * time.Second, Case: NewCasing()}
	if _, err := tr.Exchange(context.Background(), s.addr, wire.Question{Name: name, Type: wire.TypeA, Class: wire.ClassIN}); err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
}

// TCP is not open to an off-path forgery, so the case is not randomised there.
// Doing it anyway would cost nothing and prove nothing, and it would read as if
// the mechanism had not been understood.
func TestTCPQueriesAreNotRandomised(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	asked := make(chan wire.Name, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var prefix [2]byte
		if _, err := conn.Read(prefix[:]); err != nil {
			return
		}
		body := make([]byte, int(prefix[0])<<8|int(prefix[1]))
		if _, err := conn.Read(body); err != nil {
			return
		}
		query, err := wire.Unpack(body)
		if err != nil || len(query.Questions) != 1 {
			return
		}
		asked <- query.Questions[0].Name

		reply := answerMsg(aRR(string(query.Questions[0].Name), "93.184.216.34"))
		reply.Header.ID = query.Header.ID
		reply.Header.Response = true
		reply.Questions = query.Questions
		out, err := reply.Pack()
		if err != nil {
			return
		}
		conn.Write(append([]byte{byte(len(out) >> 8), byte(len(out))}, out...))
	}()

	tr := Transport{Timeout: 2 * time.Second, ForceTCP: true, Case: NewCasing()}
	q := wire.Question{Name: "www.example.com.", Type: wire.TypeA, Class: wire.ClassIN}
	if _, err := tr.Exchange(context.Background(), netip.MustParseAddrPort(ln.Addr().String()), q); err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}

	select {
	case got := <-asked:
		if got != q.Name {
			t.Errorf("the TCP query went out as %q, want %q unchanged", got, q.Name)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no query reached the server")
	}
}

// Real servers exist that lowercase the question. One is asked again without
// the randomisation, recorded, and asked plainly from then on. A resolver that
// refused outright would look broken against real infrastructure.
func TestANonConformingServerIsRetriedOnceAndThenSkipped(t *testing.T) {
	s := startCaseServer(t, lowered)
	casing := NewCasing()
	// A short timeout, because the retry deliberately waits out the deadline
	// first rather than treating one wrong-case datagram as permission to stop
	// randomising.
	tr := Transport{Timeout: 300 * time.Millisecond, Case: casing}

	q := wire.Question{Name: "www.example.com.", Type: wire.TypeA, Class: wire.ClassIN}
	rep, err := tr.Exchange(context.Background(), s.addr, q)
	if err != nil {
		t.Fatalf("Exchange() error = %v, want the plain retry to succeed", err)
	}
	if rep.Sent != q.Name {
		t.Errorf("the retry went out as %q, want the plain name %q", rep.Sent, q.Name)
	}
	if casing.Nonconforming() != 1 {
		t.Errorf("non-conforming servers = %d, want 1", casing.Nonconforming())
	}

	// The first query was randomised, the retry was not.
	first, second := s.asked(t), s.asked(t)
	if first == q.Name {
		t.Errorf("the first query went out unrandomised as %q", first)
	}
	if second != q.Name {
		t.Errorf("the retry went out as %q, want %q", second, q.Name)
	}

	// And from here on it is asked plainly with no second timeout to pay.
	start := time.Now()
	if _, err := tr.Exchange(context.Background(), s.addr, q); err != nil {
		t.Fatalf("second Exchange() error = %v", err)
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Errorf("the second exchange took %v, so the server was randomised again", elapsed)
	}
	if got := s.asked(t); got != q.Name {
		t.Errorf("the next query went out as %q, want %q", got, q.Name)
	}
}

// The randomisation must not leak past the resolver. A client that asked about
// example.com gets records owned by example.com, whatever case went out on the
// wire, or the answer is confusing and the cache holds a mangled name.
func TestTheCaseThatWentOutDoesNotReachTheAnswer(t *testing.T) {
	s := startCaseServer(t, verbatim)
	tr := Transport{Timeout: 2 * time.Second, Case: NewCasing()}

	q := wire.Question{Name: "www.example.com.", Type: wire.TypeA, Class: wire.ClassIN}
	rep, err := tr.Exchange(context.Background(), s.addr, q)
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if got := rep.Msg.Questions[0].Name; got != q.Name {
		t.Errorf("the reply's question is %q, want %q", got, q.Name)
	}
	for _, rr := range rep.Msg.Answers {
		if rr.Name != q.Name {
			t.Errorf("an answer is owned by %q, want %q", rr.Name, q.Name)
		}
	}
}

// The nonce comes back in more than the question. A referral is owned by the
// zone as it was spelled on the way out, and glue for a nameserver inside that
// zone inherits the same case through a compression pointer. All of it has to
// be put back, or the case leaks into the cache and into what a client is shown.
func TestTheCaseIsRestoredInEveryNameThatEchoedIt(t *testing.T) {
	m := &wire.Message{
		Questions: []wire.Question{{Name: "wWw.BbC.co.UK.", Type: wire.TypeA, Class: wire.ClassIN}},
		Authority: []wire.RR{
			nsRR("BbC.co.UK.", "dns1.BbC.co.UK."),
			soaRR("co.UK."),
		},
		Additional: []wire.RR{
			aRR("dns1.BbC.co.UK.", "127.0.0.1"),
			// A name that merely ends in the same letters without a label
			// boundary is not a suffix of anything and must be left alone.
			aRR("notbbc.co.UK.", "127.0.0.2"),
		},
		Answers: []wire.RR{cnameRR("wWw.BbC.co.UK.", "edge.BbC.co.UK.")},
	}
	restoreCase(m, "wWw.BbC.co.UK.", "www.bbc.co.uk.")

	want := map[string]string{
		"question":   "www.bbc.co.uk.",
		"ns owner":   "bbc.co.uk.",
		"ns host":    "dns1.bbc.co.uk.",
		"soa owner":  "co.uk.",
		"glue owner": "dns1.bbc.co.uk.",
		"unrelated":  "notbbc.co.uk.",
		"cname":      "edge.bbc.co.uk.",
	}
	got := map[string]string{
		"question":   string(m.Questions[0].Name),
		"ns owner":   string(m.Authority[0].Name),
		"ns host":    string(m.Authority[0].Data.(wire.NS).Host),
		"soa owner":  string(m.Authority[1].Name),
		"glue owner": string(m.Additional[0].Name),
		"unrelated":  string(m.Additional[1].Name),
		"cname":      string(m.Answers[0].Data.(wire.CNAME).Target),
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s = %q, want %q", k, got[k], w)
		}
	}
}

// A reply carrying the wrong transaction id is refused whatever its case, and
// the case check does not get to run before the id check.
func TestATransactionIDMismatchIsRefusedBeforeTheCaseIsLookedAt(t *testing.T) {
	q := wire.Question{Name: "eXaMple.CoM.", Type: wire.TypeA, Class: wire.ClassIN}
	m := &wire.Message{
		Header:    wire.Header{ID: 0x1234, Response: true},
		Questions: []wire.Question{q},
	}
	raw, err := m.Pack()
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}
	_, err = accept(raw, 0x4321, q)
	if err == nil {
		t.Fatal("accept() took a reply with the wrong transaction id")
	}
	if !strings.Contains(err.Error(), "transaction id") {
		t.Errorf("error = %v, want it to name the transaction id", err)
	}
}

// Two queries in a row leave from different source ports. The kernel picks
// them, because the socket is dialled rather than bound, and that is 15 or so
// bits an off-path attacker has to guess alongside the transaction id.
func TestConsecutiveQueriesLeaveFromDifferentPorts(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	ports := make(chan int, 4)
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
			ports <- from.(*net.UDPAddr).Port

			reply := answerMsg(aRR(string(query.Questions[0].Name), "93.184.216.34"))
			reply.Header.ID = query.Header.ID
			reply.Header.Response = true
			reply.Questions = query.Questions
			if out, err := reply.Pack(); err == nil {
				conn.WriteTo(out, from)
			}
		}
	}()

	tr := Transport{Timeout: 2 * time.Second}
	server := netip.MustParseAddrPort(conn.LocalAddr().String())
	q := wire.Question{Name: "example.com.", Type: wire.TypeA, Class: wire.ClassIN}
	for range 2 {
		if _, err := tr.Exchange(context.Background(), server, q); err != nil {
			t.Fatalf("Exchange() error = %v", err)
		}
	}

	first, second := <-ports, <-ports
	if first == second {
		t.Errorf("both queries left from port %d, so the source port is not randomised", first)
	}
}
