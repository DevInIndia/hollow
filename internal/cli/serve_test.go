package cli

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/DevInIndia/hollow/internal/blocklist"
	"github.com/DevInIndia/hollow/internal/resolver"
	"github.com/DevInIndia/hollow/internal/stats"
	"github.com/DevInIndia/hollow/internal/wire"
)

func TestServeRejectsBadArguments(t *testing.T) {
	tests := map[string][]string{
		"unrecognised flag": {"--nope"},
		"a positional":      {"127.0.0.1:15353"},
		"no workers":        {"--workers", "0"},
		"negative workers":  {"--workers", "-1"},

		// A hints file that does not exist must stop the server before it binds,
		// rather than falling back to the compiled-in roots and serving from a
		// root the operator did not choose.
		"missing hints file": {"--hints", "/nonexistent/named.root"},

		// An address that cannot be bound is reported rather than retried
		// somewhere else.
		"unbindable address": {"--addr", "203.0.113.1:15353"},

		"negative cache size": {"--cache-size", "-1"},

		// Two flags that contradict each other. Honouring one and dropping the
		// other silently would leave the operator believing they had asked for
		// something they did not get.
		"stale without a cache": {"--cache-size", "0", "--serve-stale", "1h"},

		// A block mode nobody implements, and a list file that is not there.
		// Both stop the server before it binds, for the same reason the hints
		// file does: a resolver that is running but not filtering looks exactly
		// like one that is.
		"an unknown block mode": {"--block-mode", "refuse"},

		// A forwarder has to be an address. Resolving the name of the server
		// that resolves names needs a resolver, and the one in this process is
		// the one being configured.
		"a forwarder given as a name":  {"--forward", "dns.example.com"},
		"a forwarder that is nonsense": {"--forward", "1.1.1.1:99999"},

		// --hints names the roots to start a walk from, and forwarding does not
		// walk.
		"hints with forwarding": {"--forward", "1.1.1.1", "--hints", "/nonexistent/named.root"},
		"a missing block file":  {"--block", "/nonexistent/hosts"},

		// An allowlist with no blocklist to override does nothing at all.
		"allow with nothing to allow past": {"--allow", "/nonexistent/allow"},

		// Rate limiting takes a rate and a slip that mean something, and
		// exempting a network from a limiter that is switched off is another
		// pair of flags that contradict each other.
		"a negative rate":                         {"--rrl", "-1"},
		"a negative slip":                         {"--rrl-slip", "-2"},
		"a trusted network that is not a network": {"--rrl-trusted", "the office"},
		"trusted networks with no limiter":        {"--rrl", "0", "--rrl-trusted", "10.0.0.0/8"},

		// A control socket that cannot bind stops the server, rather than
		// leaving it running and reporting success while the operator waits for
		// a dashboard that will never attach.
		"an unbindable control address":     {"--control", "203.0.113.1:15354"},
		"a control address that is not one": {"--control", "not an address"},
	}

	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr strings.Builder
			if got := Serve(args, &stdout, &stderr); got != ExitFailure {
				t.Errorf("Serve() = %d, want %d", got, ExitFailure)
			}
			if stderr.Len() == 0 {
				t.Error("a failed serve explained nothing on stderr")
			}
		})
	}
}

// The queries a resolver should answer with an rcode rather than by resolving.
// Each is a shape that is either meaningless to a resolver or that no two
// implementations agree on.
func TestRecursorRefusesWhatItCannotAnswer(t *testing.T) {
	name, err := wire.ParseName("example.com.")
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	inQuestion := wire.Question{Name: name, Type: wire.TypeA, Class: wire.ClassIN}

	tests := map[string]struct {
		query *wire.Message
		want  uint8
	}{
		"an update opcode": {
			query: &wire.Message{
				Header:    wire.Header{ID: 1, Opcode: 5},
				Questions: []wire.Question{inQuestion},
			},
			want: wire.RcodeNotImp,
		},
		"no question at all": {
			query: &wire.Message{Header: wire.Header{ID: 2}},
			want:  wire.RcodeFormErr,
		},
		"two questions": {
			query: &wire.Message{
				Header:    wire.Header{ID: 3},
				Questions: []wire.Question{inQuestion, inQuestion},
			},
			want: wire.RcodeFormErr,
		},
		"a class we do not serve": {
			query: &wire.Message{
				Header:    wire.Header{ID: 4},
				Questions: []wire.Question{{Name: name, Type: wire.TypeA, Class: 3}}, // CHAOS
			},
			want: wire.RcodeRefused,
		},
	}

	rc := &recursor{resolver: &resolver.Resolver{}, log: discard()}
	for label, tc := range tests {
		t.Run(label, func(t *testing.T) {
			reply := rc.ServeDNS(context.Background(), tc.query, testClient)
			if reply == nil {
				t.Fatal("ServeDNS() = nil, want a reply carrying an rcode")
			}
			if reply.Header.Rcode != tc.want {
				t.Errorf("rcode %d, want %d", reply.Header.Rcode, tc.want)
			}
			if reply.Header.ID != tc.query.Header.ID {
				t.Errorf("reply id %d, want %d echoed back", reply.Header.ID, tc.query.Header.ID)
			}
			if !reply.Header.Response {
				t.Error("reply has the response bit clear")
			}
			// Even a refusal has to be encodable, or the server answers a bad
			// query with silence and the client waits out its own timeout.
			if _, err := reply.Pack(); err != nil {
				t.Errorf("the refusal does not encode: %v", err)
			}
		})
	}
}

// A resolution that fails is SERVFAIL, not silence. The zero Resolver has no
// root hints, so this reaches the failure path without touching the network.
func TestRecursorReportsAFailedResolutionAsServFail(t *testing.T) {
	name, err := wire.ParseName("example.com.")
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	query := &wire.Message{
		Header:    wire.Header{ID: 7, RecursionDesired: true},
		Questions: []wire.Question{{Name: name, Type: wire.TypeA, Class: wire.ClassIN}},
	}

	rc := &recursor{resolver: &resolver.Resolver{}, log: discard()}
	reply := rc.ServeDNS(context.Background(), query, testClient)
	if reply == nil {
		t.Fatal("ServeDNS() = nil, want SERVFAIL")
	}
	if reply.Header.Rcode != wire.RcodeServFail {
		t.Errorf("rcode %d, want SERVFAIL (%d)", reply.Header.Rcode, wire.RcodeServFail)
	}
	if !reply.Header.RecursionAvailable {
		t.Error("RA is clear, so a client would take us for a stub")
	}
}

// The chain has to come back in the order it was walked, with the links
// collected across earlier exchanges ahead of the final answer. A client asking
// a recursive server expects the whole chain, since it cannot walk it itself.
func TestRecursorReturnsTheWholeCNAMEChain(t *testing.T) {
	from, err := wire.ParseName("www.example.com.")
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	to, err := wire.ParseName("example.com.")
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}

	link := wire.RR{
		Name: from, Type: wire.TypeCNAME, Class: wire.ClassIN, TTL: 300,
		Data: wire.CNAME{Target: to},
	}
	final := wire.RR{
		Name: to, Type: wire.TypeA, Class: wire.ClassIN, TTL: 300,
		Data: wire.A{Addr: netip.MustParseAddr("192.0.2.1")},
	}

	query := &wire.Message{
		Header:    wire.Header{ID: 9, RecursionDesired: true},
		Questions: []wire.Question{{Name: from, Type: wire.TypeA, Class: wire.ClassIN}},
	}
	res := &resolver.Result{
		// CNAMEs holds only what the final message does not, which is what the
		// resolver guarantees, so the two are concatenated rather than merged.
		CNAMEs: []wire.RR{link},
		Reply: &resolver.Reply{
			Msg: &wire.Message{
				Header:  wire.Header{Rcode: wire.RcodeSuccess},
				Answers: []wire.RR{final},

				// Glue the upstream happened to attach. It was never
				// bailiwick-checked, so it must not reach the client.
				Additional: []wire.RR{{
					Name: to, Type: wire.TypeA, Class: wire.ClassIN, TTL: 300,
					Data: wire.A{Addr: netip.MustParseAddr("198.51.100.9")},
				}},
			},
		},
	}

	rc := &recursor{resolver: &resolver.Resolver{}, log: discard()}
	reply := rc.reply(query, res)

	if len(reply.Answers) != 2 {
		t.Fatalf("reply carries %d answers, want the link and the address", len(reply.Answers))
	}
	if reply.Answers[0].Type != wire.TypeCNAME {
		t.Errorf("first answer is %s, want the CNAME link first", reply.Answers[0].Type)
	}
	if reply.Answers[1].Type != wire.TypeA {
		t.Errorf("second answer is %s, want the address last", reply.Answers[1].Type)
	}
	if reply.Header.Authoritative {
		t.Error("AA is set on records this server is only repeating")
	}

	// The additional section holds our own OPT and nothing else: the upstream
	// record must not have been passed through.
	for _, rr := range reply.Additional {
		if rr.Type != wire.TypeOPT {
			t.Errorf("upstream additional record %s %s reached the client", rr.Name, rr.Type)
		}
	}
	if _, ok, err := reply.EDNS(); err != nil || !ok {
		t.Errorf("reply carries no OPT record: ok=%v err=%v", ok, err)
	}
}

func discard() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// testClient is the address the handler tests present as the asker. Any valid
// address will do; what matters is that it is not the zero Addr, since that is
// the value the server uses to mean it could not tell.
var testClient = netip.MustParseAddr("192.0.2.10")

// The recursor has to account for every path out of ServeDNS, including the
// ones that refuse without resolving. A total that counts only the successes
// sits quietly below the number of packets the server answered, and an operator
// reading it has no way to tell.
func TestRecursorRecordsEveryOutcome(t *testing.T) {
	name, err := wire.ParseName("example.com.")
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	inQuestion := wire.Question{Name: name, Type: wire.TypeA, Class: wire.ClassIN}

	col := stats.New()
	rc := &recursor{resolver: &resolver.Resolver{}, log: discard(), stats: col}

	// One of each: a bad opcode, a bad question count, a refused class, and a
	// resolution that fails because the zero Resolver has no root hints.
	rc.ServeDNS(context.Background(), &wire.Message{
		Header:    wire.Header{ID: 1, Opcode: 5},
		Questions: []wire.Question{inQuestion},
	}, testClient)
	rc.ServeDNS(context.Background(), &wire.Message{Header: wire.Header{ID: 2}}, testClient)
	rc.ServeDNS(context.Background(), &wire.Message{
		Header:    wire.Header{ID: 3},
		Questions: []wire.Question{{Name: name, Type: wire.TypeA, Class: 3}},
	}, testClient)
	rc.ServeDNS(context.Background(), &wire.Message{
		Header:    wire.Header{ID: 4, RecursionDesired: true},
		Questions: []wire.Question{inQuestion},
	}, testClient)

	s := col.Snapshot()
	if s.QueriesTotal != 4 {
		t.Errorf("QueriesTotal = %d, want all 4 outcomes counted", s.QueriesTotal)
	}
	if s.UpstreamErrors != 1 {
		t.Errorf("UpstreamErrors = %d, want 1", s.UpstreamErrors)
	}
	if len(s.TopClients) != 1 || s.TopClients[0].Name != testClient.String() {
		t.Errorf("TopClients = %+v, want the one client that asked", s.TopClients)
	}

	// Two of the four are attributable to a name: the refused class and the
	// failed resolution. The other two are counted as queries and left out of
	// the name list, because neither has a name to attribute.
	//
	// The bad-opcode message does carry a question section, and it is
	// deliberately not read. In an UPDATE that section is the zone section and
	// means something else, so treating it as a queried name would put a name
	// nobody looked up into the statistics.
	var named uint64
	for _, item := range s.TopDomains {
		named += item.Count
	}
	if named != 2 {
		t.Errorf("the name lists account for %d queries, want 2", named)
	}
}

// A nil collector is the handler tests' configuration and must stay inert.
func TestRecursorWithNoCollectorDoesNotPanic(t *testing.T) {
	rc := &recursor{resolver: &resolver.Resolver{}, log: discard()}
	reply := rc.ServeDNS(context.Background(), &wire.Message{Header: wire.Header{ID: 1}}, testClient)
	if reply == nil {
		t.Fatal("ServeDNS() = nil")
	}
}

// The shutdown report is the only way these numbers are visible before the
// control socket exists, so it has to say something when nothing happened
// rather than printing an empty section.
func TestReportOnAnIdleServer(t *testing.T) {
	var out strings.Builder
	report(&out, stats.New().Snapshot())
	if got := out.String(); !strings.Contains(got, "none") {
		t.Errorf("report on an idle server printed %q", got)
	}
}

func TestReportNamesWhatItCounted(t *testing.T) {
	col := stats.New()
	col.Record(stats.Event{
		At: time.Now(), Client: testClient,
		Name: "example.com.", Type: 1, Duration: 5 * time.Millisecond,
	})
	var out strings.Builder
	report(&out, col.Snapshot())

	got := out.String()
	for _, want := range []string{"queries: 1", "latency:", "example.com."} {
		if !strings.Contains(got, want) {
			t.Errorf("report is missing %q:\n%s", want, got)
		}
	}
	// The two drop lines are noise when there is nothing to report, and a line
	// that always reads zero is one an operator learns to skip.
	if strings.Contains(got, "dropped") {
		t.Errorf("report mentions drops when there were none:\n%s", got)
	}
}

// blocking builds a recursor that will refuse the given names. Its resolver has
// no root hints, so anything reaching resolution fails, which is exactly what
// makes it visible whether the blocklist answered before the walk started.
func blocking(t *testing.T, mode blocklist.Mode, list string) (*recursor, *stats.Collector) {
	t.Helper()
	l, err := blocklist.Parse([]io.Reader{strings.NewReader(list)}, nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	col := stats.New()
	return &recursor{
		resolver: &resolver.Resolver{}, log: discard(), stats: col,
		blocks: l, blockMode: mode,
	}, col
}

func ask(t *testing.T, rc *recursor, n string, typ wire.Type) *wire.Message {
	t.Helper()
	name, err := wire.ParseName(n)
	if err != nil {
		t.Fatalf("ParseName(%q): %v", n, err)
	}
	return rc.ServeDNS(context.Background(), &wire.Message{
		Header:    wire.Header{ID: 9, RecursionDesired: true},
		Questions: []wire.Question{{Name: name, Type: typ, Class: wire.ClassIN}},
	}, testClient)
}

func TestABlockedNameIsAnsweredWithoutResolving(t *testing.T) {
	rc, col := blocking(t, blocklist.ModeNXDomain, "0.0.0.0 ads.example.com\n")

	reply := ask(t, rc, "ads.example.com.", wire.TypeA)
	if reply.Header.Rcode != wire.RcodeNXDomain {
		t.Errorf("rcode = %d, want NXDOMAIN", reply.Header.Rcode)
	}

	s := col.Snapshot()
	if s.QueriesBlocked != 1 {
		t.Errorf("QueriesBlocked = %d, want 1", s.QueriesBlocked)
	}
	if s.UpstreamErrors != 0 {
		// The resolver has no hints, so any attempt to resolve would fail and
		// be counted. Zero here is the proof that the block answered first.
		t.Errorf("UpstreamErrors = %d, want 0; the query reached the resolver", s.UpstreamErrors)
	}
	if len(s.TopBlocked) != 1 || s.TopBlocked[0].Name != "ads.example.com." {
		t.Errorf("TopBlocked = %+v, want ads.example.com.", s.TopBlocked)
	}
}

func TestAnUnblockedNameIsNotCountedAsBlocked(t *testing.T) {
	// The counter has to distinguish a blocked NXDOMAIN from a real one, which
	// is why it is passed in rather than read off the rcode.
	rc, col := blocking(t, blocklist.ModeNXDomain, "0.0.0.0 ads.example.com\n")

	reply := ask(t, rc, "www.example.com.", wire.TypeA)
	if reply.Header.Rcode != wire.RcodeServFail {
		t.Errorf("rcode = %d, want SERVFAIL from the hint-less resolver", reply.Header.Rcode)
	}
	if s := col.Snapshot(); s.QueriesBlocked != 0 {
		t.Errorf("QueriesBlocked = %d, want 0", s.QueriesBlocked)
	}
}

func TestTheBlockModeReachesTheClient(t *testing.T) {
	rc, _ := blocking(t, blocklist.ModeNull, "||example.com^\n")

	reply := ask(t, rc, "ads.example.com.", wire.TypeA)
	if reply.Header.Rcode != wire.RcodeSuccess || len(reply.Answers) != 1 {
		t.Fatalf("rcode %d with %d answers, want 0 and 1", reply.Header.Rcode, len(reply.Answers))
	}
	if a, ok := reply.Answers[0].Data.(wire.A); !ok || a.Addr.String() != "0.0.0.0" {
		t.Errorf("answer = %v, want 0.0.0.0", reply.Answers[0].Data)
	}
}

func TestReportBlocklistSaysWhatLoadedAndWhatDidNot(t *testing.T) {
	l, err := blocklist.Parse([]io.Reader{strings.NewReader("a.example\n||b.example^\nnonsense line one\n")}, nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	var out strings.Builder
	reportBlocklist(&out, l, blocklist.ModeNoData)

	got := out.String()
	for _, want := range []string{"1 names", "1 domains", "nodata", "1 lines skipped"} {
		if !strings.Contains(got, want) {
			t.Errorf("startup line is missing %q:\n%s", want, got)
		}
	}

	// Nothing loaded and nothing to say.
	out.Reset()
	reportBlocklist(&out, nil, blocklist.ModeNXDomain)
	if out.Len() != 0 {
		t.Errorf("reportBlocklist with no list printed %q", out.String())
	}
}

func TestSkippedLinesAreSilentWhenThereAreNone(t *testing.T) {
	l, err := blocklist.Parse([]io.Reader{strings.NewReader("a.example\n")}, nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	var out strings.Builder
	reportBlocklist(&out, l, blocklist.ModeNXDomain)
	if strings.Contains(out.String(), "skipped") {
		t.Errorf("a clean list reported skipped lines:\n%s", out.String())
	}
}

func TestStringListCollectsRepeatedFlags(t *testing.T) {
	var s stringList
	if err := s.Set("one"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := s.Set("two"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := s.Set(""); err == nil {
		t.Error("Set accepted an empty path")
	}
	if got := s.String(); got != "one,two" {
		t.Errorf("String() = %q, want \"one,two\"", got)
	}
}

func TestParseServersTakesAddressesWithOrWithoutAPort(t *testing.T) {
	got, err := parseServers([]string{"1.1.1.1", "127.0.0.1:5353", "2606:4700:4700::1111", "[::1]:5300"})
	if err != nil {
		t.Fatalf("parseServers: %v", err)
	}
	want := []string{"1.1.1.1:53", "127.0.0.1:5353", "[2606:4700:4700::1111]:53", "[::1]:5300"}
	if len(got) != len(want) {
		t.Fatalf("parseServers returned %d servers, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Errorf("server %d = %s, want %s", i, got[i], want[i])
		}
	}

	// A bare IPv6 address must not be read as a host and a port, which is what
	// makes the order of the two parse attempts matter.
	if _, err := parseServers([]string{"dns.google"}); err == nil {
		t.Error("parseServers accepted a name")
	}
}

func TestReportModeSaysWhereAnswersComeFrom(t *testing.T) {
	var out strings.Builder
	reportMode(&out, nil, false)
	if !strings.Contains(out.String(), "from the root") {
		t.Errorf("iterative mode printed %q", out.String())
	}

	out.Reset()
	servers, err := parseServers([]string{"1.1.1.1", "8.8.8.8"})
	if err != nil {
		t.Fatalf("parseServers: %v", err)
	}
	reportMode(&out, servers, true)
	got := out.String()
	for _, want := range []string{"1.1.1.1:53", "8.8.8.8:53", "in order", "not walked", "randomised case"} {
		if !strings.Contains(got, want) {
			t.Errorf("forwarding mode line is missing %q:\n%s", want, got)
		}
	}
}

// The handler is indifferent to which resolver it holds, which is the whole
// reason answerer is an interface. A Forwarder with no servers fails every
// query, and the handler turns that into SERVFAIL exactly as it does for a
// failed walk.
func TestTheHandlerAcceptsAForwarder(t *testing.T) {
	col := stats.New()
	rc := &recursor{resolver: &resolver.Forwarder{}, log: discard(), stats: col}

	reply := ask(t, rc, "example.com.", wire.TypeA)
	if reply.Header.Rcode != wire.RcodeServFail {
		t.Errorf("rcode = %d, want SERVFAIL", reply.Header.Rcode)
	}
	if s := col.Snapshot(); s.UpstreamErrors != 1 {
		t.Errorf("UpstreamErrors = %d, want 1", s.UpstreamErrors)
	}
}

func TestParsePrefixesTakesNetworksAndBareAddresses(t *testing.T) {
	// No flag at all means the loopback default, which is what keeps a limiter
	// that is on by default from limiting the operator's own testing.
	got, err := parsePrefixes(nil)
	if err != nil {
		t.Fatalf("parsePrefixes(nil) error = %v", err)
	}
	if len(got) != 2 || !got[0].Contains(netip.MustParseAddr("127.0.0.1")) {
		t.Errorf("the default exemption is %v, want loopback", got)
	}

	got, err = parsePrefixes([]string{"10.0.0.0/8", "192.0.2.7", "2001:db8::/32"})
	if err != nil {
		t.Fatalf("parsePrefixes() error = %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("prefixes = %d, want 3", len(got))
	}
	// A bare address is exempt as itself rather than as some guessed network.
	if got[1].Bits() != 32 || !got[1].Contains(netip.MustParseAddr("192.0.2.7")) {
		t.Errorf("a bare address became %v, want 192.0.2.7/32", got[1])
	}
	if got[1].Contains(netip.MustParseAddr("192.0.2.8")) {
		t.Error("a bare address exempted its neighbour too")
	}
}

func TestReportLimiterSaysWhatIsLimitedAndWhatIsNot(t *testing.T) {
	var out strings.Builder
	reportLimiter(&out, 20, 2, loopback)
	for _, want := range []string{"20 a second", "second one answered truncated", "127.0.0.0/8", "::1/128"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the limiter line is missing %q:\n%s", want, out.String())
		}
	}

	out.Reset()
	reportLimiter(&out, 0, 2, nil)
	if !strings.Contains(out.String(), "off") {
		t.Errorf("a disabled limiter printed %q", out.String())
	}

	// Slip off is worth saying plainly, because it is the setting that turns
	// the limiter into an outage for a real client behind a busy network.
	out.Reset()
	reportLimiter(&out, 20, 0, loopback)
	if !strings.Contains(out.String(), "0 dropped") {
		t.Errorf("slip off printed %q", out.String())
	}
}
