package cli

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"

	"github.com/DevInIndia/hollow/internal/resolver"
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
			reply := rc.ServeDNS(context.Background(), tc.query)
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
	reply := rc.ServeDNS(context.Background(), query)
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
