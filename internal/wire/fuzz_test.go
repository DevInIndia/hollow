package wire

import (
	"bytes"
	"errors"
	"net/netip"
	"os"
	"reflect"
	"testing"
)

// typedErrors is every failure Unpack is allowed to report. A decode that fails
// with anything else has taken a path nobody classified, which a caller cannot
// act on and a test cannot match with errors.Is.
var typedErrors = []error{
	ErrTruncated,
	ErrLabelType,
	ErrLabelTooLong,
	ErrNameTooLong,
	ErrNameSyntax,
	ErrBadPointer,
	ErrTooManyRecords,
	ErrRData,
}

// FuzzUnpack drives the decoder with arbitrary octets.
//
// Three properties hold for every input.
//
// Decoding never panics and never hangs. Fuzzing checks that for free and it is
// the property that matters most, because Unpack runs on octets that arrived
// from the network before anything has authenticated them.
//
// A failed decode reports one of the errors above.
//
// A successful decode survives a round trip: re-encoding succeeds, decoding the
// result reproduces the same message, and encoding that a second time produces
// the same octets. This is the property TestGoldenReencodeIsStable asserts on
// the two captures, generalised to whatever the fuzzer builds.
func FuzzUnpack(f *testing.F) {
	for _, seed := range seedCorpus(f) {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, msg []byte) {
		first, err := Unpack(msg)
		if err != nil {
			for _, want := range typedErrors {
				if errors.Is(err, want) {
					return
				}
			}
			t.Fatalf("Unpack() = %v, which is not one of the package's errors", err)
		}

		buf, err := first.Pack()
		if err != nil {
			t.Fatalf("Unpack accepted the message but Pack rejected it: %v", err)
		}
		second, err := Unpack(buf)
		if err != nil {
			t.Fatalf("re-encoded message no longer decodes: %v\n% x", err, buf)
		}
		if !reflect.DeepEqual(first, second) {
			t.Fatalf("round trip changed the message\n first %+v\nsecond %+v", first, second)
		}
		// The first encode may legitimately differ from the input, since the
		// encoder picks its own compression targets. The second may not differ
		// from the first: by then the input is our own output.
		again, err := second.Pack()
		if err != nil {
			t.Fatalf("re-Pack() = %v", err)
		}
		if !bytes.Equal(buf, again) {
			t.Fatalf("encoding is not a fixed point\n got % x\nwant % x", again, buf)
		}
	})
}

// seedCorpus is the starting point for mutation: the two real captures, one
// packed message per record type, and the malformed shapes from the section 8
// matrix. Seeding with structurally valid messages matters more than the count,
// because the mutation engine cannot discover a 12-octet header and a
// length-prefixed name layout on its own in any reasonable time.
func seedCorpus(f *testing.F) [][]byte {
	f.Helper()

	seeds := [][]byte{
		{},                        // case 19, empty message
		make([]byte, headerLen-1), // case 1, shorter than a header
		make([]byte, headerLen),   // a bare header, valid and useless
	}

	for _, name := range []string{"example-com-a.bin", "com-ns-referral.bin"} {
		b, err := os.ReadFile("testdata/" + name)
		if err != nil {
			f.Fatalf("reading fixture: %v", err)
		}
		seeds = append(seeds, b)
	}

	// One valid message per type, so every rdata parser is on the path from the
	// first execution rather than waiting for the mutator to guess a type code.
	for _, m := range validMessages() {
		buf, err := m.Pack()
		if err != nil {
			f.Fatalf("packing seed: %v", err)
		}
		seeds = append(seeds, buf)
	}

	return append(seeds, malformedMessages()...)
}

func validMessages() []*Message {
	answer := func(typ Type, data RData) *Message {
		return &Message{
			Header:    Header{ID: 0x4242, Response: true, RecursionDesired: true},
			Questions: []Question{{Name: "example.org.", Type: typ, Class: ClassIN}},
			Answers: []RR{{
				Name: "example.org.", Type: typ, Class: ClassIN, TTL: 3600, Data: data,
			}},
		}
	}

	query := &Message{
		Header:    Header{ID: 0x1a2b, RecursionDesired: true},
		Questions: []Question{{Name: "example.com.", Type: TypeA, Class: ClassIN}},
	}
	query.SetEDNS(EDNS{DO: true, Options: []Option{{Code: 10, Data: []byte{1, 2, 3, 4}}}})

	nodata := answer(TypeA, nil)
	nodata.Answers = nil
	nodata.Authority = []RR{{
		Name: "example.org.", Type: TypeSOA, Class: ClassIN, TTL: 300,
		Data: SOA{
			Primary: "ns1.example.org.", Mailbox: "hostmaster.example.org.",
			Serial: 2026082901, Refresh: 7200, Retry: 3600, Expire: 1209600, Minimum: 300,
		},
	}}

	// Two names that differ only in where their label boundaries fall. The
	// round-trip property caught the encoder collapsing these onto one key.
	labelBoundaries := answer(TypeA, A{Addr: netip.MustParseAddr("192.0.2.1")})
	labelBoundaries.Questions[0].Name = "a.b."
	labelBoundaries.Answers[0].Name = "a\\.b."

	return []*Message{
		query,
		nodata,
		labelBoundaries,
		answer(TypeA, A{Addr: netip.MustParseAddr("192.0.2.1")}),
		answer(TypeAAAA, AAAA{Addr: netip.MustParseAddr("2001:db8::1")}),
		answer(TypeNS, NS{Host: "ns1.example.net."}),
		answer(TypeCNAME, CNAME{Target: "canonical.example.net."}),
		answer(TypePTR, PTR{Target: "host.example.net."}),
		answer(TypeMX, MX{Preference: 10, Exchange: "mail.example.net."}),
		answer(TypeTXT, TXT{Strings: []string{"v=spf1 -all", "second"}}),
		answer(TypeSRV, SRV{Priority: 10, Weight: 60, Port: 5060, Target: "sip.example.net."}),
		answer(65280, Unknown{Kind: 65280, Data: []byte{1, 2, 3}}),
	}
}

// malformedMessages mirrors the reject tables in message_test.go, name_test.go
// and rdata_test.go. Those tables assert the class of failure; here the same
// shapes are only starting points, so they carry no expectation.
//
// The name cases are rebuilt with offsets relative to a real header, because a
// pointer that resolves is a far better seed than one rejected on its first
// octet.
func malformedMessages() [][]byte {
	// Header with the counts left to the caller and everything else valid.
	header := func(qd, an, ns, ar uint16) []byte {
		return []byte{
			0x12, 0x34, // ID
			0x81, 0x80, // QR RD RA
			byte(qd >> 8), byte(qd),
			byte(an >> 8), byte(an),
			byte(ns >> 8), byte(ns),
			byte(ar >> 8), byte(ar),
		}
	}
	// A message whose single question name is the given octets.
	question := func(name ...byte) []byte {
		return append(append(header(1, 0, 0, 0), name...), 0, 1, 0, 1)
	}

	return [][]byte{
		// Cases 2 and 3: counts that the octets present cannot support.
		append(header(3, 0, 0, 0), 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1),
		append(header(0, 0xFFFF, 0, 0), make([]byte, 28)...),

		// Cases 4 to 10, the name matrix, entered from the question section.
		question(64, 'a', 0),             // label length 64, a reserved type
		question(0x80, 0),                // reserved label type 0x80
		question(3, 'c', 'o', 'm'),       // no terminating zero
		question(9, 'c', 'o', 'm', 0),    // label runs past the end
		question(0xC0, 0x0C),             // pointer to itself
		question(0xC0, 0x20),             // pointer forward
		question(0xC0, 0x0E, 0xC0, 0x0C), // two pointers referencing each other
		// A pointer that targets an offset below its own position at every
		// step, yet loops: the labels at 14 walk forward to the pointer at 16,
		// which jumps back to 14. Rejected only by comparing each target
		// against the previous target rather than against the read position.
		question(1, 'a', 1, 'b', 0xC0, 0x0E),
		// A pointer into the middle of a label's payload, where 'o' is 111 and
		// so reads as a reserved label type.
		append(header(1, 0, 0, 0), 3, 'c', 'o', 'm', 0, 0xC0, 0x0D, 0, 1, 0, 1),

		// Cases 11 to 18, RDLENGTH disagreeing with the rdata it frames.
		answerMsg(TypeA, 0xFFFF, []byte{1, 2, 3, 4}),
		answerMsg(TypeA, 5, []byte{192, 0, 2, 1, 0}),
		answerMsg(TypeAAAA, 4, []byte{192, 0, 2, 1}),
		answerMsg(TypeCNAME, 4, []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0}),
		answerMsg(TypeNS, 9, []byte{2, 'n', 's', 0, 0, 0, 0, 0, 0}),
		answerMsg(TypeTXT, 3, []byte{5, 'a', 'b'}),
		answerMsg(TypeMX, 5, []byte{0, 10, 4, 'm', 'a'}),
		answerMsg(TypeSOA, 18, []byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4}),
		answerMsg(TypeSRV, 6, []byte{0, 10, 0, 60, 0x13, 0xc4}),
		answerMsg(TypeOPT, 6, []byte{0, 10, 0, 0xFF, 1, 2}),
	}
}
